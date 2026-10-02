"""Health and readiness.

`GET /health` is a *liveness* probe: is this process alive and able to answer?
It must not depend on Postgres or the scanner service, because a database
outage should not cause an orchestrator to kill an otherwise healthy process
and turn a degradation into an outage.

`GET /health/ready` is the *readiness* probe: should this instance receive
traffic? That one does check its dependencies, and returns 503 when they are
down. Splitting them is the difference between a database blip and a
restart storm.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from backend.api.dependencies import AppSettings, ScannerBackendDep
from backend.auth.jwt import DEV_DEFAULT_SECRET
from backend.config.settings import get_settings
from backend.policy.rules import MAX_REMEDIATION_ATTEMPTS, assert_human_merge_required
from backend.schemas.contracts import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(
    response: Response,
    settings: AppSettings,
    scanner_backend: ScannerBackendDep,
) -> HealthResponse:
    """Liveness. Never fails on a dependency outage.

    Reports dependency state for observability but always returns 200 as long
    as the process can serve HTTP. A container that restarts because Postgres
    blinked has turned a degraded service into a down one.
    """
    scanning = await scanner_backend.health()

    # Best-effort: a failing database must not turn a liveness probe into a
    # 500. The value is informational and the readiness probe is the one that
    # gates traffic.
    database_ok, database_detail = await _check_database()

    policy = {
        "auto_merge_blocked": True,
        "human_merge_required": True,
        "max_remediation_attempts": MAX_REMEDIATION_ATTEMPTS,
        "note": "This system can propose and review; it cannot merge.",
    }
    if settings.app_env.lower() == "production" and settings.jwt_secret == DEV_DEFAULT_SECRET:
        # Worth surfacing on a health endpoint: a security tool running with a
        # publicly-known signing key is exactly the kind of finding this
        # product exists to catch, and it would be poor form to ship one.
        policy["warning"] = "jwt secret is the development default"

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        version="0.1.0",
        database="reachable" if database_ok else f"unreachable ({database_detail})",
        scanning_service=scanning,
        policy=policy,
    )


@router.get("/health/ready")
async def ready(
    response: Response,
    settings: AppSettings,
    scanner_backend: ScannerBackendDep,
) -> dict[str, Any]:
    """Readiness. Returns 503 when a dependency the service needs is down."""
    database_ok, database_detail = await _check_database()
    scanning = await scanner_backend.health()
    scanning_ok = bool(scanning.get("healthy"))

    ready_state = database_ok and scanning_ok
    if not ready_state:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "ready": ready_state,
        "checks": {
            "database": {"ok": database_ok, "detail": database_detail},
            "scanning_service": {"ok": scanning_ok, "detail": scanning},
        },
    }


@router.get("/health/policy")
async def policy_check(settings: AppSettings) -> dict[str, Any]:
    """Verify the non-negotiable safety rails still hold, at runtime.

    Calls the same function startup does, so "is auto-merge still blocked?" is
    a question this process can answer on demand rather than a claim in a
    README. Raises `MergePolicyViolation` (surfaced as a 500) if someone has set
    `SENTINEL_ALLOW_AUTO_MERGE=true`, which is the loudest possible signal that
    a deployment is misconfigured.
    """
    from backend.mcp_server.server import mcp_sdk_major_version

    assert_human_merge_required(
        actor="GET /health/policy", allow_auto_merge=get_settings().allow_auto_merge
    )
    return {
        "auto_merge": "blocked",
        "human_approval_required": True,
        "max_remediation_attempts": MAX_REMEDIATION_ATTEMPTS,
        "mcp_sdk_major_version": mcp_sdk_major_version(),
        "verified": True,
    }


async def _check_database() -> tuple[bool, str]:
    """One `SELECT 1` against the shared engine.

    Uses the loop-scoped engine from `backend.database.session` rather than
    building one here. A health check is the most frequently called endpoint in
    the service, and constructing a fresh engine (and its connection pool) per
    call would be the fastest way to exhaust the database's connection limit
    from a single process.
    """

    from backend.database.session import get_session_factory

    try:
        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
        return True, "reachable"
    except Exception as exc:  # noqa: BLE001 - any failure means "not ready"
        return False, type(exc).__name__
