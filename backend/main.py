"""FastAPI application.

Wires the routers, the middleware, and the startup/shutdown lifecycle. Three
things in the lifespan are worth reading:

1. **`assert_human_merge_required`** runs before anything is served. If
   `SENTINEL_ALLOW_AUTO_MERGE` is set, startup raises. There is no code path
   that would honour the flag, so failing loudly is the only honest response
   to someone setting it.

2. **The scanner backend is built once** and stored on `app.state`. Which
   implementation that is depends on `SENTINEL_SCANNER_TRANSPORT`; under
   Docker Compose it is a real `GrpcScannerClient` sharing one channel, because
   building a channel per request would pay a TCP handshake each time and
   exhaust gRPC's connection pool. It is closed on shutdown.

3. **Engines and the background loop are disposed on shutdown.** Without this,
   a script or a test that created an engine leaves an unclosed pool and emits
   `Task was destroyed but it is pending` on exit.

The API is the human-facing surface. The MCP server (`backend/mcp_server/`) is
the agent-facing one. Both sit on the same services, so neither is a special
case and neither can drift from the other's behaviour.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from backend.api.middleware.correlation import (
    AccessLogMiddleware,
    CorrelationIdMiddleware,
    correlation_id_from,
)
from backend.api.routes import audit, findings, health, remediations, scans, sla, tickets
from backend.auth.jwt import assert_secret_is_not_default
from backend.auth.router import router as auth_router
from backend.config.settings import get_settings
from backend.core.asyncio_utils import shutdown_background_loop
from backend.core.logging import configure_logging, get_logger
from backend.database.session import dispose_engines
from backend.policy.rules import MergePolicyViolation, assert_human_merge_required
from backend.telemetry import get_telemetry_client

logger = get_logger(__name__)

API_DESCRIPTION = """
Security-triage API for Ironclad Cyber Defense.

SentinelMCP scans a codebase, persists findings, tracks them against
severity-based SLAs, and drafts human-approved remediation pull requests using
an AutoGen developer/reviewer loop.

**This API can propose and review code. It cannot merge it.** Every remediation
pull request is opened as a draft with `auto_merge_blocked=true`, and a person
with the APPROVER or ADMIN role must authorize it before it becomes mergeable.
A human then performs the merge in the git host.
"""

TAGS_METADATA: list[dict[str, Any]] = [
    {"name": "health", "description": "Liveness, readiness, and the runtime policy check."},
    {"name": "scans", "description": "Trigger scans and read scan history."},
    {"name": "findings", "description": "The triage backlog: read findings, change their status."},
    {
        "name": "remediation",
        "description": "Run the agent loop, review drafts, and the human approval gate.",
    },
    {"name": "sla", "description": "Severity-based SLA dashboard."},
    {"name": "tickets", "description": "Tracked remediation work items."},
    {"name": "cve", "description": "Advisory lookup over the local CVE feed."},
    {"name": "audit", "description": "Read-only. Every finding and every agent decision."},
    {"name": "auth", "description": "Token issuing and identity."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown.

    Startup order matters: the safety rails are verified *before* anything is
    served, so a misconfigured deployment never accepts a request it should
    refuse.
    """
    settings = get_settings()
    configure_logging(settings.log_level)

    # 1. Safety rails first. A process that cannot honour them should not be
    #    reachable at all.
    assert_human_merge_required(
        actor="application startup", allow_auto_merge=settings.allow_auto_merge
    )
    assert_secret_is_not_default()

    # 2. One scanner backend for the process lifetime.
    from backend.mcp_server.server import build_scanner_backend

    app.state.scanner_backend = await build_scanner_backend(settings)
    app.state.telemetry = get_telemetry_client()
    logger.info(
        "startup complete service=%s env=%s auth_enabled=%s telemetry_sink=%s",
        settings.app_name,
        settings.app_env,
        settings.auth_enabled,
        settings.telemetry_sink,
    )

    try:
        yield
    finally:
        logger.info("shutdown: disposing engines and stopping background loop")
        # A gRPC backend owns a channel; closing it releases the socket rather
        # than leaving the process to be killed with the connection still open.
        backend = getattr(app.state, "scanner_backend", None)
        if backend is not None and hasattr(backend, "close"):
            await backend.close()
        await dispose_engines()
        shutdown_background_loop()
        logger.info("shutdown complete")


def create_app() -> FastAPI:
    """Build the application. Called once by `main.py` and by the tests."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description=API_DESCRIPTION,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Middleware order: correlation id outermost so it wraps everything,
    # including the access log's own log line and any 404 from the router.
    app.add_middleware(AccessLogMiddleware)
    app.add_middleware(CorrelationIdMiddleware)

    app.include_router(health.router)
    app.include_router(auth_router)
    app.include_router(scans.router)
    app.include_router(findings.router)
    app.include_router(remediations.router)
    app.include_router(sla.router)
    app.include_router(tickets.router)
    app.include_router(audit.router)

    _register_error_handlers(app)
    _register_root(app)
    return app


def _register_error_handlers(app: FastAPI) -> None:
    """Structured error responses that always carry the correlation id.

    A 500 that does not tell the caller which request failed is unactionable
    in a system where one request touches four tables and a telemetry stream.
    """

    @app.exception_handler(MergePolicyViolation)
    async def _merge_policy_violation(request: Request, exc: MergePolicyViolation) -> JSONResponse:
        # 500, not 400. Reaching this means the process is running in a state
        # that should have been impossible -- a bug or a tampered setting, not a
        # client mistake -- so it must page someone rather than look like a
        # validation error the caller can fix.
        logger.critical("merge policy violated: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "merge_policy_violation",
                "detail": str(exc),
                "correlation_id": correlation_id_from(request),
            },
        )

    @app.exception_handler(ValueError)
    async def _unhandled_value_error(request: Request, exc: ValueError) -> JSONResponse:
        # A `ValueError` reaching the boundary is a bug in our own validation
        # ordering, not user input -- FastAPI's Pydantic layer catches user
        # input first. Surfaced as a 400 with a generic message: the specific
        # reason is logged, because these messages tend to carry internal
        # detail.
        logger.warning("ValueError escaped to the boundary: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "error": "bad_request",
                "detail": "the request could not be processed",
                "correlation_id": correlation_id_from(request),
            },
        )


def _register_root(app: FastAPI) -> None:
    """A root route that points a first-time visitor at the useful endpoints."""

    @app.get("/", include_in_schema=False)
    async def root() -> dict[str, Any]:
        return {
            "service": get_settings().app_name,
            "version": "0.1.0",
            "description": "Security triage with human-approved agent remediation.",
            "endpoints": {
                "docs": "/docs",
                "openapi": "/openapi.json",
                "health": "/health",
                "readiness": "/health/ready",
                "policy_check": "/health/policy",
                "run_a_scan": "POST /scans",
                "triage_queue": "GET /findings",
                "sla_dashboard": "GET /sla/dashboard",
                "approval_queue": "GET /pull-requests/awaiting-approval",
                "audit": "GET /audit",
            },
            "guarantee": (
                "This system proposes and reviews remediation pull requests. "
                "It cannot merge them: every pull request is created with "
                "auto_merge_blocked=true, and merging is a human action in the git host."
            ),
        }


app = create_app()
