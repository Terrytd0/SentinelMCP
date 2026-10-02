"""Scan routes.

`POST /scans` is the operator-triggered entry point into the pipeline. It goes
over real gRPC to the scanning service, so triggering a scan from the API
exercises exactly the boundary a deployment would.

Error mapping is the interesting part. A scan that failed and a scan that found
nothing look identical to a careless client, so they get different status
codes:

    200  the scan ran; `new_findings: 0` is a real answer
    207  the scan ran but the scanner reported a problem; `findings` has what survived
    502  the scanning service was unreachable or refused the request
    400  the request itself was wrong
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status

from backend.api.dependencies import CurrentPrincipal, DbSession, ScannerBackendDep
from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import AuditAction
from backend.database.repositories.ticket import AuditRepository
from backend.grpc_service.client import ScannerServiceError
from backend.schemas.contracts import (
    FindingResponse,
    ScanRequestBody,
    ScanResponseBody,
    ScanTargetsResponse,
)
from backend.services.scanning import PartialScanError, ScanFailedError, ScanningService

logger = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResponseBody)
async def run_scan(
    payload: ScanRequestBody,
    session: DbSession,
    scanner_backend: ScannerBackendDep,
    principal: CurrentPrincipal,
) -> ScanResponseBody:
    """Run a scan and persist the findings.

    Idempotent by fingerprint: running the same scan twice reports the second
    run's findings as `refreshed_findings`, not `new_findings`. That is what
    makes a scheduled scan safe to run on a timer.
    """
    correlation_id = payload.correlation_id or new_correlation_id()
    service = ScanningService(session, scanner_backend, audit=AuditRepository(session))

    try:
        outcome = await service.run_scan(
            target=payload.target,
            scanners=payload.scanners or None,
            min_severity=payload.min_severity,
            correlation_id=correlation_id,
            actor=principal.audit_actor,
        )
    except PartialScanError as exc:
        # 207 Multi-Status: the operation partially succeeded. The findings
        # that were collected are real and worth showing; pretending the whole
        # scan failed would hide them, and reporting success would hide the
        # problem.
        logger.warning("partial scan correlation_id=%s detail=%s", correlation_id, exc.detail)
        return ScanResponseBody(
            scan_id=exc.outcome.scan_id,
            correlation_id=correlation_id,
            target=payload.target,
            new_findings=exc.outcome.new_count,
            refreshed_findings=len(exc.outcome.refreshed),
            total_findings=exc.outcome.total,
            counts_by_severity=exc.outcome.counts,
            duration_ms=exc.outcome.duration_ms,
            partial=True,
            created=[
                FindingResponse.from_model(f, include_snippet=False) for f in exc.outcome.created
            ],
        )

    except ScanFailedError as exc:
        logger.error("scan failed correlation_id=%s reason=%s", correlation_id, exc.reason)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"scan did not complete: {exc.reason}. "
                "This is 'we could not look', not 'there is nothing there'."
            ),
        ) from exc

    except ScannerServiceError as exc:
        logger.error("scanning service unreachable correlation_id=%s", correlation_id)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"scanning service unavailable: {exc}",
        ) from exc

    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return ScanResponseBody(
        scan_id=outcome.scan_id,
        correlation_id=outcome.correlation_id,
        target=outcome.target,
        new_findings=outcome.new_count,
        refreshed_findings=len(outcome.refreshed),
        total_findings=outcome.total,
        counts_by_severity=outcome.counts,
        duration_ms=outcome.duration_ms,
        partial=outcome.partial,
        created=[FindingResponse.from_model(f, include_snippet=False) for f in outcome.created],
    )


@router.get("/targets", response_model=ScanTargetsResponse)
async def list_scan_targets(scanner_backend: ScannerBackendDep) -> ScanTargetsResponse:
    """Targets the fixture scanner can serve, and what it is available for.

    Exists because the fixture scanner is deterministic: knowing the exact
    target strings is what makes the demo reproducible.

    The list is read out of the backend's *health*, not out of a private
    attribute on the in-process client. That used to be how it worked, and it
    meant this endpoint silently returned `[]` whenever the process was talking
    to a real gRPC scanning service -- a discovery endpoint that worked in
    development and returned nothing in the deployment it exists for. Both
    transports now report the same capability over the same interface.
    """
    health = await scanner_backend.health()
    return ScanTargetsResponse(
        fixture_targets=list(health.get("fixture_targets", [])),
        available_scanners=[str(s) for s in health.get("available_scanners", [])],
        note=(
            "Fixture targets are the only scan targets with deterministic output. "
            "The semgrep scanner accepts any directory path on the scanning host."
        ),
    )


@router.get("/history", response_model=list[dict[str, object]])
async def scan_history(
    session: DbSession,
    limit: int = 50,
) -> list[dict[str, object]]:
    """Recent scan runs, newest first, from the audit log.

    Read from `audit_logs` rather than a `scans` table on purpose: scan history
    is audit history, and a second table would be a second thing that can
    disagree with the audit trail about what was scanned.
    """
    entries = await AuditRepository(session).list_recent(
        actions=[AuditAction.SCAN_RUN], limit=limit
    )
    return [
        {
            "audit_id": str(entry.id),
            "actor": entry.actor,
            "correlation_id": entry.correlation_id,
            "summary": entry.summary,
            "payload": entry.payload,
            "created_at": entry.created_at.isoformat(),
        }
        for entry in entries
    ]
