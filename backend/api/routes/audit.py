"""Audit-log routes.

Read-only, by design. There is no POST, no DELETE, and no PATCH on this
router -- `backend/database/repositories/ticket.py::AuditRepository` exposes
append and read, and nothing else. An audit log that can be edited is not one,
so the absence is enforced structurally rather than by convention.

The endpoint that matters most is `/audit/correlation/{id}`: it returns
everything the system did during one externally-triggered operation, across
findings, proposals, pull requests, and MCP tool calls, in order. That is the
query an incident responder runs at 2am.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.dependencies import DbSession
from backend.database.enums import AuditAction
from backend.database.repositories.ticket import AuditRepository
from backend.schemas.contracts import AuditEntryResponse, AuditTrailResponse

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=AuditTrailResponse)
async def recent_audit_entries(
    session: DbSession,
    action: list[AuditAction] | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditTrailResponse:
    """The most recent audit entries, newest first."""
    entries = await AuditRepository(session).list_recent(actions=action, limit=limit)
    return AuditTrailResponse(
        entries=[AuditEntryResponse.from_model(e) for e in entries],
        total=len(entries),
    )


@router.get("/correlation/{correlation_id}", response_model=AuditTrailResponse)
async def audit_by_correlation(
    correlation_id: str,
    session: DbSession,
) -> AuditTrailResponse:
    """Every action taken during one externally-triggered operation, in order.

    A single scan, a single `propose_fix` call, a single approval: everything
    the system did, with one id. This is the forensic view.
    """
    entries = await AuditRepository(session).list_by_correlation(correlation_id)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"no audit entries for correlation id {correlation_id!r}. "
                "Check the id, or note that a correlation id is only recorded "
                "for operations that reached persistence."
            ),
        )
    return AuditTrailResponse(
        entries=[AuditEntryResponse.from_model(e) for e in entries],
        total=len(entries),
    )


@router.get("/entity/{entity_type}/{entity_id}", response_model=AuditTrailResponse)
async def audit_for_entity(
    entity_type: str,
    entity_id: str,
    session: DbSession,
) -> AuditTrailResponse:
    """The full history of one finding, ticket, proposal, or pull request."""
    entries = await AuditRepository(session).list_for_entity(entity_type, entity_id)
    if not entries:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no audit entries for {entity_type} {entity_id!r}",
        )
    return AuditTrailResponse(
        entries=[AuditEntryResponse.from_model(e) for e in entries],
        total=len(entries),
    )


@router.get("/stats")
async def audit_stats(session: DbSession) -> dict[str, int]:
    """Entry counts grouped by action.

    Useful as a quick check that the log is being written at all, and as a
    coarse view of where the system's activity is.
    """
    return await AuditRepository(session).count_by_action()


@router.get("/machine-activity")
async def machine_activity(
    session: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
) -> AuditTrailResponse:
    """Only the actions taken by machines: scanners, agents, and MCP tools.

    The actors use a `mcp:`, `agent:`, or `system:` prefix by convention, so
    "what did the automation do, as opposed to the people?" is one filter
    rather than a join.
    """
    repository = AuditRepository(session)
    all_entries = await repository.list_recent(limit=2000)
    machine_prefixes = ("mcp:", "agent:", "system:")
    filtered = [e for e in all_entries if e.actor.startswith(machine_prefixes)][:limit]
    return AuditTrailResponse(
        entries=[AuditEntryResponse.from_model(e) for e in filtered],
        total=len(filtered),
    )
