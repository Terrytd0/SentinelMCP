"""Finding triage routes.

Read and status-change endpoints. Note the one convention that runs through
all of them: **snippets are returned by the detail endpoint and omitted from
the list.** A triage queue of 200 findings does not need 200 blocks of source
code, and the snippet is the most sensitive field in the system -- shipping it
in a list response puts it in every browser cache and proxy log between the
client and the server, whether or not anyone read it.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.dependencies import CurrentPrincipal, DbSession
from backend.core.ids import new_correlation_id
from backend.database.enums import (
    AuditAction,
    FindingStatus,
    ScannerKind,
    Severity,
)
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.policy.rules import evaluate_sla
from backend.schemas.contracts import (
    FindingDetailResponse,
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdateRequest,
    SlaStateResponse,
)
from backend.services.sla import SlaService

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    session: DbSession,
    severity: list[Severity] = Query(default_factory=list),
    scanner: list[ScannerKind] = Query(default_factory=list),
    status_filter: list[FindingStatus] = Query(default_factory=list, alias="status"),
    query: str | None = Query(default=None, max_length=200),
    include_closed: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> FindingListResponse:
    """The triage queue, most urgent first.

    Defaults to open findings only. `include_closed=true` adds remediated,
    accepted-risk, and false-positive rows -- useful for a fix-rate report, and
    off by default because those rows are not work.
    """
    repository = FindingRepository(session)

    if include_closed:
        found = await repository.search(
            query=query,
            statuses=status_filter or None,
            severities=severity or None,
            limit=limit + offset,
        )
    else:
        found = await repository.list_open_with_sla(
            severities=severity or None,
            scanner_kinds=scanner or None,
            limit=limit,
            offset=offset,
        )
        if status_filter:
            wanted = set(status_filter)
            found = [f for f in found if f.status in wanted]
        if query:
            needle = query.lower()
            found = [
                f
                for f in found
                if needle in f.title.lower()
                or needle in f.description.lower()
                or needle in (f.file_path or "").lower()
                or needle in f.rule_id.lower()
            ]

    return FindingListResponse(
        findings=[FindingResponse.from_model(f, include_snippet=False) for f in found],
        total=len(found),
        limit=limit,
        offset=offset,
    )


@router.get("/at-risk", response_model=list[FindingResponse])
async def list_at_risk(
    session: DbSession,
    limit: int = Query(default=25, ge=1, le=200),
) -> list[FindingResponse]:
    """Findings closest to breaching, in deadline order.

    Not severity order. A critical with three days left is more urgent to fix
    today than a high with twenty minutes left, and the person triaging this
    list needs them ordered by how much time is actually left.
    """
    from backend.services.sla import findings_at_risk

    at_risk = await findings_at_risk(session, limit=limit)
    return [FindingResponse.from_model(f, include_snippet=False) for f in at_risk]


@router.get("/by-cve/{cve_id}", response_model=list[FindingResponse])
async def findings_by_cve(
    cve_id: str,
    session: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[FindingResponse]:
    """Every finding referencing a CVE."""
    normalized = cve_id.strip().upper()
    found = await FindingRepository(session).find_by_cve(normalized, limit=limit)
    return [FindingResponse.from_model(f, include_snippet=False) for f in found]


@router.get("/{finding_id}", response_model=FindingDetailResponse)
async def get_finding(finding_id: uuid.UUID, session: DbSession) -> FindingDetailResponse:
    """One finding, with the snippet, SLA state, and current workflow context.

    This is the only endpoint that returns source code, and it is a single
    finding at a time on purpose.
    """
    repository = FindingRepository(session)
    finding = await repository.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    sla_state = await SlaService(session).state_for(finding)
    tickets = await TicketRepository(session).list_for_finding(finding_id)
    latest = await RemediationRepository(session).latest_proposal_for_finding(finding_id)

    base = FindingResponse.from_model(finding, include_snippet=True)
    return FindingDetailResponse(
        **base.model_dump(),
        raw_payload=dict(finding.raw_payload),
        sla=SlaStateResponse(
            state=sla_state.state,
            breached=sla_state.breached,
            hours_remaining=sla_state.hours_remaining,
            due_at=sla_state.due_at,
            fraction_elapsed=sla_state.fraction_elapsed,
        ),
        ticket_keys=[t.ticket_key for t in tickets],
        latest_proposal_status=latest.status if latest else None,
    )


@router.post("/{finding_id}/status", response_model=FindingDetailResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdateRequest,
    session: DbSession,
    principal: CurrentPrincipal,
) -> FindingDetailResponse:
    """Move a finding through its lifecycle, with an audit row.

    Supports optimistic concurrency through `expected_current_status`. Two
    analysts triaging from two browser tabs is a real scenario, and
    last-write-wins would silently discard one of them -- so the second write
    gets a 409 and the UI can re-read.
    """
    repository = FindingRepository(session)
    audit = AuditRepository(session)
    correlation_id = new_correlation_id()

    finding = await repository.get(finding_id)
    if finding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="finding not found")

    if (
        payload.expected_current_status is not None
        and finding.status != payload.expected_current_status
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"finding is {finding.status.value!r}, not "
                f"{payload.expected_current_status.value!r}; re-read and retry"
            ),
        )

    previous = finding.status
    updated = await repository.update_status(finding_id, payload.status)
    if updated is None:  # pragma: no cover - the row was just read
        raise HTTPException(status_code=404, detail="finding not found")

    action = (
        AuditAction.FINDING_STATUS_CHANGED
        if payload.status.is_terminal is False
        else AuditAction.FINDING_STATUS_CHANGED
    )
    await audit.append(
        actor=principal.audit_actor,
        action=action,
        entity_type="finding",
        entity_id=finding_id,
        correlation_id=correlation_id,
        summary=f"{previous.value} -> {payload.status.value}: {finding.title}",
        payload={
            "from": previous.value,
            "to": payload.status.value,
            "reason": payload.reason,
            "severity": finding.severity.value,
        },
    )

    sla_state = evaluate_sla(
        severity=updated.severity,
        due_at=updated.sla_due_at,
        first_seen_at=updated.first_seen_at,
        closed_at=updated.closed_at,
    )
    base = FindingResponse.from_model(updated, include_snippet=True)
    return FindingDetailResponse(
        **base.model_dump(),
        raw_payload=dict(updated.raw_payload),
        sla=SlaStateResponse(
            state=sla_state.state,
            breached=sla_state.breached,
            hours_remaining=sla_state.hours_remaining,
            due_at=sla_state.due_at,
            fraction_elapsed=sla_state.fraction_elapsed,
        ),
    )
