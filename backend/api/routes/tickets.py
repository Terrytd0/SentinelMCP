"""Ticket and CVE routes.

`GET /cves/{cve_id}` is the HTTP twin of the `get_cve_details` MCP tool, over
the same `CveService` and the same local advisory feed. Two surfaces, one
implementation, so the two can never drift apart in what they tell a user.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.dependencies import CurrentPrincipal, CveServiceDep, DbSession
from backend.core.ids import new_correlation_id
from backend.database.enums import AuditAction, FindingStatus, TicketStatus
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.schemas.contracts import CreateTicketRequest, TicketResponse
from backend.services.cve import CveNotFoundError

router = APIRouter(tags=["tickets", "cve"])


@router.get("/cves/{cve_id}")
async def get_cve(cve_id: str, service: CveServiceDep) -> dict[str, object]:
    """One advisory, with the CVSS band and any severity disagreement flagged.

    Returns 404 rather than an empty object for an unknown CVE, because "this
    CVE is not in our local feed" is a different answer from "this CVE has no
    description" and a client rendering a triage view needs to tell them apart.
    """
    try:
        advisory = service.get(cve_id)
    except CveNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"{exc} This service reads a local advisory feed rather than "
                "querying NVD, so a recent or obscure CVE will miss."
            ),
        ) from exc

    # `severity` is a plain value here rather than the enum, because the
    # response is advisory metadata, not a request the caller can use to set
    # anything -- and the derived fields are informational.
    return {
        **advisory,
        "severity": str(advisory.get("severity") or ""),
        "note": "advisories come from data/cve/advisories.json; refresh on a schedule",
    }


@router.get("/cves")
async def search_cves(
    service: CveServiceDep,
    product: str | None = Query(default=None, max_length=200),
    min_cvss: float = Query(default=0.0, ge=0.0, le=10.0),
) -> dict[str, object]:
    """Search the local advisory feed by product and CVSS floor."""
    matches = service.search(product=product, min_cvss=min_cvss)
    return {"count": len(matches), "advisories": matches}


@router.get("/tickets", response_model=list[TicketResponse])
async def list_tickets(
    session: DbSession,
    ticket_status: list[TicketStatus] | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[TicketResponse]:
    """Tracked remediation tickets."""
    found = await TicketRepository(session).list_tickets(statuses=ticket_status, limit=limit)
    return [TicketResponse.from_model(t) for t in found]


@router.get("/tickets/{ticket_key}", response_model=TicketResponse)
async def get_ticket(ticket_key: str, session: DbSession) -> TicketResponse:
    """One ticket by its human-facing key, e.g. `SEC-1042`."""
    ticket = await TicketRepository(session).get_by_key(ticket_key.strip().upper())
    if ticket is None:
        raise HTTPException(status_code=404, detail=f"ticket {ticket_key!r} not found")
    return TicketResponse.from_model(ticket)


@router.post("/tickets", response_model=TicketResponse, status_code=status.HTTP_201_CREATED)
async def create_ticket(
    payload: CreateTicketRequest,
    session: DbSession,
    principal: CurrentPrincipal,
) -> TicketResponse:
    """Open a ticket for a finding, with an audit row.

    Mirrors the `create_ticket` MCP tool. The HTTP version records a named
    human as the actor; the MCP version records `mcp:create_ticket`. Same
    table, so "who actually opened this?" is answerable for both.
    """
    findings = FindingRepository(session)
    finding = await findings.get(payload.finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    tickets = TicketRepository(session)
    audit = AuditRepository(session)
    correlation_id = new_correlation_id()

    ticket = await tickets.create_ticket(
        finding_id=payload.finding_id,
        title=payload.title,
        description=payload.description,
        priority=finding.severity,
        created_by=principal.audit_actor,
        assignee=payload.assignee,
    )
    if finding.triaged_at is None:
        await findings.update_status(payload.finding_id, FindingStatus.TRIAGED)

    await audit.append(
        actor=principal.audit_actor,
        action=AuditAction.TICKET_CREATED,
        entity_type="ticket",
        entity_id=ticket.id,
        correlation_id=correlation_id,
        summary=f"opened {ticket.ticket_key}: {payload.title}",
        payload={
            "finding_id": str(payload.finding_id),
            "ticket_key": ticket.ticket_key,
            "priority": ticket.priority.value,
        },
    )
    return TicketResponse.from_model(ticket)
