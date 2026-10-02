"""SLA dashboard routes.

The severity-based SLA view: what is open, what is late, and how late, grouped
by severity. This is the screen a security lead opens first thing in the
morning, so the numbers on it have to be defensible -- which is why the
classification lives in `backend/policy/rules.py::evaluate_sla` and is
recomputed on read rather than stored in a column that could drift.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Query

from backend.api.dependencies import DbSession
from backend.core.logging import get_logger
from backend.database.repositories.finding import FindingRepository
from backend.schemas.contracts import SlaDashboardResponse
from backend.services.sla import SlaService, findings_at_risk

logger = get_logger(__name__)

router = APIRouter(prefix="/sla", tags=["sla"])


@router.get("/dashboard", response_model=SlaDashboardResponse)
async def sla_dashboard(session: DbSession) -> SlaDashboardResponse:
    """Full SLA posture: totals, per-severity breakdown, remediation, tickets."""
    dashboard = await SlaService(session).dashboard()
    return SlaDashboardResponse(**dashboard.as_dict())


@router.get("/summary")
async def sla_summary(session: DbSession) -> dict[str, Any]:
    """The headline numbers only, for a status widget.

    A separate endpoint from `/dashboard` so a dashboard widget polling every
    30 seconds does not drag the whole per-severity breakdown and the
    remediation stats with it.
    """
    dashboard = await SlaService(session).dashboard()
    return {
        "generated_at": dashboard.generated_at.isoformat(),
        "open": dashboard.total_open,
        "breached": dashboard.total_breached,
        "at_risk": dashboard.total_at_risk,
        "awaiting_human_approval": dashboard.remediations.get("awaiting_human_approval", 0),
    }


@router.get("/breached")
async def breached_findings(
    session: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Open findings past their deadline, most urgent first."""
    breached = await FindingRepository(session).list_breached(limit=limit)
    return [
        {
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity.value,
            "file_path": finding.file_path,
            "due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
            "hours_overdue": _overdue_hours(finding),
        }
        for finding in breached
    ]


@router.get("/at-risk")
async def at_risk_findings(
    session: DbSession,
    limit: int = Query(default=25, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Findings nearest their deadline, soonest first.

    Ordered by hours remaining rather than severity, because this list answers
    "what do I work on today?" and a critical with three days left is the more
    urgent of two amber findings.
    """
    at_risk = await findings_at_risk(session, limit=limit)
    return [
        {
            "finding_id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity.value,
            "file_path": finding.file_path,
            "due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
        }
        for finding in at_risk
    ]


def _overdue_hours(finding: Any) -> float | None:
    from backend.core.clock import hours_between, utc_now

    if finding.sla_due_at is None:
        return None
    return round(abs(hours_between(utc_now(), finding.sla_due_at)), 1)
