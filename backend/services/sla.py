"""Severity-based SLA tracking.

Answers the question a security lead actually asks every morning: *what am I
going to be blamed for today?* The output is grouped by severity, because
"14 findings are late" is useless -- "2 critical and 5 high are late" is a
prioritised list.

The three-state model (`on_track` / `at_risk` / `breached`, plus `met`,
`stopped`, and `not_started`) comes from `backend/policy/rules.py`. This module
owns the *aggregation* over many findings, and the dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.enums import FindingStatus, Severity
from backend.database.models.finding import Finding
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import TicketRepository
from backend.policy.rules import SlaState, evaluate_sla, sla_hours_for

logger = get_logger(__name__)


@dataclass(slots=True)
class SeveritySlaBucket:
    """SLA posture for one severity level."""

    severity: Severity
    sla_hours: int
    total_open: int = 0
    on_track: int = 0
    at_risk: int = 0
    breached: int = 0
    met: int = 0
    stopped: int = 0
    not_started: int = 0
    oldest_breach_hours: float = 0.0
    """How long the single worst breach has been overdue. The number a lead
    looks at first, because it is the finding they will be asked about."""

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "sla_hours": self.sla_hours,
            "total_open": self.total_open,
            "on_track": self.on_track,
            "at_risk": self.at_risk,
            "breached": self.breached,
            "met": self.met,
            "stopped": self.stopped,
            "not_started": self.not_started,
            "breach_rate": round(self.breached / self.total_open, 4) if self.total_open else 0.0,
            "oldest_breach_hours": round(self.oldest_breach_hours, 1),
        }


@dataclass(slots=True)
class SlaDashboard:
    """The whole picture, in the shape the API returns it."""

    generated_at: datetime
    buckets: list[SeveritySlaBucket] = field(default_factory=list)
    total_open: int = 0
    total_breached: int = 0
    total_at_risk: int = 0
    remediations: dict[str, Any] = field(default_factory=dict)
    tickets: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "totals": {
                "open": self.total_open,
                "breached": self.total_breached,
                "at_risk": self.total_at_risk,
                "breach_rate": (
                    round(self.total_breached / self.total_open, 4) if self.total_open else 0.0
                ),
            },
            "by_severity": [bucket.as_dict() for bucket in self.buckets],
            "remediations": self.remediations,
            "tickets": self.tickets,
        }


class SlaService:
    """Computes SLA posture from the findings table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._findings = FindingRepository(session)

    async def state_for(self, finding: Finding, *, now: datetime | None = None) -> SlaState:
        """SLA state for a single finding.

        Recomputed from `first_seen_at` and `sla_due_at` rather than read from
        a stored `is_breached` column. A stored flag is a cached answer, and a
        cached answer needs a job to keep it fresh; deriving it means the
        number is correct the instant it is read, with nothing to fall behind.
        """
        return evaluate_sla(
            severity=finding.severity,
            due_at=finding.sla_due_at,
            first_seen_at=finding.first_seen_at,
            closed_at=finding.closed_at,
        )

    async def dashboard(self, *, now: datetime | None = None) -> SlaDashboard:
        """Full SLA posture across every open finding, grouped by severity.

        Terminal findings are included in the `met`/`stopped` counts because
        "we closed 40 of them" is part of the report -- a dashboard that only
        ever shows open work cannot show progress, and cannot show that the
        fix rate is fine while the breach count is rising.
        """
        moment = now or utc_now()
        open_findings = await self._findings.list_open_with_sla(limit=1000)
        closed_findings = await self._list_closed(limit=1000)

        buckets: dict[Severity, SeveritySlaBucket] = {
            severity: SeveritySlaBucket(severity=severity, sla_hours=sla_hours_for(severity))
            for severity in (
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            )
        }

        for finding in open_findings:
            bucket = buckets.get(finding.severity)
            if bucket is None:
                continue
            state = await self.state_for(finding, now=moment)
            bucket.total_open += 1
            _apply_state(bucket, state.state)
            if state.state == "breached" and state.hours_remaining is not None:
                overdue = abs(state.hours_remaining)
                bucket.oldest_breach_hours = max(bucket.oldest_breach_hours, overdue)

        for finding in closed_findings:
            bucket = buckets.get(finding.severity)
            if bucket is None:
                continue
            state = await self.state_for(finding, now=moment)
            if state.state == "met":
                bucket.met += 1
            else:
                bucket.stopped += 1

        dashboard = SlaDashboard(
            generated_at=moment,
            buckets=[b for b in buckets.values() if b.total_open or b.met or b.stopped],
            total_open=sum(b.total_open for b in buckets.values()),
            total_breached=sum(b.breached for b in buckets.values()),
            total_at_risk=sum(b.at_risk for b in buckets.values()),
        )

        dashboard.remediations = await RemediationRepository(self._session).remediation_stats()
        dashboard.tickets = await TicketRepository(self._session).counts_by_status()
        return dashboard

    async def _list_closed(self, *, limit: int) -> list[Finding]:
        terminal = [s.value for s in FindingStatus if s.is_terminal]
        result = await self._session.execute(
            select(Finding).where(Finding.status.in_(terminal)).limit(limit)
        )
        return list(result.scalars().all())


def _apply_state(bucket: SeveritySlaBucket, state: str) -> None:
    match state:
        case "on_track":
            bucket.on_track += 1
        case "at_risk":
            bucket.at_risk += 1
        case "breached":
            bucket.breached += 1
        case "not_started":
            bucket.not_started += 1
        case _:
            # A closed finding cannot reach here: closed findings are tallied
            # separately as met/stopped. Counted as on_track rather than
            # dropped so `total_open` always equals the sum of its parts.
            bucket.on_track += 1


async def findings_at_risk(session: AsyncSession, *, limit: int = 25) -> list[Finding]:
    """Open findings closest to breaching, most urgent first.

    "Closest to breaching" is a value judgement, and this is the answer: the
    amber list, sorted by how much time is left rather than by severity. A
    critical with three days left is more urgent than a high with twenty
    minutes left -- both are amber, and an analyst triaging the amber list
    wants them in deadline order.
    """
    repository = FindingRepository(session)
    open_findings = await repository.list_open_with_sla(limit=1000)

    scored: list[tuple[float, Finding]] = []
    for finding in open_findings:
        state = evaluate_sla(
            severity=finding.severity,
            due_at=finding.sla_due_at,
            first_seen_at=finding.first_seen_at,
            closed_at=None,
        )
        if state.state in ("at_risk", "breached") and state.hours_remaining is not None:
            scored.append((state.hours_remaining, finding))

    scored.sort(key=lambda pair: pair[0])
    logger.debug("at-risk sweep evaluated open=%d at_risk=%d", len(open_findings), len(scored))
    return [finding for _, finding in scored[:limit]]
