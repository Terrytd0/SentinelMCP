"""Finding repository.

Two things here matter more than the CRUD:

1. `upsert_from_scan()`, which implements the fingerprint-based identity that
   makes re-running a scan safe. Without it, every scheduled scan inflates the
   open-finding count and the SLA dashboard becomes noise.
2. `list_open_with_sla()`, the query behind the dashboard. It has to be
   correct about *terminal* states, or the numbers it reports are wrong in the
   direction that is hardest to notice.

No raw SQLAlchemy outside this module. Services and routes go through here.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.clock import utc_now
from backend.core.ids import compute_fingerprint
from backend.core.logging import get_logger
from backend.database.enums import FindingStatus, ScannerKind, Severity
from backend.database.models.finding import Finding
from backend.scanners.base import RawFinding

logger = get_logger(__name__)


class FindingRepository:
    """Data access for `findings`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, finding_id: uuid.UUID) -> Finding | None:
        return await self._session.get(Finding, finding_id)

    async def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        result = await self._session.execute(
            select(Finding).where(Finding.fingerprint == fingerprint)
        )
        return result.scalar_one_or_none()

    async def list_by_ids(self, finding_ids: Sequence[uuid.UUID]) -> list[Finding]:
        if not finding_ids:
            return []
        result = await self._session.execute(
            select(Finding).where(Finding.id.in_(list(finding_ids)))
        )
        return list(result.scalars().all())

    async def list_open_with_sla(
        self,
        *,
        severities: Sequence[Severity] | None = None,
        scanner_kinds: Sequence[ScannerKind] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Finding]:
        """Actionable findings only, most urgent first.

        Excludes terminal states explicitly rather than relying on a status
        filter being exhaustive. A new terminal status added to the enum must
        not silently start showing up as "still open" here -- that regression
        is exactly the kind that makes a dashboard quietly wrong.
        """
        terminal = [s.value for s in FindingStatus if s.is_terminal]
        conditions = [Finding.status.notin_(terminal)]
        if severities:
            conditions.append(Finding.severity.in_(list(severities)))
        if scanner_kinds:
            conditions.append(Finding.scanner_kind.in_(list(scanner_kinds)))

        result = await self._session.execute(
            select(Finding)
            .where(and_(*conditions))
            # Severity is a string column, so ordering has to happen in Python:
            # `ORDER BY severity` would sort alphabetically (critical, high,
            # info, low, medium) and put INFO at the top. The rank is a
            # property of the enum, not of the string, so the sort is applied
            # after the query. Bounded by `limit` first to keep the page small.
            .order_by(Finding.first_seen_at.asc())
            .limit(min(limit, 1000))
            .offset(offset)
        )
        return sorted(result.scalars().all(), key=lambda f: (f.severity.rank, f.first_seen_at))

    async def list_breached(
        self, *, now: datetime | None = None, limit: int = 200
    ) -> list[Finding]:
        """Open findings whose deadline has passed, most urgent first.

        "Breached" here means *still open and past due*. Findings that were
        fixed late are handled by the SLA service from `closed_at`; they are
        not in this query because a fixed finding is not an outstanding
        obligation.
        """
        moment = now or utc_now()
        terminal = [s.value for s in FindingStatus if s.is_terminal]
        result = await self._session.execute(
            select(Finding)
            .where(
                Finding.status.notin_(terminal),
                Finding.sla_due_at.is_not(None),
                Finding.sla_due_at < moment,
            )
            .order_by(Finding.sla_due_at.asc())
            .limit(limit)
        )
        return sorted(result.scalars().all(), key=lambda f: (f.severity.rank, f.sla_due_at))

    async def counts_by_status(self) -> dict[str, int]:
        """`{status: count}` for the dashboard's headline tiles."""
        result = await self._session.execute(
            select(Finding.status, func.count()).group_by(Finding.status)
        )
        return {str(status): count for status, count in result.all()}

    async def counts_by_severity(self, *, open_only: bool = True) -> dict[Severity, int]:
        """`{severity: count}` for every severity, zero-filled.

        Keyed by the enum rather than its string so a caller can index with
        `Severity.CRITICAL` and be checked by the type system.
        """
        statement = select(Finding.severity, func.count()).group_by(Finding.severity)
        if open_only:
            terminal = [s.value for s in FindingStatus if s.is_terminal]
            statement = statement.where(Finding.status.notin_(terminal))
        result = await self._session.execute(statement)
        counts: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for severity, count in result.all():
            counts[Severity(severity)] = int(count)
        return counts

    async def update_status(
        self,
        finding_id: uuid.UUID,
        new_status: FindingStatus,
        *,
        now: datetime | None = None,
    ) -> Finding | None:
        """Move a finding to a new lifecycle state, stamping the right timestamps.

        The timestamp bookkeeping lives here rather than in each caller
        because getting it wrong is subtle and the consequences compound:
        `closed_at` is what stops the SLA clock, and a finding closed without
        it keeps accruing breach time forever.
        """
        moment = now or utc_now()
        finding = await self.get(finding_id)
        if finding is None:
            return None

        finding.status = new_status
        if new_status is FindingStatus.TRIAGED and finding.triaged_at is None:
            finding.triaged_at = moment
        if new_status is FindingStatus.REMEDIATED:
            finding.remediated_at = moment
        if new_status.is_terminal:
            finding.closed_at = moment
        else:
            # Re-opening clears the terminal markers, or the dashboard would
            # show a closed finding as closed while the status says open.
            finding.closed_at = None
            if new_status is not FindingStatus.REMEDIATED:
                finding.remediated_at = None

        await self._session.flush()
        return finding

    async def increment_remediation_attempts(self, finding_ids: Sequence[uuid.UUID]) -> None:
        """Count one more agent attempt against each of these findings."""
        if not finding_ids:
            return
        await self._session.execute(
            update(Finding)
            .where(Finding.id.in_(list(finding_ids)))
            .values(remediation_attempts=Finding.remediation_attempts + 1)
        )
        await self._session.flush()

    async def upsert_from_scan(
        self,
        *,
        raw_findings: Sequence[RawFinding],
        scanner_kind: ScannerKind,
        target: str,
        scan_id: uuid.UUID,
        sla_deadlines: dict[str, datetime] | None = None,
    ) -> tuple[list[Finding], list[Finding]]:
        """Persist a scan's findings, matching existing rows by fingerprint.

        Returns `(created, refreshed)`. The split is what lets the API report
        "3 new, 5 already known" instead of just a total -- an analyst cares
        only about the new ones.

        `sla_deadlines` maps a fingerprint to the deadline the *caller* computed,
        rather than this method calling the policy engine. Keeping the policy
        call in the service layer means the rule has one home and a test that
        can assert it without a database.

        On a refresh, only the fields a scanner can legitimately change are
        updated (`last_seen_at`, severity, confidence, description, snippet,
        raw payload). `first_seen_at`, `sla_due_at`, `status`, and every
        lifecycle timestamp are left alone -- a re-scan must not restart an
        SLA clock that a human is already working against.
        """
        created: list[Finding] = []
        refreshed: list[Finding] = []
        now = utc_now()
        deadlines = sla_deadlines or {}

        for raw in raw_findings:
            fingerprint = compute_fingerprint(
                scanner_kind=scanner_kind.value,
                rule_id=raw.rule_id,
                file_path=raw.file_path,
                target=target,
                title=raw.title,
            )
            existing = await self.get_by_fingerprint(fingerprint)

            if existing is not None:
                existing.last_seen_at = now
                existing.severity = raw.severity
                existing.confidence = raw.confidence
                existing.title = raw.title
                existing.description = raw.description
                existing.snippet = raw.snippet
                existing.start_line = raw.start_line
                existing.end_line = raw.end_line
                existing.cwe_ids = list(raw.cwe_ids)
                existing.cve_ids = list(raw.cve_ids)
                existing.raw_payload = dict(raw.raw_payload)
                existing.scan_id = scan_id
                refreshed.append(existing)
                continue

            finding = Finding(
                fingerprint=fingerprint,
                rule_id=raw.rule_id,
                title=raw.title,
                description=raw.description,
                severity=raw.severity,
                confidence=raw.confidence,
                scanner_kind=scanner_kind,
                target=target,
                file_path=raw.file_path,
                start_line=raw.start_line,
                end_line=raw.end_line,
                snippet=raw.snippet,
                cwe_ids=list(raw.cwe_ids),
                cve_ids=list(raw.cve_ids),
                raw_payload=dict(raw.raw_payload),
                status=FindingStatus.OPEN,
                first_seen_at=raw.detected_at or now,
                last_seen_at=now,
                sla_due_at=deadlines.get(fingerprint),
                auto_remediation_eligible=False,
                scan_id=scan_id,
            )
            self._session.add(finding)
            created.append(finding)

        await self._session.flush()
        logger.info(
            "persisted scan findings scan_id=%s created=%d refreshed=%d",
            scan_id,
            len(created),
            len(refreshed),
        )
        return created, refreshed

    async def search(
        self,
        *,
        query: str | None = None,
        statuses: Sequence[FindingStatus] | None = None,
        severities: Sequence[Severity] | None = None,
        cve_id: str | None = None,
        limit: int = 50,
    ) -> list[Finding]:
        """Text and field search across the open backlog.

        A deliberately simple `ILIKE` over title/description/file_path rather
        than a full-text index: this is a triage tool where a security analyst
        types a CVE id or a rule name, and a Postgres `tsvector` column would
        be a second schema to keep in sync for no benefit at this scale.
        """
        conditions = []
        if query:
            pattern = f"%{query.strip()}%"
            conditions.append(
                or_(
                    Finding.title.ilike(pattern),
                    Finding.description.ilike(pattern),
                    Finding.file_path.ilike(pattern),
                    Finding.rule_id.ilike(pattern),
                )
            )
        if statuses:
            conditions.append(Finding.status.in_(list(statuses)))
        if severities:
            conditions.append(Finding.severity.in_(list(severities)))

        statement = select(Finding)
        if conditions:
            statement = statement.where(and_(*conditions))
        result = await self._session.execute(
            statement.order_by(Finding.last_seen_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def find_by_cve(self, cve_id: str, *, limit: int = 50) -> list[Finding]:
        """Findings referencing a CVE.

        `cve_ids` is a JSON array, so this uses a text containment match rather
        than an `= ANY(...)` index seek. Adequate because a single CVE maps to a
        handful of findings; the GIN index on `cve_ids` covers it if that
        assumption ever stops holding.
        """
        result = await self._session.execute(
            select(Finding)
            .where(Finding.cve_ids.contains([cve_id]))
            .order_by(Finding.last_seen_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())
