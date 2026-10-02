"""The scanning service: run a scan, persist findings, open the audit trail.

This is the orchestrator that ties the gRPC boundary to the database. It is
the reason the scanner abstraction is worth having -- the same code path serves
an in-process registry (tests, scripts) and a real gRPC service (the API), and
nothing above this layer knows which.

The flow, and the reasoning for each step:

    1. compute a correlation id          -- one external action, one id
    2. call the scanner backend          -- gRPC or in-process
    3. classify the outcome              -- clean / partial / failed
    4. compute SLA deadlines             -- policy decides, here it is applied
    5. upsert by fingerprint             -- re-scan updates, never duplicates
    6. write audit rows                  -- per finding and per scan
    7. emit telemetry                    -- same event whether gRPC or not

Step 3 is the one people skip. A scan that returned an error and no findings
must not be persisted as "0 findings" or recorded as a successful run: the
difference between "the code is clean" and "we could not look" is the whole
value of a security tool, and conflating them is how a real critical ships.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.core.ids import compute_fingerprint, new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import AuditAction, ScannerKind, Severity
from backend.database.models.finding import Finding
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.ticket import AuditRepository
from backend.grpc_service.client import ScannerBackend
from backend.policy.rules import evaluate_auto_remediation, sla_deadline_for
from backend.scanners.base import ScanResult
from backend.telemetry import get_telemetry_client
from backend.telemetry.events import EventStatus

logger = get_logger(__name__)


class ScanFailedError(RuntimeError):
    """The scan did not produce usable results.

    Raised (rather than returned) so no caller can accidentally treat a failed
    scan as a clean one. The message distinguishes the three failure modes.
    """

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class PartialScanError(ScanFailedError):
    """The scanner produced some findings and then reported a problem.

    Subclasses `ScanFailedError` because a caller that cannot handle a failed
    scan certainly cannot handle a half-failed one -- but the type exists so
    that a caller who *can* (the dashboard) can choose to show the findings
    that did come back, via the `outcome` attribute.
    """

    def __init__(self, reason: str, detail: str, outcome: ScanOutcome) -> None:
        super().__init__(reason, detail)
        self.outcome = outcome


@dataclass(slots=True)
class ScanOutcome:
    """What a scan did, as reported to the caller."""

    scan_id: uuid.UUID
    correlation_id: str
    target: str
    scanner_kinds: list[ScannerKind]
    created: list[Finding] = field(default_factory=list)
    refreshed: list[Finding] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    duration_ms: float = 0.0
    partial: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.created) + len(self.refreshed)

    @property
    def new_count(self) -> int:
        return len(self.created)

    def summary(self) -> dict[str, Any]:
        return {
            "scan_id": str(self.scan_id),
            "correlation_id": self.correlation_id,
            "target": self.target,
            "scanners": [k.value for k in self.scanner_kinds],
            "new": self.new_count,
            "refreshed": len(self.refreshed),
            "total": self.total,
            "partial": self.partial,
            "counts": self.counts,
            "duration_ms": round(self.duration_ms, 2),
            "errors": self.errors,
        }


class ScanningService:
    """Runs scans and persists what they find."""

    def __init__(
        self,
        session: AsyncSession,
        scanner_backend: ScannerBackend,
        *,
        audit: AuditRepository | None = None,
    ) -> None:
        self._session = session
        self._scanners = scanner_backend
        self._findings = FindingRepository(session)
        self._audit = audit or AuditRepository(session)
        self._telemetry = get_telemetry_client()

    async def run_scan(
        self,
        *,
        target: str,
        scanners: Sequence[ScannerKind] | None = None,
        min_severity: Severity | None = None,
        correlation_id: str | None = None,
        actor: str = "system:scan",
    ) -> ScanOutcome:
        """Run one scan and persist everything it found.

        Returns a `ScanOutcome`, or raises `ScanFailedError` /
        `PartialScanError`. Raises on total failure so the caller cannot read a
        failed scan as a clean one; the partial case is also an exception, with
        the recovered findings attached to the raised object for a caller
        sophisticated enough to use them.
        """
        scan_id = uuid.uuid4()
        correlation = correlation_id or new_correlation_id()
        requested = list(scanners or [ScannerKind.FIXTURE])

        logger.info(
            "scan started scan_id=%s target=%s scanners=%s correlation_id=%s",
            scan_id,
            target,
            [k.value for k in requested],
            correlation,
        )

        try:
            with self._telemetry.measure(
                "scan.run", correlation_id=correlation, metadata={"target": target}
            ) as measurement:
                result = await self._scanners.scan(
                    target,
                    scanners=requested,
                    min_severity=min_severity,
                    correlation_id=correlation,
                )
                outcome = await self._persist(result, scan_id=scan_id, correlation_id=correlation)
                measurement.metadata = {
                    "target": target,
                    "findings": outcome.total,
                    "new": outcome.new_count,
                    "partial": outcome.partial,
                }
                return outcome

        except ScanFailedError:
            # A failed scan gets an audit row too: "we tried and could not
            # look" is exactly the information an auditor needs.
            await self._audit.append(
                actor=actor,
                action=AuditAction.SCAN_RUN,
                entity_type="scan",
                entity_id=scan_id,
                correlation_id=correlation,
                summary=f"scan failed for target {target!r}",
                payload={
                    "target": target,
                    "outcome": "failed",
                    "scanners": [k.value for k in requested],
                },
            )
            self._telemetry.emit(
                "scan.run",
                status=EventStatus.ERROR,
                correlation_id=correlation,
                error_type=ScanFailedError.__name__,
                metadata={"target": target, "outcome": "failed"},
            )
            raise

    async def _persist(
        self, result: ScanResult, *, scan_id: uuid.UUID, correlation_id: str
    ) -> ScanOutcome:
        """Turn a scan result into a persisted outcome, or raise.

        The three-way decision lives here rather than in the caller so that
        every caller -- API route, MCP tool, script -- gets identical
        semantics.
        """
        if result.error and not result.findings:
            raise ScanFailedError(
                "scanner reported an error and produced no findings", result.error
            )
        if result.error:
            # Keep the findings; raise so the caller knows the run was partial.
            outcome = await self._store(result, scan_id=scan_id, correlation_id=correlation_id)
            raise PartialScanError("scanner reported a partial result", result.error, outcome)

        return await self._store(result, scan_id=scan_id, correlation_id=correlation_id)

    async def _store(
        self, result: ScanResult, *, scan_id: uuid.UUID, correlation_id: str
    ) -> ScanOutcome:
        """Upsert findings, stamp SLA deadlines, and write the audit trail."""
        deadlines = {
            # Keyed by fingerprint, which the repository recomputes the same
            # way -- so the policy decision and the stored deadline cannot
            # disagree, because they are keyed identically.
            _fingerprint_for(finding, result): sla_deadline_for(finding.severity)
            for finding in result.findings
        }

        created, refreshed = await self._findings.upsert_from_scan(
            raw_findings=result.findings,
            scanner_kind=result.scanner_kind,
            target=result.target,
            scan_id=scan_id,
            sla_deadlines=deadlines,
        )

        # Whether the agent may eventually touch this is policy, evaluated
        # once here and stored on the row, so the MCP tool and the remediation
        # script do not each re-derive it (and cannot disagree). The
        # service layer still re-checks before drafting
        # (`RemediationService._assert_allowed`) -- this is a fast filter, not
        # the gate.
        source_roots = tuple(get_settings().remediation_source_roots)
        for finding in created:
            finding.auto_remediation_eligible = evaluate_auto_remediation(
                severity=finding.severity,
                confidence=finding.confidence,
                status=finding.status,
                file_path=finding.file_path,
                snippet=finding.snippet,
                remediation_attempts=finding.remediation_attempts,
                source_roots=source_roots,
            ).eligible

        await self._record_audit(
            result=result,
            scan_id=scan_id,
            correlation_id=correlation_id,
            created=created,
            refreshed=refreshed,
        )

        counts = result.counts_by_severity()
        return ScanOutcome(
            scan_id=scan_id,
            correlation_id=correlation_id,
            target=result.target,
            scanner_kinds=[result.scanner_kind],
            created=created,
            refreshed=refreshed,
            counts={k.value: v for k, v in counts.items()},
            duration_ms=result.duration_ms,
            partial=result.error is not None,
            errors=[result.error] if result.error else [],
        )

    async def _record_audit(
        self,
        *,
        result: ScanResult,
        scan_id: uuid.UUID,
        correlation_id: str,
        created: Sequence[Finding],
        refreshed: Sequence[Finding],
    ) -> None:
        """Write the scan row and one row per finding.

        One row per finding is a lot of writes for a large scan, and that is
        the correct trade here: an audit log that records "40 findings" without
        recording *which* forty is not an audit log. The batch is inside the
        caller's transaction, so it is all-or-nothing with the findings
        themselves.
        """
        await self._audit.append(
            actor="system:scanner",
            action=AuditAction.SCAN_RUN,
            entity_type="scan",
            entity_id=scan_id,
            correlation_id=correlation_id,
            summary=f"scanned {result.target!r} with {result.scanner_kind.value}",
            payload={
                "target": result.target,
                "scanner": result.scanner_kind.value,
                "new": len(created),
                "refreshed": len(refreshed),
                "counts": {k.value: v for k, v in result.counts_by_severity().items()},
                "duration_ms": round(result.duration_ms, 2),
                "partial": result.error is not None,
            },
        )

        for finding in created:
            await self._audit.append(
                actor="system:scanner",
                action=AuditAction.FINDING_CREATED,
                entity_type="finding",
                entity_id=finding.id,
                correlation_id=correlation_id,
                summary=f"{finding.severity.value}: {finding.title}",
                payload={
                    "fingerprint": finding.fingerprint,
                    "rule_id": finding.rule_id,
                    "scanner": finding.scanner_kind.value,
                    "file_path": finding.file_path,
                    "cve_ids": finding.cve_ids,
                    "sla_due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
                },
            )

        for finding in refreshed:
            await self._audit.append(
                actor="system:scanner",
                action=AuditAction.FINDING_UPDATED,
                entity_type="finding",
                entity_id=finding.id,
                correlation_id=correlation_id,
                summary=f"re-observed: {finding.title}",
                payload={
                    "fingerprint": finding.fingerprint,
                    "severity": finding.severity.value,
                    "last_seen_at": finding.last_seen_at.isoformat(),
                },
            )


def _fingerprint_for(finding: Any, result: ScanResult) -> str:
    """Recompute a raw finding's fingerprint, exactly as the repository will.

    Calls the same `compute_fingerprint` with the same four arguments the
    repository passes, so the SLA deadline keyed here and the row keyed there
    cannot drift -- there is no second implementation to get out of sync.
    """
    return compute_fingerprint(
        scanner_kind=result.scanner_kind.value,
        rule_id=finding.rule_id,
        file_path=finding.file_path,
        target=result.target,
        title=finding.title,
    )
