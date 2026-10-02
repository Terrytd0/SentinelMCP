"""The full pipeline against a real PostgreSQL.

These tests exercise the parts that cannot be unit tested: the fingerprint
upsert, SLA deadline stamping, transactional integrity, and the fact that the
schema the tests run against is the one Alembic actually created.

They skip themselves when PostgreSQL is not reachable, so a bare `pytest` stays
green on a machine with no database.
"""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import func, select

from backend.core.clock import utc_now
from backend.database.enums import (
    AuditAction,
    FindingStatus,
    ScannerKind,
    Severity,
)
from backend.database.models.audit_log import AuditLog
from backend.database.models.finding import Finding
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.ticket import AuditRepository
from backend.grpc_service.client import ScannerBackend
from backend.services.scanning import ScanFailedError, ScanningService

pytestmark = pytest.mark.integration


# --- Ingestion and identity ---------------------------------------------


async def test_a_scan_persists_its_findings(db_session: Any) -> None:
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    outcome = await service.run_scan(target="app/", actor="test")

    assert outcome.new_count == 8
    assert outcome.counts["critical"] == 2
    assert len(outcome.created) == 8
    await db_session.commit()


async def test_every_persisted_finding_has_a_fingerprint_and_an_sla_deadline(
    db_session: Any,
) -> None:
    """A finding with no deadline silently never breaches, and one with no
    fingerprint duplicates on every re-scan. Both are invisible until they have
    been running for a month."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")

    rows = (await db_session.execute(select(Finding))).scalars().all()
    assert rows
    for row in rows:
        assert len(row.fingerprint) == 64
        assert row.sla_due_at is not None
        assert row.first_seen_at is not None
        assert row.last_seen_at is not None
    await db_session.commit()


async def test_rescanning_updates_rather_than_duplicates(db_session: Any) -> None:
    """The most important persistence behaviour in the project.

    Without it, a scheduled scan reports 40 "new" findings every day, the open
    count inflates without bound, and the real backlog becomes invisible.
    """
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))

    first = await service.run_scan(target="app/", actor="test")
    assert first.new_count == 8
    assert len(first.refreshed) == 0
    await db_session.commit()

    second = await service.run_scan(target="app/", actor="test")
    assert second.new_count == 0, "a re-scan created duplicates"
    assert len(second.refreshed) == 8
    await db_session.commit()

    total = await db_session.scalar(select(func.count()).select_from(Finding))
    assert total == 8


async def test_a_rescan_does_not_restart_the_sla_clock(db_session: Any) -> None:
    """A human is already working against that deadline. Resetting it on every
    scheduled scan makes the SLA unenforceable."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))

    first = await service.run_scan(target="app/", actor="test")
    await db_session.commit()
    original_due = {f.fingerprint: f.sla_due_at for f in first.created}

    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    for finding in (await db_session.execute(select(Finding))).scalars().all():
        assert finding.sla_due_at == original_due[finding.fingerprint]


async def test_a_rescan_advances_last_seen_but_not_first_seen(db_session: Any) -> None:
    """The dashboard reports "new this week" from one and "still open" from the
    other; conflating them makes a two-year-old finding look new."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))

    first = await service.run_scan(target="app/", actor="test")
    await db_session.commit()
    first_seen = {f.fingerprint: f.first_seen_at for f in first.created}

    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    rows = (await db_session.execute(select(Finding))).scalars().all()
    assert rows
    for row in rows:
        assert row.first_seen_at == first_seen[row.fingerprint]
        assert row.last_seen_at >= row.first_seen_at


async def test_two_targets_do_not_collide(db_session: Any) -> None:
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await service.run_scan(target="services/payments/", actor="test")

    total = await db_session.scalar(select(func.count()).select_from(Finding))
    assert total == 13
    await db_session.commit()


# --- Failure handling ---------------------------------------------------


async def test_a_clean_target_is_not_a_failure(db_session: Any) -> None:
    """`new_findings: 0` is a true answer and must not raise."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    outcome = await service.run_scan(target="does/not/exist/", actor="test")
    assert outcome.new_count == 0
    assert outcome.partial is False
    await db_session.commit()


async def test_a_failed_scan_writes_an_audit_row(db_session: Any) -> None:
    """ "We tried and could not look" is exactly what an auditor needs to know,
    so a failure is recorded rather than only logged."""
    from backend.scanners.base import ScanResult

    class _FailingBackend(ScannerBackend):
        """A backend whose scanner always fails, to exercise the failure path."""

        async def scan(
            self,
            target: str,
            *,
            scanners: Any = None,
            min_severity: Any = None,
            correlation_id: str = "",
        ) -> ScanResult:
            return ScanResult(scanner_kind=ScannerKind.FIXTURE, target=target, error="disk full")

        async def health(self) -> dict[str, Any]:
            return {"healthy": True}

        async def close(self) -> None:
            return None

    service = ScanningService(db_session, _FailingBackend(), audit=AuditRepository(db_session))
    with pytest.raises(ScanFailedError):
        await service.run_scan(target="app/", actor="test")

    failures = await AuditRepository(db_session).list_recent(
        actions=[AuditAction.SCAN_RUN], limit=10
    )
    assert any(e.payload.get("outcome") == "failed" for e in failures)
    await db_session.commit()


# --- Audit trail --------------------------------------------------------


async def test_a_scan_writes_one_audit_row_per_finding(db_session: Any) -> None:
    """An audit log that records "8 findings" without recording *which* eight is
    not an audit log."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    outcome = await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    created = await AuditRepository(db_session).list_recent(
        actions=[AuditAction.FINDING_CREATED], limit=100
    )
    assert len(created) == 8
    assert {str(f.id) for f in outcome.created} == {e.entity_id for e in created}


async def test_audit_rows_carry_the_correlation_id(db_session: Any) -> None:
    """One externally-triggered operation, one id, queryable across tables."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    outcome = await service.run_scan(target="app/", actor="test", correlation_id="trace-me")
    await db_session.commit()

    entries = await AuditRepository(db_session).list_by_correlation("trace-me")
    assert len(entries) == 9  # one scan row + eight finding rows
    assert outcome.correlation_id == "trace-me"


async def test_the_audit_log_is_append_only(db_session: Any) -> None:
    repository = AuditRepository(db_session)
    assert not hasattr(repository, "update")
    assert not hasattr(repository, "delete")


# --- Repository queries -------------------------------------------------


async def test_open_findings_exclude_every_terminal_state(db_session: Any) -> None:
    """A new terminal status must not silently start showing up as "still
    open" -- that regression is exactly the kind that makes a dashboard quietly
    wrong."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    repository = FindingRepository(db_session)
    open_rows = await repository.list_open_with_sla(limit=100)
    assert len(open_rows) == 8

    target = open_rows[0]
    for terminal in FindingStatus:
        if not terminal.is_terminal:
            continue
        await repository.update_status(target.id, terminal)
    await db_session.commit()

    remaining = await repository.list_open_with_sla(limit=100)
    assert len(remaining) == 7
    assert target.id not in {f.id for f in remaining}


async def test_open_findings_are_sorted_by_severity_not_alphabetically(
    db_session: Any,
) -> None:
    """`ORDER BY severity` on a string column would put INFO at the top."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    rows = await FindingRepository(db_session).list_open_with_sla(limit=100)
    ranks = [f.severity.rank for f in rows]
    assert ranks == sorted(ranks)
    assert rows[0].severity is Severity.CRITICAL


async def test_closing_a_finding_stamps_closed_at(db_session: Any) -> None:
    """`closed_at` is what stops the SLA clock. Without it a closed finding
    accrues breach time forever."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    repository = FindingRepository(db_session)
    row = (await repository.list_open_with_sla(limit=1))[0]
    await repository.update_status(row.id, FindingStatus.REMEDIATED)

    refreshed = await repository.get(row.id)
    assert refreshed is not None
    assert refreshed.closed_at is not None
    assert refreshed.remediated_at is not None
    await db_session.commit()


async def test_reopening_a_finding_clears_the_terminal_timestamps(db_session: Any) -> None:
    """Otherwise the dashboard shows a closed finding as closed while the status
    column says open."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    repository = FindingRepository(db_session)
    row = (await repository.list_open_with_sla(limit=1))[0]
    await repository.update_status(row.id, FindingStatus.REMEDIATED)
    await repository.update_status(row.id, FindingStatus.OPEN)

    refreshed = await repository.get(row.id)
    assert refreshed is not None
    assert refreshed.closed_at is None
    assert refreshed.remediated_at is None
    await db_session.commit()


async def test_findings_by_cve_uses_the_jsonb_index(db_session: Any) -> None:
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    matches = await FindingRepository(db_session).find_by_cve("CVE-2023-46695")
    assert matches
    assert all("CVE-2023-46695" in f.cve_ids for f in matches)
    assert await FindingRepository(db_session).find_by_cve("CVE-1999-00000") == []


async def test_severity_counts_are_zero_filled(db_session: Any) -> None:
    """A dashboard that has to invent missing keys is a dashboard that renders
    wrong for the severities nobody has."""
    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    counts = await FindingRepository(db_session).counts_by_severity()
    assert set(counts) == set(Severity)
    assert counts[Severity.INFO] == 0
    assert counts[Severity.CRITICAL] == 2


async def test_breached_findings_exclude_closed_ones(db_session: Any) -> None:
    """A finding that was fixed late is handled by the SLA service, from
    `closed_at`. It is not an outstanding obligation."""
    from datetime import timedelta

    backend = await _backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test")
    await db_session.commit()

    repository = FindingRepository(db_session)
    rows = await repository.list_open_with_sla(limit=100)
    for row in rows:
        row.sla_due_at = utc_now() - timedelta(hours=1)
    await db_session.commit()

    assert len(await repository.list_breached()) == 8

    await repository.update_status(rows[0].id, FindingStatus.REMEDIATED)
    await db_session.commit()
    breached = await repository.list_breached()
    assert len(breached) == 7
    assert rows[0].id not in {f.id for f in breached}


async def test_a_failure_part_way_through_a_scan_persists_nothing(db_session: Any) -> None:
    """All-or-nothing: findings and their audit rows commit together or not at all.

    A scan whose audit trail is half-written is worse than a scan that failed
    outright -- it leaves findings on the dashboard that nobody can trace back
    to a scanner run.
    """
    from backend.database.repositories.ticket import AuditRepository as _Audit

    class _FailingAudit(_Audit):
        """Raises part-way through, after some findings have been flushed."""

        def __init__(self, session: Any) -> None:
            super().__init__(session)
            self._appends = 0

        async def append(self, **kwargs: Any) -> Any:
            self._appends += 1
            if self._appends > 3:
                raise RuntimeError("the audit sink died part-way through the scan")
            return await super().append(**kwargs)

    backend = await _backend()
    service = ScanningService(db_session, backend, audit=_FailingAudit(db_session))

    with pytest.raises(RuntimeError, match="died part-way"):
        await service.run_scan(target="app/", actor="test")

    # Uncommitted work must not survive. The session is rolled back by the
    # caller's transaction boundary; a fresh count proves it either way.
    await db_session.rollback()
    assert await db_session.scalar(select(func.count()).select_from(Finding)) == 0
    assert await db_session.scalar(select(func.count()).select_from(AuditLog)) == 0


async def test_a_duplicate_fingerprint_is_rejected_by_the_database(db_session: Any) -> None:
    """The unique constraint is the backstop behind the upsert.

    The upsert matches on fingerprint, so a duplicate should be unreachable
    through the normal path; the constraint exists so that a bug in that path
    fails loudly instead of silently doubling the backlog.
    """
    from sqlalchemy.exc import IntegrityError

    from backend.core.ids import compute_fingerprint

    fingerprint = compute_fingerprint(
        scanner_kind="fixture",
        rule_id="r",
        file_path="app/x.py",
        target="app/",
        title="t",
    )
    row = Finding(
        fingerprint=fingerprint,
        rule_id="r",
        title="t",
        description="",
        severity=Severity.HIGH,
        target="app/",
        file_path="app/x.py",
        cwe_ids=[],
        cve_ids=[],
        raw_payload={},
        first_seen_at=utc_now(),
        last_seen_at=utc_now(),
    )
    db_session.add(row)
    await db_session.commit()

    duplicate = Finding(
        fingerprint=fingerprint,
        rule_id="r",
        title="t",
        description="",
        severity=Severity.HIGH,
        target="app/",
        file_path="app/x.py",
        cwe_ids=[],
        cve_ids=[],
        raw_payload={},
        first_seen_at=utc_now(),
        last_seen_at=utc_now(),
    )
    db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        # The violation surfaces on flush, not commit -- SQLAlchemy emits the
        # INSERT as soon as the unit of work is flushed, and the repository
        # layer flushes eagerly.
        await db_session.flush()
    await db_session.rollback()


async def _backend() -> Any:
    from backend.mcp_server.server import build_scanner_backend

    return await build_scanner_backend()
