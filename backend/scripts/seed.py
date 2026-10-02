"""Seed the database with a realistic, idempotent dev dataset.

    python -m backend.scripts.seed

Idempotent: safe to run repeatedly. Users are upserted by username, and the
findings are produced by *actually running a scan* through
`ScanningService` rather than being inserted directly. That is deliberate --
seeding through the real path means the seed data satisfies the same
invariants as production data (fingerprints computed correctly, SLA deadlines
stamped, audit rows written, eligibility evaluated), and it doubles as an
end-to-end smoke test of the scan pipeline. A seed script that inserts rows
directly tests nothing and drifts from the real insert path the moment either
changes.

The dataset is chosen to make the SLA dashboard show something interesting on
first run: findings across every severity, one deliberately past its deadline,
one that is already remediated, and one escalated to a human.
"""

from __future__ import annotations

import argparse
import asyncio
from datetime import timedelta

from backend.auth.hashing import hash_password
from backend.config.settings import get_settings
from backend.core.asyncio_utils import shutdown_background_loop
from backend.core.clock import utc_now
from backend.core.logging import configure_logging, get_logger
from backend.database.enums import (
    AuditAction,
    Confidence,
    FindingStatus,
    ScannerKind,
    Severity,
    UserRole,
)
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.database.repositories.user import UserRepository
from backend.database.session import dispose_engines, session_scope
from backend.services.remediation import RemediationService
from backend.services.scanning import ScanningService

logger = get_logger(__name__)

# Demo accounts. The passwords are in the source on purpose: this is seed data
# for a local database that gets thrown away, and a reviewer running
# `docker compose up` needs to be able to log in without reading the seed
# script's docs first. Nothing here is a real credential, and
# `assert_secret_is_not_default` refuses to run this in production.
DEMO_USERS: tuple[tuple[str, str, UserRole], ...] = (
    ("dana", "ironclad-demo-analyst", UserRole.ANALYST),
    ("priya", "ironclad-demo-approver", UserRole.APPROVER),
    ("sam", "ironclad-demo-admin", UserRole.ADMIN),
)

SCAN_TARGETS = ("app/", "services/payments/")


async def seed(*, with_remediation: bool = True) -> dict[str, int]:
    """Apply the seed. Returns a count per entity, for the summary line."""
    from backend.mcp_server.server import build_scanner_backend

    settings = get_settings()
    counts = {"users": 0, "scans": 0, "new_findings": 0, "tickets": 0, "proposals": 0}

    async with session_scope() as session:
        users = UserRepository(session)
        for username, password, role in DEMO_USERS:
            existing = await users.get_by_username(username)
            if existing is None:
                await users.create(
                    username=username, hashed_password=hash_password(password), role=role
                )
                counts["users"] += 1
            else:
                logger.info("user already present username=%s", username)

        audit = AuditRepository(session)

        # 1. Run real scans. The fixture scanner is deterministic, so repeated
        #    runs produce the same fingerprints and the second run is all
        #    `refreshed` -- which is the idempotency property worth seeing.
        scanner_backend = await build_scanner_backend(settings)
        scanning = ScanningService(session, scanner_backend, audit=audit)
        findings_repo = FindingRepository(session)

        for target in SCAN_TARGETS:
            try:
                outcome = await scanning.run_scan(
                    target=target, scanners=[ScannerKind.FIXTURE], actor="system:seed"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("seed scan failed target=%s: %s", target, type(exc).__name__)
                continue
            counts["scans"] += 1
            counts["new_findings"] += outcome.new_count
            logger.info(
                "seeded scan target=%s new=%d refreshed=%d",
                target,
                outcome.new_count,
                len(outcome.refreshed),
            )

        # 2. Make the SLA dashboard interesting: push one critical finding past
        #    its deadline, and close another out as remediated. Without this the
        #    dashboard opens all-green, which demonstrates nothing.
        open_findings = await findings_repo.list_open_with_sla(limit=200)
        if open_findings:
            breached = next(
                (f for f in open_findings if f.severity is Severity.CRITICAL),
                open_findings[0],
            )
            breached.sla_due_at = utc_now() - timedelta(hours=9)
            logger.info(
                "seeded one breached finding id=%s severity=%s",
                breached.id,
                breached.severity.value,
            )

            closeable = next(
                (
                    f
                    for f in open_findings
                    if f.severity is Severity.MEDIUM and f.id != breached.id and f.snippet
                ),
                None,
            )
            if closeable is not None:
                await findings_repo.update_status(closeable.id, FindingStatus.REMEDIATED)
                await audit.append(
                    actor="user:dana",
                    action=AuditAction.FINDING_STATUS_CHANGED,
                    entity_type="finding",
                    entity_id=closeable.id,
                    summary="seed: marked remediated after a manual fix",
                    payload={"to": FindingStatus.REMEDIATED.value, "note": "seed data"},
                )
                logger.info("seeded one remediated finding id=%s", closeable.id)

        # 3. Leave a couple of low-confidence findings that policy refuses, so
        #    the "policy_refused" path is visible in a fresh database rather
        #    than only in a test.
        ineligible = [
            f for f in open_findings if f.severity is Severity.LOW or f.confidence is Confidence.LOW
        ]
        for finding in ineligible[:2]:
            finding.auto_remediation_eligible = False
        if ineligible:
            logger.info(
                "seeded %d finding(s) that policy will refuse to auto-remediate",
                len(ineligible[:2]),
            )

        # 4. Run one real remediation end to end, so a fresh database already
        #    contains a proposal, a full agent transcript, and a DRAFT pull
        #    request waiting for a human. That is the artefact a reviewer wants
        #    to see first, and generating it here proves the whole path works.
        if with_remediation:
            remediations = RemediationRepository(session)
            already = await remediations.remediation_stats()
            if already["total_proposals"] == 0:
                candidate = next(
                    (
                        f
                        for f in open_findings
                        if f.status is FindingStatus.OPEN
                        and f.snippet
                        and f.file_path
                        and f.severity is not Severity.LOW
                    ),
                    None,
                )
                if candidate is not None:
                    try:
                        remediation = await RemediationService(session, audit=audit).remediate(
                            candidate.id, actor="system:seed"
                        )
                        counts["proposals"] += 1
                        logger.info(
                            "seeded one remediation outcome=%s draft_pull_request=%s",
                            remediation.result.outcome,
                            remediation.pull_request_id,
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("seed remediation skipped: %s", type(exc).__name__)

            counts["tickets"] = len(await TicketRepository(session).list_tickets(limit=500))

    return counts


async def main_async(*, with_remediation: bool) -> int:
    try:
        counts = await seed(with_remediation=with_remediation)
    finally:
        await dispose_engines()
        shutdown_background_loop()

    print()
    print("Seed complete:")
    for key, value in counts.items():
        print(f"  {key:15} {value}")
    print()
    print("Demo accounts (development only):")
    for username, password, role in DEMO_USERS:
        print(f"  {username:8} {password:26} {role.value}")
    print()
    print("Reminder: the remediation pull request this created is a DRAFT with")
    print("auto_merge_blocked=true. Approve it as `priya` via")
    print("  POST /pull-requests/{id}/approve")
    print("and then merge it yourself in the git host. This system cannot merge.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed SentinelMCP development data.")
    parser.add_argument(
        "--no-remediation",
        action="store_true",
        help="Skip the end-to-end agent remediation (faster, and leaves no draft PR).",
    )
    parser.add_argument("--log-level", default=None, help="Override SENTINEL_LOG_LEVEL.")
    args = parser.parse_args(argv)

    configure_logging(args.log_level or get_settings().log_level)
    return asyncio.run(main_async(with_remediation=not args.no_remediation))


if __name__ == "__main__":
    raise SystemExit(main())
