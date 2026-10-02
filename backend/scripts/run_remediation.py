"""Draft a remediation for a finding, from the command line.

    python -m backend.scripts.run_remediation --finding-id <uuid>
    python -m backend.scripts.run_remediation --severity critical --limit 5
    python -m backend.scripts.run_remediation --list-candidates

The batch mode is the point of this script existing. `POST /pull-requests/...`
remediates one finding per request because that is the right shape for an API;
but the actual job a security team wants is "here are tonight's five criticals,
go", and driving that by hand through curl is exactly the kind of busywork the
agent is supposed to be removing.

Three properties this script has to preserve, because it is the one path that
runs unattended with no HTTP request in front of it:

1. **It cannot merge anything.** Every draft it produces has
   `auto_merge_blocked=true`; approving and merging stay human actions in the
   git host. There is no `--auto-merge` flag, and adding one would be the
   single most damaging change anyone could make to this repository.

2. **A refusal is a normal outcome, not a crash.** Policy refuses plenty of
   findings on purpose -- wrong path, low confidence, attempt budget spent. The
   refusal is recorded, counted, and reported; a batch run exits 0 having done
   what it legitimately could.

3. **One bad finding does not end the batch.** Each target is attempted inside
   its own error boundary, and the exit code reports how many targets the
   policy refused versus how many genuinely failed, so a partially-completed
   nightly run is distinguishable from a clean one.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import uuid
from dataclasses import dataclass, field

from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents.autogen_loop import LoopBudgetExhausted, build_engine
from backend.config.settings import get_settings
from backend.core.asyncio_utils import shutdown_background_loop
from backend.core.logging import configure_logging, get_logger
from backend.database.enums import Severity
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository
from backend.database.session import dispose_engines, session_scope
from backend.services.remediation import (
    RemediationOutcome,
    RemediationRefusedError,
    RemediationService,
)

logger = get_logger(__name__)


@dataclass
class BatchReport:
    """What a batch run did, for the summary table and the exit code."""

    attempted: int = 0
    approved: int = 0
    rejected: int = 0
    escalated: int = 0
    refused: int = 0
    failed: int = 0
    draft_pull_requests: list[int] = field(default_factory=list)
    refusals: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "attempted": self.attempted,
            "approved": self.approved,
            "rejected": self.rejected,
            "escalated": self.escalated,
            "refused_by_policy": self.refused,
            "failed": self.failed,
            "draft_pull_requests": self.draft_pull_requests,
            "refusal_breakdown": self.refusals,
        }


async def _resolve_targets(
    finding_id: uuid.UUID | None,
    severity: Severity | None,
    limit: int,
) -> list[uuid.UUID]:
    """Decide which findings to attempt.

    An explicit id is taken at face value -- including one that turns out to be
    ineligible, because silently redirecting an operator's explicit request to a
    different finding is worse than a refusal. Batch mode goes through
    `list_open_with_sla`, so it only ever considers findings the queue still
    considers actionable.
    """
    if finding_id is not None:
        return [finding_id]

    severities = [severity] if severity is not None else None
    async with session_scope() as session:
        candidates = await FindingRepository(session).list_open_with_sla(
            severities=severities, limit=limit
        )
    return [finding.id for finding in candidates]


async def _list_candidates(severity: Severity | None, limit: int) -> int:
    """Print what a batch run *would* attempt, then exit without changing anything.

    A dry run is the honest answer to "why did it skip that one?", and it is the
    only safe way to preview a `--severity critical --limit 20` against a live
    database.
    """
    severities = [severity] if severity is not None else None
    async with session_scope() as session:
        findings = await FindingRepository(session).list_open_with_sla(
            severities=severities, limit=limit
        )

    if not findings:
        print("no actionable findings match that filter")
        return 0

    print(f"{len(findings)} actionable finding(s):\n")
    for finding in findings:
        due = finding.sla_due_at.isoformat() if finding.sla_due_at else "no deadline"
        print(f"  {finding.id}  {finding.severity.value:8} {finding.status.value:14} {due}")
        print(f"      {finding.title}")
        print(f"      {finding.file_path or '<no file>'}:{finding.start_line or 0}")
    return 0


async def _remediate_one(
    target: uuid.UUID, report: BatchReport, *, actor: str, open_ticket: bool
) -> None:
    """Attempt one finding, folding the outcome into `report`.

    Every failure mode is caught here. An uncaught exception would abandon the
    rest of the batch and, worse, leave the report claiming less happened than
    did.
    """
    report.attempted += 1

    async with session_scope() as session:
        service = RemediationService(session, engine=build_engine(), audit=AuditRepository(session))
        try:
            outcome = await service.remediate(target, actor=actor, open_ticket=open_ticket)
        except RemediationRefusedError as exc:
            report.refused += 1
            key = str(exc.refusal)
            report.refusals[key] = report.refusals.get(key, 0) + 1
            print(f"  REFUSED  {target}  {exc.refusal}: {exc.reason}")
            return
        except LoopBudgetExhausted as exc:
            # Not a crash either -- it is the cost bound doing its job. Counted
            # as an escalation because from the queue's perspective the finding
            # now needs a human, which is where an exhausted budget sends it.
            report.escalated += 1
            print(f"  BUDGET   {target}  {exc}")
            return
        except LookupError as exc:
            report.failed += 1
            print(f"  MISSING  {target}  {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001 - one bad finding must not end the batch
            report.failed += 1
            print(f"  FAILED   {target}  {type(exc).__name__}: {exc}", file=sys.stderr)
            logger.exception("remediation failed finding_id=%s", target)
            return

        result = outcome.result
        if result.approved:
            report.approved += 1
            number = await _pull_request_number(session, outcome)
            if number is None:
                # Approved but no draft PR. The service creates one before
                # returning, so this is unreachable in practice -- but printing
                # "#None" in a nightly log is worse than saying so plainly.
                print(f"  APPROVED {target}  no draft pull request was recorded")
            else:
                report.draft_pull_requests.append(number)
                print(f"  APPROVED {target}  draft PR #{number} awaiting human approval")
        elif result.outcome == "rejected":
            report.rejected += 1
            print(f"  REJECTED {target}  {result.summary}")
        else:
            report.escalated += 1
            print(f"  ESCALATED {target}  {result.escalated_reason}")


async def _pull_request_number(session: AsyncSession, outcome: RemediationOutcome) -> int | None:
    """The PR number the service just opened, for display."""
    if outcome.pull_request_id is None:
        return None
    pull_request = await RemediationRepository(session).get_pull_request(outcome.pull_request_id)
    return pull_request.number if pull_request else None


async def run_batch(targets: list[uuid.UUID], *, actor: str, open_ticket: bool) -> BatchReport:
    """Run the batch, one isolated session per target.

    A session per target rather than one for the batch: each target's commit or
    rollback is then its own transaction, so a failure cannot roll back the
    proposals that already succeeded.
    """
    report = BatchReport()
    print(f"attempting {len(targets)} finding(s) as {actor}\n")
    for index, target in enumerate(targets, start=1):
        print(f"[{index}/{len(targets)}] {target}")
        await _remediate_one(target, report, actor=actor, open_ticket=open_ticket)
    return report


def _print_report(report: BatchReport) -> None:
    summary = report.as_dict()
    print("\n--- summary ---")
    for key in ("attempted", "approved", "rejected", "escalated", "refused_by_policy", "failed"):
        print(f"  {key:20} {summary[key]}")
    if report.draft_pull_requests:
        numbers = ", ".join(f"#{n}" for n in report.draft_pull_requests)
        print(f"  {'draft PRs':20} {numbers}")
    if report.refusals:
        print("\n  policy refusals:")
        for reason, count in sorted(report.refusals.items(), key=lambda kv: -kv[1]):
            print(f"    {reason:34} {count}")
    if report.draft_pull_requests:
        print(
            "\nEach draft PR is blocked from merge by policy. Approve one with\n"
            "  POST /pull-requests/{id}/approve  (APPROVER or ADMIN role),\n"
            "then merge it yourself in the git host. This tool cannot merge."
        )


async def main_async(args: argparse.Namespace) -> int:
    try:
        if args.list_candidates:
            return await _list_candidates(args.severity, args.limit)

        targets = await _resolve_targets(args.finding_id, args.severity, args.limit)
        if not targets:
            print(
                "nothing to do: no actionable findings match "
                f"--severity {args.severity.value if args.severity else 'any'}. "
                "Run a scan first (`python -m backend.scripts.seed` seeds one)."
            )
            return 0

        report = await run_batch(targets, actor=args.actor, open_ticket=not args.no_ticket)
        _print_report(report)

        if args.json:
            print(json.dumps(report.as_dict(), indent=2))

        # A clean run is "nothing actually broke". Refusals and escalations are
        # legitimate outcomes, so they do not fail the batch; a nonzero exit is
        # reserved for targets that errored.
        return 1 if report.failed else 0
    finally:
        await dispose_engines()
        shutdown_background_loop()


def build_parser() -> argparse.ArgumentParser:
    """The argument parser, built separately so tests can inspect its options.

    There is deliberately no `--auto-merge` flag, and no flag that could
    plausibly become one. The absence is asserted by
    `tests/unit/scripts/test_run_remediation_cli.py`, so adding such a flag is a
    test failure rather than something a reviewer has to think to ask about.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Draft human-approved remediation pull requests for security findings. "
            "This tool proposes and reviews; it can never merge."
        )
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--finding-id", type=uuid.UUID, help="Remediate exactly this finding.")
    target.add_argument(
        "--list-candidates",
        action="store_true",
        help="Print what a batch run would attempt and exit without changing anything.",
    )
    parser.add_argument(
        "--severity",
        type=Severity,
        choices=list(Severity),
        help="In batch mode, only findings at this severity or worse.",
    )
    parser.add_argument(
        "--limit", type=int, default=10, help="Maximum findings in a batch (default: 10)."
    )
    parser.add_argument(
        "--actor",
        default="cli:run_remediation",
        help="Who to record in the audit log (default: cli:run_remediation).",
    )
    parser.add_argument(
        "--no-ticket", action="store_true", help="Do not open a tracking ticket per finding."
    )
    parser.add_argument(
        "--json", action="store_true", help="Also print the summary as JSON for scripting."
    )
    parser.add_argument("--log-level", default=None, help="Override SENTINEL_LOG_LEVEL.")
    return parser


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    return build_parser().parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    configure_logging(args.log_level or get_settings().log_level)
    return asyncio.run(main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())
