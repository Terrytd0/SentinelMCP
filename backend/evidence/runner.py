"""Run the tiers and produce the report. Also the CLI entry point's logic.

Kept out of `scripts/evidence_report.py` so the orchestration is importable and
testable without spawning a process, which is the same split
`scripts/verify_mcp_sdk.py` uses.

Each tier is optional and each one skips itself rather than failing the run: a
machine without Semgrep or without a network should still get tiers it *can*
produce, and a report that refuses to render because one dependency is missing
is a report nobody reads. Which tiers ran is stated at the top.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from backend.core.logging import get_logger
from backend.evidence.report import EvidenceReport, default_environment
from backend.evidence.tier1 import run_tier_1
from backend.evidence.tier2 import run_tier_2
from backend.evidence.tier3 import run_tier_3
from backend.scanners.semgrep import SemgrepScanner

logger = get_logger(__name__)

T = TypeVar("T")

DEFAULT_TIER_LIMIT = 6
"""Advisories fetched by default.

    All nineteen take about 50 seconds with a warm git cache and several minutes
    cold, which is fine for a deliberate run and wrong for a commit hook. The
    report says how many it looked at, and `--all` looks at all of them.
    """


def build_report(
    *,
    tiers: tuple[str, ...] = ("1", "2", "3"),
    corpus_limit: int | None = DEFAULT_TIER_LIMIT,
    semgrep_binary: str | None = None,
    target: Path | None = None,
) -> EvidenceReport:
    """Run the requested tiers. A tier that raises is recorded as not run."""
    environment = default_environment()
    report = EvidenceReport(environment=environment)

    if "1" in tiers:
        report.tier1 = _guard(run_tier_1, "tier 1")
    if "2" in tiers:
        binary = semgrep_binary or _default_semgrep_binary()
        environment["semgrep"] = binary or "not found"
        if target is not None:
            report.tier2 = _guard(lambda: run_tier_2(target=target), "tier 2")
        else:
            report.tier2 = _guard(run_tier_2, "tier 2")
    if "3" in tiers:
        report.tier3 = _guard(lambda: run_tier_3(limit=corpus_limit), "tier 3")
        environment["corpus"] = (
            f"{len(report.tier3.manifest)} advisories, {len(report.tier3.measured)} fetched"
            if report.tier3 and report.tier3.ran
            else "skipped"
        )
    return report


def _guard[T](run: Callable[[], T], name: str) -> T | None:
    """Run a tier, recording a raised exception as "did not run".

    A report is better than a traceback, and a missing tier is better than a
    number presented as a measurement it did not produce.
    """
    try:
        return run()
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s raised %s: %s", name, type(exc).__name__, exc)
        return None


def _default_semgrep_binary() -> str:
    scanner = SemgrepScanner()
    resolved = scanner.resolved_binary
    if resolved:
        return resolved
    candidate = Path(sys.executable).parent / (
        "semgrep.exe" if sys.platform == "win32" else "semgrep"
    )
    return str(candidate) if candidate.is_file() else ""


def exit_code(report: EvidenceReport) -> int:
    """0 when nothing the tiers were asked to measure failed.

    Declines, regressions and human steps are *results*, not failures: the
    engine declining to guess is the behaviour this project wants, and counting
    it as a failure would train a reader to ignore the exit code.

    A vacuous tier 2 does fail. If the pinned rule set cannot be shown to work,
    the run did not measure what it claims to have measured, and saying so by
    exiting non-zero is the only way to stop it being quoted.
    """
    if report.tier1 and report.tier1.ran and report.tier1.failed:
        return 1
    if report.tier2 and report.tier2.runs and report.tier2.vacuous:
        return 1
    if report.tier3 and report.tier3.runs:
        if any(o.status == "fetch-failed" for o in report.tier3.outcomes):
            return 1
    return 0
