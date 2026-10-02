"""Drive the Tier 1 cases. Separate from `execution.py` so the case definitions
stay readable, and so a reader can see the ordering rules in one place.
"""

from __future__ import annotations

import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from backend.evidence.execution import (
    BEHAVIOUR_REGRESSED,
    CASES,
    CaseResult,
    ProbeContext,
    ProbeError,
    stop_servers,
)


@dataclass(slots=True)
class TierResult:
    """One tier's outcome, in a shape the report can render without knowing
    which tier produced it."""

    name: str
    cases: list[CaseResult]
    duration_ms: float
    skipped: str = ""
    """Non-empty when the whole tier could not run, with the reason.

    Present so all three tier results answer `ran` and `skipped_reason` the same
    way, and so the report has one code path for "this did not run" rather than
    three that could drift apart.
    """

    @property
    def ran(self) -> bool:
        return not self.skipped

    @property
    def skipped_reason(self) -> str:
        """Why the tier did not run, if it did not. Same name as the other two."""
        return self.skipped

    @property
    def measured(self) -> list[CaseResult]:
        return [c for c in self.cases if c.status != "skipped"]

    @property
    def passed(self) -> list[CaseResult]:
        return [c for c in self.measured if c.status == "ok"]

    @property
    def failed(self) -> list[CaseResult]:
        return [c for c in self.measured if c.status == "failed"]

    @property
    def blocked(self) -> int:
        return sum(1 for c in self.passed if c.exploit_after is False)

    @property
    def regressed(self) -> list[CaseResult]:
        return [c for c in self.passed if c.behaviour_after == BEHAVIOUR_REGRESSED]

    @property
    def human_steps(self) -> int:
        return sum(c.human_step_count for c in self.measured)


CaseRunner = Callable[[ProbeContext], CaseResult]


def run_tier_1(runner: CaseRunner | None = None) -> TierResult:
    """Run every Tier 1 case in its own temporary directory.

    One directory per case, not one for the tier: two cases can both use
    `reports.db` and a `marker` file, and a shared directory would let the
    first case's marker satisfy the second case's exploit.
    """
    cases = CASES if runner is None else (runner,)
    started = time.perf_counter()
    results: list[CaseResult] = []
    for case in cases:
        # `ignore_cleanup_errors` because a fixture that leaks a database handle
        # would otherwise fail the whole run on Windows, where an open file
        # cannot be deleted -- and a leaked handle is a fact about the fixture,
        # not a reason to lose the measurement.
        with tempfile.TemporaryDirectory(
            prefix="sentinel-evidence-", ignore_cleanup_errors=True
        ) as raw:
            workdir = Path(raw)
            ctx = ProbeContext(workdir=workdir, marker=workdir / "pwned-marker")
            ctx.db_path = str(workdir / "evidence.db")
            try:
                results.append(case(ctx))
            except ProbeError as exc:
                results.append(
                    CaseResult(
                        name=getattr(case, "__name__", "unknown"),
                        rewrite="(unknown)",
                        cwe_ids=(),
                        status="failed",
                        detail=f"the case raised ProbeError: {exc}",
                    )
                )
            finally:
                stop_servers(ctx.servers)
    return TierResult(
        name="execution",
        cases=results,
        duration_ms=(time.perf_counter() - started) * 1000.0,
    )
