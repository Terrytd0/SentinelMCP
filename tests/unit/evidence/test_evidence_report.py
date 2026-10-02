"""The report must not be able to flatter itself.

A report that renders green because a measurement did not happen is worse than
no report, so these tests attack the three ways that can go wrong: a tier that
did not run being read as a tier that passed, a declared gap disappearing, and
two renderings of the same run disagreeing.
"""

from __future__ import annotations

import pytest

from backend.evidence.execution import CaseResult
from backend.evidence.report import KNOWN_GAPS, EvidenceReport
from backend.evidence.runner import build_report, exit_code
from backend.evidence.tier1 import TierResult as Tier1Result
from backend.evidence.tier2 import PINNED_CONFIGS, RuleOutcome, Tier2Result
from backend.evidence.tier3 import AdvisoryOutcome, Tier3Result


def _case(name: str = "case", status: str = "ok", **kwargs: object) -> CaseResult:
    defaults: dict[str, object] = {
        "name": name,
        "rewrite": "eval-to-literal-eval",
        "cwe_ids": ("CWE-95",),
        "status": status,
        "exploit_before": True,
        "exploit_after": False,
        "behaviour_after": "preserved",
        "expected_behaviour": "preserved",
        "reviewer_verdict": "APPROVE",
    }
    defaults.update(kwargs)
    return CaseResult(**defaults)  # type: ignore[arg-type]


def _tier1(*cases: CaseResult, ran: bool = True) -> Tier1Result:
    return Tier1Result(
        name="execution",
        cases=list(cases),
        duration_ms=1.0,
        skipped="" if ran else "no interpreter",
    )


# --- a tier that did not run is never read as a tier that passed ----------


def test_a_tier_that_did_not_run_is_said_so() -> None:
    report = EvidenceReport(tier1=_tier1(ran=False))
    assert "SKIPPED" in report.to_text()
    assert "Skipped" in report.to_markdown()
    assert report.tiers_ran == 0


def test_a_report_with_no_tiers_at_all_still_renders() -> None:
    """A machine with no semgrep and no network should still get a report."""
    for text in (EvidenceReport().to_text(), EvidenceReport().to_markdown()):
        assert "KNOWN BLIND SPOTS" in text or "Known blind spots" in text


def test_a_failed_case_is_surfaced_before_anything_else() -> None:
    report = EvidenceReport(
        tier1=_tier1(_case("broken", status="failed", detail="the exploit still lands"))
    )
    text = report.to_text()
    assert "READ THIS FIRST" in text
    assert text.index("READ THIS FIRST") < text.index("TIER 1")
    assert "the exploit still lands" in text
    assert exit_code(report) == 1


def test_a_vacuous_tier_2_fails_the_run() -> None:
    """If the pinned rule set cannot be shown to work, nothing it said counts.

    A `--config` URL that is not a rule exits 0 and reports nothing, which is
    indistinguishable from a clean scan. Exiting non-zero is the only way to
    stop the run being quoted.
    """
    report = EvidenceReport(tier2=Tier2Result(runs=True, vacuous=True))
    assert "VACUOUS" in report.to_text()
    assert "Vacuous" in report.to_markdown()
    assert exit_code(report) == 1


def test_an_unfetchable_advisory_fails_the_run_and_is_not_a_pass() -> None:
    report = EvidenceReport(
        tier3=Tier3Result(
            runs=True,
            outcomes=[
                AdvisoryOutcome(
                    advisory="GHSA-x",
                    package="p",
                    repo="o/r",
                    cwe_ids=(),
                    summary="",
                    status="fetch-failed",
                    detail="couldn't find remote ref",
                )
            ],
        )
    )
    assert "could not be fetched" in report.to_text()
    assert exit_code(report) == 1


def test_declining_and_regressing_are_not_failures() -> None:
    """The engine declining to guess is the behaviour this project wants.

    Counting it as a failure would train a reader to ignore the exit code.
    """
    report = EvidenceReport(
        tier1=_tier1(
            _case("declined", decision="ESCALATE", reviewer_verdict="(not reached)"),
            _case("regressed", behaviour_after="regressed", expected_behaviour="regressed"),
        )
    )
    assert exit_code(report) == 0
    assert report.headline_failures == []


# --- the gaps are unconditional -------------------------------------------


def test_the_known_gaps_are_printed_even_on_a_perfect_run() -> None:
    text = EvidenceReport(
        tier1=_tier1(_case()), tier2=Tier2Result(runs=True), tier3=Tier3Result(runs=True)
    ).to_text()
    for gap in KNOWN_GAPS:
        first_sentence = gap.partition(". ")[0]
        assert first_sentence in text, first_sentence


def test_the_report_leads_with_what_it_could_not_check() -> None:
    """No single pass rate, and the denominators are named as biased."""
    markdown = EvidenceReport(tier1=_tier1(_case())).to_markdown()
    assert "no single pass rate" in markdown
    assert "flattering by construction" in markdown
    assert "rewrites in the rule table" in markdown


def test_the_tier_counts_come_from_the_run_not_from_prose() -> None:
    """A number written into a template goes stale the moment the engine changes."""
    result = _tier1(
        _case("a"),
        _case("b", status="failed", detail="nope"),
        _case("c", status="skipped", detail="no toolchain"),
    )
    report = EvidenceReport(tier1=result)
    text = report.to_text()
    assert "3 of 3 cases measurable" not in text  # 1 of the 3 is a declared skip
    assert "1 failed" in text
    assert "no toolchain" in text


# --- the two renderings agree --------------------------------------------


def test_the_text_and_markdown_report_the_same_outcome_counts() -> None:
    report = EvidenceReport(
        tier1=_tier1(
            _case("ok-one"),
            _case("regressed-one", behaviour_after="regressed", expected_behaviour="regresses"),
            _case("skipped-one", status="skipped", detail="no Go toolchain"),
        ),
        tier2=Tier2Result(
            runs=True,
            semgrep_version="1.178.0",
            hits_before=[],
            hits_after=[],
            outcomes=[
                RuleOutcome(
                    check_id="rule.a",
                    path="app.py",
                    line_before=1,
                    cwe="CWE-95: x",
                    stopped_firing=True,
                    rewrite="eval-to-literal-eval",
                    attempted=True,
                )
            ],
        ),
        tier3=Tier3Result(runs=True),
    )
    text, markdown = report.to_text(), report.to_markdown()
    for token in ("regressed-one", "skipped-one", "rule.a", "1.178.0", "no Go toolchain"):
        assert token in text, token
        assert token in markdown, token


def test_the_declared_configs_are_reported_so_a_run_can_be_reproduced() -> None:
    text = EvidenceReport(tier2=Tier2Result(runs=True)).to_text()
    for config in PINNED_CONFIGS:
        assert config in text


def test_an_outcome_that_stopped_firing_without_a_patch_is_its_own_category() -> None:
    """Not `fixed`. Padding the score with rules that were never applicable to
    our patch would make the number meaningless."""
    outcome = RuleOutcome(
        check_id="r", path="a.py", line_before=1, cwe="CWE-1", stopped_firing=True
    )
    assert outcome.credit == "stopped-without-a-patch"
    assert outcome.attempted is False


def test_a_declined_rewrite_is_not_scored_as_a_failed_fix() -> None:
    outcome = RuleOutcome(
        check_id="r",
        path="a.go",
        line_before=1,
        cwe="CWE-798",
        stopped_firing=False,
        escalated=True,
    )
    assert outcome.credit == "declined-correctly"


# --- the runner ----------------------------------------------------------


def test_the_runner_records_a_tier_that_raises_rather_than_crashing() -> None:
    """A report is better than a traceback, and a missing tier is better than a
    wrong number presented as a measurement."""
    report = build_report(tiers=("1",))
    assert report.tier1 is not None
    assert report.tier2 is None
    assert report.tiers_ran == 1


@pytest.mark.parametrize("tiers", [(), ("1",), ("2",), ("1", "2")])
def test_the_runner_can_be_asked_for_a_subset_of_tiers(tiers: tuple[str, ...]) -> None:
    report = build_report(tiers=tiers)
    assert (report.tier1 is not None) is ("1" in tiers)
    assert (report.tier2 is not None) is ("2" in tiers)
    assert report.tier3 is None, "tier 3 must not run unless it was asked for"
