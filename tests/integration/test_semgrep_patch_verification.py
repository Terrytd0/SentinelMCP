"""Tier 2 against a real Semgrep binary and the real registry.

Integration, and it skips itself when Semgrep or the network is absent -- Rule 1
in `CLAUDE.md`: a bare `pytest` with nothing running must pass, and must never
fail because a service is down. A tier that cannot run has to say so, and the
report is where that is recorded; the test's job is only to assert the behaviour
when the dependency *is* there.

The rule packs are fetched from semgrep.dev and cached by Semgrep itself, so
only the first run needs the network.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from backend.evidence.tier2 import (
    PINNED_CONFIGS,
    SAMPLE_TARGET,
    _binary_beside_the_interpreter,
    _escalated_locations,
    run_tier_2,
)
from backend.scanners.semgrep import SemgrepScanner


def _semgrep_binary() -> str | None:
    scanner = SemgrepScanner()
    if scanner.resolved_binary:
        return scanner.resolved_binary
    return _binary_beside_the_interpreter()


def _registry_is_reachable(binary: str) -> bool:
    from backend.evidence.tier2 import _run_semgrep

    output = _run_semgrep(binary, SAMPLE_TARGET, ("p/security-audit",), 300)
    return bool(output.hits)


pytestmark = pytest.mark.integration


def test_the_tier_runs_and_is_not_vacuous() -> None:
    """The guard that makes this tier mean anything.

    A `--config` URL that is not a rule exits 0 and reports nothing, which is
    indistinguishable from a clean scan. Four of eleven rule ids guessed while
    building this tier behaved exactly that way. So the tier refuses to report
    anything unless at least one pinned rule fired on the *unpatched* sample.
    """
    binary = _semgrep_binary()
    if binary is None:
        pytest.skip("semgrep is not installed; install it or set SENTINEL_SEMGREP_BINARY")
    if not _registry_is_reachable(binary):
        pytest.skip("the semgrep registry is not reachable, so no rule pack can be resolved")

    result = run_tier_2()
    assert result.runs
    assert not result.vacuous, (
        "no pinned rule fired on the unpatched sample, so the rule set cannot be shown "
        "to work and nothing it reported about the patched tree counts"
    )
    assert result.semgrep_version != "unknown"
    assert result.fetch_errors == []


def test_every_pinned_config_is_reported_so_the_run_can_be_reproduced() -> None:
    binary = _semgrep_binary()
    if binary is None:
        pytest.skip("semgrep is not installed")
    result = run_tier_2()
    assert result.configs == PINNED_CONFIGS


def test_the_patched_tree_really_is_a_separate_copy() -> None:
    """The sample is a scan target and is never modified in place.

    Patching `data/samples/` directly would make a second run measure the first
    run's output, and would quietly destroy the fixture the SAST tests rely on.
    """
    binary = _semgrep_binary()
    if binary is None:
        pytest.skip("semgrep is not installed")
    before = SAMPLE_TARGET.joinpath("app.py").read_text(encoding="utf-8")
    run_tier_2()
    after = SAMPLE_TARGET.joinpath("app.py").read_text(encoding="utf-8")
    assert before == after, "the evidence tier modified the sample in place"
    assert "shell=True" in after
    assert "ast.literal_eval(expression)" not in after


def test_a_rule_that_stopped_firing_is_attributed_to_a_rewrite() -> None:
    """A stopped rule with no rewrite behind it is a coincidence, not a fix.

    `no-rewrite-available` is its own category for exactly this reason: padding
    the fixed count with rules that were never applicable to anything we
    produced would make the number meaningless.
    """
    binary = _semgrep_binary()
    if binary is None:
        pytest.skip("semgrep is not installed")
    if not _registry_is_reachable(binary):
        pytest.skip("the semgrep registry is not reachable")
    result = run_tier_2()
    for outcome in result.outcomes:
        if outcome.credit == "fixed":
            assert outcome.rewrite, f"{outcome.check_id} stopped firing with no rewrite behind it"
            assert outcome.attempted
        if outcome.credit == "declined-correctly":
            assert outcome.escalated


def test_the_go_secret_finding_is_declined_rather_than_patched() -> None:
    """The defect Tier 2 found: a Python `os.environ[...]` in a Go file.

    `move-secret-to-environment` matches Go's `const Key = "..."` and used to
    answer with Python, which does not compile. The rule table is now
    language-gated, so the Go finding escalates -- and the rule must keep firing
    on the Go file, because that is the *correct* outcome.
    """
    binary = _semgrep_binary()
    if binary is None:
        pytest.skip("semgrep is not installed")
    if not _registry_is_reachable(binary):
        pytest.skip("the semgrep registry is not reachable")
    result = run_tier_2()
    escalated = {f"{path}:{line}" for path, line in _escalated_locations(result.unpatched_lines)}
    assert any("gateway.go:25" in item for item in escalated), result.unpatched_lines
    assert any("not valid in this language" in note for note in result.unpatched_lines)

    go_secret = [o for o in result.outcomes if o.path == "gateway.go" and "CWE-798" in o.cwe]
    assert go_secret, "p/secrets stopped reporting the Go hardcoded key, which is unexpected"
    assert all(o.credit == "declined-correctly" for o in go_secret), (
        "declining a Go secret is correct; the rule still firing is the right outcome"
    )


def test_the_harness_does_not_depend_on_semgrep_being_on_path() -> None:
    """`SemgrepScanner` resolves against PATH, which is right for a deployed
    process and wrong for a developer running `.venv\\Scripts\\python -m pytest`
    in a shell where the venv was never activated -- which is the documented way
    to run this project's suite on Windows. Hence a local fallback, used only
    here and never in the production scanner.
    """
    if shutil.which("semgrep") is None:
        candidate = _binary_beside_the_interpreter()
        assert candidate is not None and Path(candidate).is_file()
    else:
        assert (
            _binary_beside_the_interpreter() is None
            or Path(
                _binary_beside_the_interpreter()  # type: ignore[arg-type]
            ).is_file()
        )
