"""The Tier 1 execution harness must be trustworthy before its numbers mean
anything.

Two jobs here, in order of importance:

1. **The harness can fail.** A green Tier 1 report is only worth reading if the
   harness would report red when it should. So these tests deliberately break
   things -- a patch that does nothing, a snippet that does not compile, an
   exploit that never lands -- and assert that the case fails.

2. **The findings it produced stay recorded.** Tier 1 found four defects. If a
   later change quietly removes one of them, the report gets a little better
   every time and the history becomes a lie. So each finding is pinned below,
   with a comment naming the defect it came from.
"""

from __future__ import annotations

import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from backend.agents.deterministic import DeterministicDeveloper, DeterministicReviewer
from backend.database.enums import AgentDecision
from backend.evidence.execution import (
    BEHAVIOUR_REGRESSED,
    CASES,
    ProbeContext,
    case_eval_to_literal_eval,
    case_http_redirect_strip_proxy_auth,
    case_math_rand_to_crypto_rand,
    case_move_secret_to_environment,
    case_server_side_template_injection,
    case_shell_true_to_argv_list,
    case_sql_fstring_to_bound_parameter,
    load_module,
    probe,
    run_mutation_control,
    stop_servers,
)
from backend.evidence.tier1 import run_tier_1


@pytest.fixture
def ctx(tmp_path: Path) -> Iterator[ProbeContext]:
    context = ProbeContext(workdir=tmp_path, marker=tmp_path / "pwned-marker")
    context.db_path = str(tmp_path / "evidence.db")
    yield context
    stop_servers(context.servers)


# --- the harness can fail -----------------------------------------------


def test_a_case_whose_exploit_never_lands_fails_rather_than_passing(
    ctx: ProbeContext,
) -> None:
    """Guard 1.

    A probe that cannot detect the vulnerability has measured nothing. If the
    exploit does not fire on the *unpatched* code, the honest outcome is a failed
    case -- not a green one that happens to have nothing to report.
    """
    from backend.evidence.execution import _run_python_case

    result = _run_python_case(
        ctx,
        name="never-vulnerable",
        rewrite="eval-to-literal-eval",
        cwe_ids=("CWE-95",),
        rule_id="python.lang.security.audit.eval-detected",
        source="""
            def run_report(expression):
                return expression
            """,
        exploit=lambda module: False,
        benign=lambda module: module.run_report("x"),
    )
    assert result.status == "failed"
    assert "exploit did not land" in result.detail


def test_a_benign_call_that_works_afterwards_means_the_module_loaded(
    ctx: ProbeContext,
) -> None:
    """Guard 2.

    If a benign call fails on the *unpatched* module the case fails, because then
    a later failure cannot be attributed to the patch.
    """
    from backend.evidence.execution import _run_python_case

    result = _run_python_case(
        ctx,
        name="already-broken",
        rewrite="eval-to-literal-eval",
        cwe_ids=("CWE-95",),
        rule_id="python.lang.security.audit.eval-detected",
        source="""
            def run_report(expression):
                return eval(expression)
            """,
        exploit=lambda module: module.run_report("1") == 1,
        benign=lambda module: (_ for _ in ()).throw(RuntimeError("already broken")),
    )
    assert result.status == "failed"
    assert "unpatched" in result.detail


def test_the_mutation_control_catches_a_harness_that_always_says_blocked(
    ctx: ProbeContext,
) -> None:
    """Guard 3, the important one.

    `run_mutation_control` re-applies the diff backwards and requires the exploit
    to come back. Handed a diff whose reverse does not apply, it must say the
    control failed rather than reporting a pass -- because a control that cannot
    fail is not a control.
    """
    source = "def f():\n    return eval('1')\n"
    patch = (
        "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n"
        "-    return eval('1')\n+    return ast.literal_eval('1')\n"
    )
    verdict = run_mutation_control(
        original_text=source,
        patched_text="something else entirely\n",
        patch=patch,
        ctx=ctx,
        name="mismatch",
        exploit=lambda module, _ctx: True,
    )
    assert verdict.startswith("control-failed")


def test_the_mutation_control_rejects_a_diff_that_is_not_a_replacement(ctx: ProbeContext) -> None:
    verdict = run_mutation_control(
        original_text="x = 1\n",
        patched_text="x = 1\n",
        patch="--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+added\n",
        ctx=ctx,
        name="addition",
        exploit=lambda module, _ctx: True,
    )
    assert "control-vacuous" in verdict


# --- the findings, pinned -----------------------------------------------


def test_the_parameterised_statement_renders_the_same_rows_under_pyformat(
    ctx: ProbeContext,
) -> None:
    """The defect Tier 1 found: `LIKE '%s%'`, silently returning the wrong rows.

    The rewrite used to emit `LIKE '%s%'`, where the `LIKE` wildcard immediately
    before the placeholder collides with it. Under `pyformat` that is a
    `ValueError`; under sqlite3, which does not treat `%` specially, it is *not*
    an error at all -- it is `LIKE '%s%'` as SQL, meaning "any prefix, a literal
    `s`, any suffix", so a search for `quarterly` returns whichever row happens
    to contain the letter `s`. A security fix that silently returns the wrong
    rows is worse than no fix, and the unit suite asserted only that the emitted
    text contained `%s`, which the broken form also did.

    This test executes the statement, which is the whole reason it exists.
    """
    result = case_sql_fstring_to_bound_parameter(ctx)
    assert result.status == "ok", result.detail
    assert result.extras["selects_the_same_rows"] is True
    assert result.extras["statement"] == "SELECT * FROM reports WHERE title LIKE %s"
    assert "%%" not in result.extras["statement"], (
        "a doubled percent in the emitted statement means a literal percent collided "
        "with the placeholder"
    )


def test_the_sql_rewrite_declines_rather_than_guessing_when_it_cannot_bind() -> None:
    """The `sql =` keyword argument is a loud TypeError, on purpose.

    The rewrite documents that writing the bind call is the human's job, and
    leaves `execute(sql = ...)` -- which does not run. That is better than
    emitting something that half-runs and returns the wrong answer, so this
    pins the loud failure rather than the quiet one.
    """
    from backend.agents.deterministic import _REWRITES

    sql = next(r for r in _REWRITES if r.name == "sql-fstring-to-bound-parameter")
    patched = sql.apply("    c.execute(f\"SELECT * FROM t WHERE a = '{v}'\")", "app/x.py")
    assert "sql = " in patched
    assert "NOT runnable" in sql.description
    assert "TypeError" in sql.description


def test_the_reviewer_no_longer_rejects_a_correct_one_line_signature_change() -> None:
    """The defect Tier 1 found in the reviewer itself.

    The parse check reconstructs the patched source from the diff's added lines
    alone. For a one-line change to a function signature that reconstruction is a
    lone `def fetch_followed_link(url, allow_redirects=False):` -- a block header
    with no body -- which cannot compile. The reviewer therefore requested
    changes on a patch that was completely correct, and would have sent a
    security fix back for a reason that had nothing to do with it.
    """
    reviewer = DeterministicReviewer()
    before = "def fetch_followed_link(url, allow_redirects=True):\n    return get(url)\n"
    after = "def fetch_followed_link(url, allow_redirects=False):\n    return get(url)\n"
    patch = (
        "### test\n\n--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n"
        f"-{before.splitlines()[0]}\n+{after.splitlines()[0]}\n"
    )
    verdict = reviewer.review(
        patch=patch,
        snippet=before.splitlines()[0],
        file_path="app/x.py",
        rule_id="python.requests.security.audit.redirect-proxies",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.APPROVE, verdict.message


def test_the_reviewer_still_rejects_genuinely_broken_syntax() -> None:
    """The counterpart, so the fix above is not a loosening.

    `def f(:` is not a valid block header. The discrimination is made by trying,
    not by pattern-matching on a colon -- see
    `deterministic._parses_with_implicit_body`.
    """
    reviewer = DeterministicReviewer()
    patch = (
        "--- a/app/x.py\n+++ b/app/x.py\n@@ -1,2 +1,2 @@\n"
        "-def f():\n-    return 1\n+def f(:\n+    return ast.literal_eval(1\n"
    )
    verdict = reviewer.review(
        patch=patch,
        snippet="def f():\n    return 1",
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert "does not parse" in verdict.message


def test_the_reviewer_does_not_parse_check_a_diff_it_cannot_reconstruct() -> None:
    """The defect Tier 3 found, in its larger form.

    The parse check rebuilds the patched source from the diff's *added lines*,
    which is only the patched file when one line became one line. Run on a
    multi-line diff, it rejected a real, merged fix because the added lines are a
    fragment -- a `try:` block with its body in the file but not in the diff, a
    nine-line replacement of three. It was the objection in 15 of the 18
    rejections measured over real upstream fixes.

    A gate that objects for reasons about the shape of the diff rather than the
    correctness of the patch is worse than no gate: it trains a reviewer to
    approve without reading.
    """
    reviewer = DeterministicReviewer()
    before = "def f(a):\n    x = compute(a)\n    y = 1\n    return x\n"
    after = (
        "def f(a):\n    try:\n        x = compute(a)\n    except ValueError:\n"
        "        x = None\n    y = 1\n    return x\n"
    )
    patch = (
        "--- a/app/x.py\n+++ b/app/x.py\n@@ -1,4 +1,7 @@\n"
        + "".join(f"-{line}\n" for line in before.splitlines())
        + "".join(f"+{line}\n" for line in after.splitlines())
    )
    verdict = reviewer.review(
        patch=patch,
        snippet=before,
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert "does not parse" not in verdict.message, (
        f"a diff that is not a like-for-like replacement must not be parse-checked: "
        f"{verdict.message}"
    )


def test_the_reviewer_still_parse_checks_a_like_for_like_replacement() -> None:
    """The counterpart: the check keeps its value where it is valid.

    Every rewrite in the table produces a one-for-one line replacement, so
    narrowing the check to that shape is what keeps catching a regex rewrite that
    produced unbalanced brackets.
    """
    reviewer = DeterministicReviewer()
    before = "    return render(x\n"
    after = "    return render(ast.literal_eval(x)\n"
    patch = f"--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-{before}\n+{after}\n"
    verdict = reviewer.review(
        patch=patch,
        snippet=before,
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert "does not parse" in verdict.message


def test_a_one_line_replacement_that_is_broken_is_still_rejected() -> None:
    """A `def` header that is genuinely malformed, at equal line counts.

    The discriminator is that appending a body does not make it compile, not the
    line counts -- so this one survives the narrowing above.
    """
    reviewer = DeterministicReviewer()
    patch = "--- a/app/x.py\n+++ b/app/x.py\n@@ -1 +1 @@\n-def f():\n+def f(:\n"
    verdict = reviewer.review(
        patch=patch,
        snippet="def f():",
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert "does not parse" in verdict.message


def test_the_shell_rewrite_is_recorded_as_platform_dependent(ctx: ProbeContext) -> None:
    """`shell=False` blocks the injection on both platforms, and breaks the
    command only on POSIX.

    Worth pinning because it is the least flattering honest result in Tier 1, and
    because the honest answer differs by `os.name` -- so the case declares its
    expectation per platform rather than asserting one shape everywhere.
    """
    result = case_shell_true_to_argv_list(ctx)
    assert result.status == "ok", result.detail
    assert result.exploit_before is True
    assert result.exploit_after is False
    assert result.extras["regression_is_platform_dependent"] is True
    import os

    if os.name == "nt":
        assert result.behaviour_after == "preserved"
    else:
        assert result.behaviour_after == BEHAVIOUR_REGRESSED


def test_the_secret_rewrite_fails_closed_rather_than_defaulting(
    ctx: ProbeContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A migrated secret must not silently fall back to a default.

    And the stronger property, which the report calls out: the rewrite emits a
    *module-level* `os.environ[...]`, so an unset variable raises during import
    and the application does not start. That is the right direction and a real
    deployment change, so it is measured rather than discovered.
    """
    monkeypatch.delenv("STRIPE_SECRET_KEY", raising=False)
    result = case_move_secret_to_environment(ctx)
    assert result.status == "ok", result.detail
    assert result.exploit_before is True, "the literal must be in the source before the fix"
    assert result.exploit_after is False
    assert "does not import" in str(result.extras["fails_closed_without_the_env_var"])


def test_the_redirect_case_uses_a_real_cross_origin_socket(ctx: ProbeContext) -> None:
    """The attack is header forwarding across an origin boundary.

    Two real servers on ephemeral ports, because a mocked HTTP client asserts
    that the mock was called. The patch stops the redirect; the target server
    never sees the `Proxy-Authorization` header that was meant for the origin.
    """
    result = case_http_redirect_strip_proxy_auth(ctx)
    assert result.status == "ok", result.detail
    assert result.exploit_before is True
    assert result.exploit_after is False
    assert result.benign_after_ok is True, "a direct, non-redirecting fetch must still work"
    assert result.extras["redirect_target_headers"], (
        "the target must have received the header before the fix, or the case is vacuous"
    )


def test_the_engine_declines_a_class_it_has_no_rule_for(ctx: ProbeContext) -> None:
    """The negative control. Guessing at a security fix is the worst behaviour
    this system could have, so it is asserted directly rather than inferred from
    the coverage of the other cases.
    """
    result = case_server_side_template_injection(ctx)
    assert result.status == "ok", result.detail
    assert result.decision == "ESCALATE"
    assert "no rewrite for this vulnerability class" in result.extras["escalation_rationale"]


def test_the_removed_math_rand_rule_stays_removed(ctx: ProbeContext) -> None:
    """Tier 2 found it emitted `secrets.randbelow` into a Go file.

    `math/rand.Int(n) int` and `crypto/rand.Int(rand.Reader, n) (*big.Int, error)`
    have incompatible signatures, so no regex can replace one with the other.
    Repairing it was not possible; removing it was.
    """
    result = case_math_rand_to_crypto_rand(ctx)
    assert result.status == "skipped"
    assert result.extras["rule_removed"] is True
    turn = DeterministicDeveloper().develop(
        snippet='    return fmt.Sprintf("ord_%d", rand.Intn(1000000))',
        file_path="services/p/reference.go",
        rule_id="go.gosec.audit.weak-random",
        cwe_ids=["CWE-338"],
        feedback=[],
        round_index=1,
    )
    assert turn.decision is AgentDecision.ESCALATE


def test_the_eval_rewrite_is_measured_through_a_real_import(ctx: ProbeContext) -> None:
    result = case_eval_to_literal_eval(ctx)
    assert result.status == "ok", result.detail
    assert result.exploit_before is True
    assert result.exploit_after is False
    assert result.benign_after_ok is True
    assert "ast.literal_eval" in str(result.extras["agent_patched_text"])


# --- the whole tier -----------------------------------------------------


def test_every_case_declares_a_mutation_control_and_passes_it(ctx: ProbeContext) -> None:
    """A case that cannot pass its own control has not been measured."""
    import tempfile

    # The escalation case has no patch, so there is nothing to revert; the two Go
    # cases are declared skips. Both are asserted separately.
    skipped = {"case_disable_tls_verification", "case_math_rand_to_crypto_rand"}
    for case in CASES:
        if case.__name__ in skipped or case.__name__ == "case_server_side_template_injection":
            continue
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as raw:
            workdir = Path(raw)
            context = ProbeContext(workdir=workdir, marker=workdir / "marker")
            context.db_path = str(workdir / "evidence.db")
            try:
                result = case(context)
            finally:
                stop_servers(context.servers)
        assert result.status == "ok", f"{result.name}: {result.detail}"
        assert result.mutation_control.startswith("control-passed"), (
            f"{result.name}: {result.mutation_control}"
        )
        assert result.exploit_before is True, f"{result.name} never proved it was vulnerable"
        assert result.exploit_after is False, f"{result.name} did not block the exploit"


def test_no_case_declares_a_regression_that_has_been_fixed(ctx: ProbeContext) -> None:
    """If a declared regression is quietly deleted the report gets better every
    time and the history becomes a lie. This pins the declarations.
    """
    import os

    result = run_tier_1(case_shell_true_to_argv_list)
    shell = next(c for c in result.cases if c.name == "shell-true-to-argv-list")
    expected = "preserved" if os.name == "nt" else BEHAVIOUR_REGRESSED
    assert shell.expected_behaviour == expected
    assert shell.status == "ok", shell.detail


def test_the_tier_runs_end_to_end_and_reports_what_it_skipped() -> None:
    result = run_tier_1()
    assert result.ran
    assert not result.failed, [c.detail for c in result.failed]
    assert result.blocked >= 5
    skipped = [c for c in result.cases if c.status == "skipped"]
    assert len(skipped) == 2
    for case in skipped:
        assert case.detail, "a skipped case must say why, in the report a reader sees"
    for case in result.measured:
        # "(not reached)" is the escalation case: there is no patch, so the
        # reviewer was never asked.
        assert case.reviewer_verdict in {"APPROVE", "REQUEST_CHANGES", "(not reached)"}


def test_the_tier_runs_every_declared_case_exactly_once() -> None:
    result = run_tier_1()
    assert result.ran
    assert len(result.cases) == len(CASES)
    assert len({c.name for c in result.cases}) == len(CASES), "two cases share a name"


# --- fixtures ------------------------------------------------------------


def test_a_module_that_will_not_import_is_a_probe_error_not_a_pass(
    ctx: ProbeContext,
) -> None:
    from backend.evidence.execution import ProbeError

    with pytest.raises(ProbeError):
        load_module("broken", "def f(:\n", ctx)


def test_probe_wraps_an_arbitrary_failure() -> None:
    from backend.evidence.execution import ProbeError

    with pytest.raises(ProbeError, match="ZeroDivisionError"):
        probe("a division", lambda: 1 / 0)


def test_load_module_does_not_cache_across_loads(ctx: ProbeContext) -> None:
    """Otherwise the 'after' measurement silently re-measures the 'before' one."""
    first = load_module("dup", "VALUE = 1\n", ctx)
    second = load_module("dup", "VALUE = 2\n", ctx)
    assert first.VALUE == 1
    assert second.VALUE == 2
    assert first is not second


def test_a_declared_human_step_that_no_longer_applies_is_an_error(
    ctx: ProbeContext,
) -> None:
    """Otherwise a case can drift from what it claims to test, silently."""
    from backend.evidence.execution import HumanStep, _run_python_case

    result = _run_python_case(
        ctx,
        name="drifted",
        rewrite="eval-to-literal-eval",
        cwe_ids=("CWE-95",),
        rule_id="python.lang.security.audit.eval-detected",
        source="""
            def run_report(expression):
                return eval(expression)
            """,
        exploit=lambda module: bool(module.run_report("__import__('os').getcwd()")) or True,
        benign=lambda module: module.run_report("1"),
        human_steps=(HumanStep(label="stale", find="NOT_IN_THE_SOURCE", replace="x"),),
    )
    assert result.status == "failed"
    assert "no longer matches" in result.detail


def test_a_case_is_isolated_from_whatever_a_previous_case_left_behind() -> None:
    """Two cases share the names `reports.db` and the marker file.

    A shared directory, or a marker not reset between measurements, would let one
    case's leftovers satisfy another case's exploit. Rather than assert on the
    implementation of the isolation, this asserts the behaviour: a case still
    passes when it runs immediately after itself, and after every other case.
    """
    first = run_tier_1()
    second = run_tier_1()
    assert not first.failed
    assert not second.failed
    assert {c.name: c.status for c in first.cases} == {c.name: c.status for c in second.cases}
    for case in second.measured:
        # The escalation case measures no exploit -- there is no patch to try.
        if case.exploit_before is None:
            continue
        assert case.exploit_before is True, f"{case.name} was contaminated by an earlier run"
