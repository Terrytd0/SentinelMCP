"""The deterministic developer/reviewer pair.

These tests pin down *what patch the engine produces*, not just that it produces
one. The engine is deterministic by construction, which is the property that
makes it usable as the control in the AutoGen comparison -- and a control whose
output can drift is not a control. So the exact diffs below are asserted, and a
rewrite change that alters them has to change them deliberately.
"""

from __future__ import annotations

import pytest

from backend.agents.deterministic import (
    _REWRITES,
    UNKNOWN_LANGUAGE,
    AgentTurn,
    DeterministicDeveloper,
    DeterministicReviewer,
    Rewrite,
    _comment_marker,
    language_of,
)
from backend.database.enums import AgentDecision

PY_EVAL_SNIPPET = '    return render(eval(request.args["expr"]))'
GO_TLS_SNIPPET = (
    "transport := &http.Transport{\n    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n}"
)
PY_SHELL_SNIPPET = '    subprocess.run(f"soffice {path}", shell=True, check=True)'
GO_SECRET_SNIPPET = 'const StripeSecretKey = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"'
PY_SECRET_SNIPPET = 'STRIPE_SECRET_KEY = "REDACTED_PLACEHOLDER_NOT_A_REAL_KEY"'
PY_SQL_SNIPPET = "    sql = f\"SELECT * FROM reports WHERE title LIKE '%{term}%'\""


@pytest.fixture
def developer() -> DeterministicDeveloper:
    return DeterministicDeveloper()


@pytest.fixture
def reviewer() -> DeterministicReviewer:
    return DeterministicReviewer()


def _develop(
    developer: DeterministicDeveloper,
    snippet: str,
    path: str,
    rule: str,
    cwes: list[str],
) -> AgentTurn:
    return developer.develop(
        snippet=snippet, file_path=path, rule_id=rule, cwe_ids=cwes, feedback=[], round_index=1
    )


# --- Comment markers ----------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("app/main.py", "#"),
        ("app/main.go", "//"),
        ("web/app.ts", "//"),
        ("infra/network.conf", "#"),
        ("Makefile", "#"),
    ],
)
def test_comment_marker_follows_the_language(path: str, expected: str) -> None:
    assert _comment_marker(path) == expected


def test_no_rewrite_injects_a_comment_into_the_source() -> None:
    """A comment inside the patch is a correctness hazard; the note goes in the
    diff preamble instead.

    `render(eval(x))` -> `render(# note` + newline + `ast.literal_eval(x))` was
    a real bug this guards against.
    """
    for rule in _REWRITES:
        applied = rule.apply(PY_EVAL_SNIPPET, "app/x.py")
        assert "\n#" not in applied, f"{rule.name} injects a comment into the source"
        assert "\n//" not in applied, f"{rule.name} injects a comment into the source"


# --- The developer ------------------------------------------------------


def test_eval_is_replaced_with_literal_eval(developer: DeterministicDeveloper) -> None:
    turn = _develop(
        developer, PY_EVAL_SNIPPET, "app/handlers/report.py", "python.eval-detected", ["CWE-95"]
    )
    assert turn.decision is AgentDecision.PROPOSE
    assert turn.patch is not None
    assert 'return render(eval(request.args["expr"]))' in _removed(turn.patch)
    assert 'return render(ast.literal_eval(request.args["expr"]))' in _added(turn.patch)


def test_the_diff_note_lives_in_the_preamble_not_the_code(
    developer: DeterministicDeveloper,
) -> None:
    turn = _develop(
        developer, PY_EVAL_SNIPPET, "app/handlers/report.py", "python.eval-detected", ["CWE-95"]
    )
    assert turn.patch is not None
    assert "### fix: use ast.literal_eval()" in turn.patch
    preamble, _, diff = turn.patch.partition("--- a/")
    assert "### fix:" in preamble
    assert "# use ast.literal_eval" not in diff, "the note leaked into the diff body"


def test_a_go_finding_never_gets_a_python_comment(developer: DeterministicDeveloper) -> None:
    turn = _develop(
        developer,
        GO_TLS_SNIPPET,
        "services/payments/gateway.go",
        "go.crypto.security.audit.tls-verification-disabled",
        ["CWE-295"],
    )
    assert turn.decision is AgentDecision.PROPOSE
    assert turn.patch is not None
    assert "InsecureSkipVerify: false" in _added(turn.patch)
    assert "# agent fix" not in turn.patch, "a `#` comment does not compile in Go"


def test_sql_interpolation_becomes_a_bound_parameter(developer: DeterministicDeveloper) -> None:
    turn = _develop(
        developer, PY_SQL_SNIPPET, "app/handlers/search.py", "python.raw-query", ["CWE-89"]
    )
    assert turn.decision is AgentDecision.PROPOSE
    assert turn.patch is not None
    assert "%{term}" not in _added(turn.patch), "the interpolation survived the rewrite"
    assert "%s" in _added(turn.patch)


def test_the_sql_rewrite_preserves_the_statement_text(developer: DeterministicDeveloper) -> None:
    """Regression guard for a real bug.

    The first implementation captured only the leading verb and rebuilt the
    rest from a fixed string, so `SELECT * FROM reports WHERE ...` came out as
    `SELECT WHERE ...` -- a patch that deleted a table from a query while
    claiming to secure it.
    """
    turn = _develop(
        developer, PY_SQL_SNIPPET, "app/handlers/search.py", "python.raw-query", ["CWE-89"]
    )
    assert turn.patch is not None
    assert "FROM reports" in _added(turn.patch), "the SQL rewrite dropped the FROM clause"
    assert "LIKE" in _added(turn.patch)


def test_shell_true_is_removed(developer: DeterministicDeveloper) -> None:
    turn = _develop(
        developer, PY_SHELL_SNIPPET, "app/services/export.py", "python.shell-true", ["CWE-78"]
    )
    assert turn.patch is not None
    assert "shell=True" not in _added(turn.patch)
    assert "shell=False, check=True" in _added(turn.patch), (
        "the patch must not comment out the arguments after shell=False"
    )


def test_a_hardcoded_secret_moves_to_the_environment(developer: DeterministicDeveloper) -> None:
    turn = _develop(
        developer,
        PY_SECRET_SNIPPET,
        "app/services/config.py",
        "python.lang.security.audit.hardcoded-credentials",
        ["CWE-798"],
    )
    assert turn.patch is not None
    # The secret necessarily appears in the diff's *removed* line -- that is what a
    # diff is. The property that matters is that the fix does not reintroduce it.
    assert "sk_live_51H8" not in _added(turn.patch), "the secret value is in the new line"
    assert 'os.environ["STRIPE_SECRET_KEY"]' in _added(turn.patch)


def test_a_go_secret_escalates_rather_than_emitting_python(
    developer: DeterministicDeveloper,
) -> None:
    """Regression guard for a defect the evidence harness found.

    `GO_SECRET_SNIPPET` and `PY_SECRET_SNIPPET` are byte-identical apart from the
    `const`, and one regex matches both. The rewrite used to answer both with
    `os.environ[...]`, which does not compile in Go -- and the test for it
    *asserted that was correct*, on a `.go` path. So the suite was not merely
    blind to the bug, it was holding it in place.

    Found by `backend/evidence/tier2.py`, which ran an independent static
    analyser over the patched Go file. See `docs/evidence.md`.
    """
    turn = _develop(
        developer,
        GO_SECRET_SNIPPET,
        "services/payments/config.go",
        "go.crypto.security.audit.hardcoded-credential",
        ["CWE-798"],
    )
    assert turn.decision is AgentDecision.ESCALATE, "a Go file was given a Python rewrite"
    assert turn.patch is None
    assert "os.environ" not in turn.message
    assert "go" in turn.rationale, "the escalation must name the language it declined for"
    assert turn.metadata["rejected_for_language"]


def test_a_rewrite_declines_an_unrecognised_file_extension(
    developer: DeterministicDeveloper,
) -> None:
    """Fails closed: an unknown language is not a licence to guess.

    Same reasoning as `_path_within_roots`. A file with no recognised extension
    could be anything, and emitting a Python fix into it because we could not
    tell would be the same defect as the Go case above.
    """
    turn = _develop(
        developer,
        PY_EVAL_SNIPPET,
        "app/report.unknownext",
        "python.lang.security.audit.eval-detected",
        ["CWE-95"],
    )
    assert turn.decision is AgentDecision.ESCALATE
    assert turn.patch is None
    assert turn.metadata["language"] == "unknown"


def test_every_rewrite_declares_the_language_its_replacement_is_valid_in() -> None:
    """The metadata has to be there for the gate above to be reachable."""
    for rule in _REWRITES:
        assert rule.languages, f"{rule.name} declares no language, so it can never fire"
        assert UNKNOWN_LANGUAGE not in rule.languages, (
            f"{rule.name} claims to be valid in an unrecognised language, which would "
            "defeat the fail-closed gate"
        )


def test_math_rand_no_longer_has_a_rewrite(developer: DeterministicDeveloper) -> None:
    """The rule was removed, not fixed, and this says why it must stay removed.

    Its pattern was Go's `rand.Intn(` and its replacement was Python's
    `secrets.randbelow(`. Repairing it would need a `crypto/rand` import, a
    `*big.Int` bound, and an error path -- none of which a regex can produce, and
    all of which a "fix" that skips is a patch that does not compile. CWE-338
    must escalate to a human.
    """
    assert all("math-rand" not in rule.name for rule in _REWRITES)
    turn = _develop(
        developer,
        '    return fmt.Sprintf("ord_%d", rand.Intn(1000000))',
        "services/payments/reference.go",
        "go.gosec.audit.weak-random",
        ["CWE-338"],
    )
    assert turn.decision is AgentDecision.ESCALATE
    assert turn.patch is None
    assert "secrets.randbelow" not in turn.message


def test_no_snippet_escalates_rather_than_guessing(developer: DeterministicDeveloper) -> None:
    turn = _develop(developer, "   ", "app/x.py", "python.eval-detected", ["CWE-95"])
    assert turn.decision is AgentDecision.ESCALATE
    assert turn.patch is None


def test_an_unknown_vulnerability_class_escalates(developer: DeterministicDeveloper) -> None:
    turn = _develop(developer, "something odd()", "app/x.py", "weird.rule", ["CWE-9999"])
    assert turn.decision is AgentDecision.ESCALATE
    assert turn.patch is None
    assert "no known remediation pattern" in turn.summary.lower()


def test_a_rewrite_whose_cwe_does_not_match_is_not_applied(
    developer: DeterministicDeveloper,
) -> None:
    """`CWE-95` is authoritative; a rule id containing "eval" must not be
    enough on its own when a CWE is supplied and disagrees."""
    turn = _develop(developer, PY_EVAL_SNIPPET, "app/x.py", "totally.unrelated-rule", ["CWE-400"])
    assert turn.decision is AgentDecision.ESCALATE


def test_output_is_deterministic(developer: DeterministicDeveloper) -> None:
    """The property that makes this engine a usable benchmark control."""
    first = _develop(developer, PY_EVAL_SNIPPET, "app/handlers/report.py", "r", ["CWE-95"])
    second = _develop(developer, PY_EVAL_SNIPPET, "app/handlers/report.py", "r", ["CWE-95"])
    assert first.patch == second.patch
    assert first.rationale == second.rationale


def test_feedback_is_acknowledged_in_the_rationale(developer: DeterministicDeveloper) -> None:
    turn = developer.develop(
        snippet=PY_EVAL_SNIPPET,
        file_path="app/x.py",
        rule_id="python.eval-detected",
        cwe_ids=["CWE-95"],
        feedback=["narrow the change", "add a test"],
        round_index=2,
    )
    assert "Revision 2" in turn.rationale
    assert "2 prior comment" in turn.rationale


# --- The reviewer -------------------------------------------------------


def test_the_reviewer_approves_a_good_patch(
    developer: DeterministicDeveloper, reviewer: DeterministicReviewer
) -> None:
    turn = _develop(
        developer, PY_EVAL_SNIPPET, "app/handlers/report.py", "python.eval-detected", ["CWE-95"]
    )
    verdict = reviewer.review(
        patch=turn.patch or "",
        snippet=PY_EVAL_SNIPPET,
        file_path="app/handlers/report.py",
        rule_id="python.eval-detected",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.APPROVE
    assert "NOT sufficient" in verdict.rationale, (
        "the reviewer must state that its approval is not a merge"
    )


def test_the_reviewer_rejects_an_empty_patch(reviewer: DeterministicReviewer) -> None:
    verdict = reviewer.review(
        patch="", snippet=PY_EVAL_SNIPPET, file_path="app/x.py", rule_id="r", round_index=1
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES


def test_the_reviewer_rejects_a_no_op_patch(reviewer: DeterministicReviewer) -> None:
    """A patch that leaves the vulnerable construct in place is a no-op."""
    verdict = reviewer.review(
        patch=_diff(PY_EVAL_SNIPPET, PY_EVAL_SNIPPET + "  # reformat\n"),
        snippet=PY_EVAL_SNIPPET,
        file_path="app/x.py",
        rule_id="python.eval-detected",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert any("vulnerable construct" in c for c in verdict.message.splitlines())


def test_the_reviewer_rejects_a_patch_that_does_not_parse(reviewer: DeterministicReviewer) -> None:
    verdict = reviewer.review(
        patch=_diff("def f():\n    return 1\n", "def f(:\n    return 1\n"),
        snippet="def f():\n    return 1\n",
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert "parse" in verdict.message or "compile" in verdict.message


def test_the_reviewer_accepts_a_return_statement_fragment(reviewer: DeterministicReviewer) -> None:
    """A scanner snippet is a fragment, not a module.

    `return render(...)` is a SyntaxError at module level and valid three lines
    down. Compiling only the fragment would make every remediation of a
    return-statement finding request changes for an unrelated reason.
    """
    verdict = reviewer.review(
        patch=_diff(PY_EVAL_SNIPPET, PY_EVAL_SNIPPET.replace("eval(", "ast.literal_eval(")),
        snippet=PY_EVAL_SNIPPET,
        file_path="app/x.py",
        rule_id="python.eval-detected",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.APPROVE


def test_the_reviewer_rejects_an_oversized_patch(reviewer: DeterministicReviewer) -> None:
    before = "x = 1\n"
    after = "x = 1\n" + "".join(f"y{i} = {i}\n" for i in range(40))
    verdict = reviewer.review(
        patch=_diff(before, after),
        snippet=before,
        file_path="app/x.py",
        rule_id="python.other",
        round_index=1,
    )
    assert verdict.decision is AgentDecision.REQUEST_CHANGES
    assert "reviewable in one sitting" in verdict.message


def test_every_rewrite_documents_its_own_limits() -> None:
    """A security rewrite must state what it does *not* fix.

    `eval` -> `ast.literal_eval` does not add `import ast`; the SQL rewrite does
    not write the bind call. An agent that hides those gaps produces a pull
    request that looks finished and is not.
    """
    for rule in _REWRITES:
        assert rule.description, f"{rule.name} has no description"
        assert rule.cwes, f"{rule.name} declares no CWE"
        assert rule.note or rule.transform, f"{rule.name} explains nothing to the reader"
    assert isinstance(_REWRITES[0], Rewrite)


def test_diff_lines_are_newline_terminated(developer: DeterministicDeveloper) -> None:
    """A scanner snippet usually has no trailing newline.

    Without normalization, `difflib` concatenates the `-` and `+` lines onto
    one line and `git apply` rejects the patch.
    """
    turn = _develop(developer, PY_EVAL_SNIPPET, "app/x.py", "python.eval-detected", ["CWE-95"])
    assert turn.patch is not None
    diff_lines = [
        line
        for line in turn.patch.splitlines()
        if line.startswith(("+", "-")) and not line.startswith(("+++", "---"))
    ]
    for line in diff_lines:
        assert line.strip(), "a diff line lost its content"


def _diff(before: str, after: str) -> str:
    """Build a diff the way the production code does.

    Newline-normalizing matters here for the same reason it does in
    `_unified_diff`: without it, `difflib` concatenates the `-` and `+` lines
    and every reviewer assertion below is testing a malformed patch.
    """
    import difflib

    before = before if before.endswith("\n") else before + "\n"
    after = after if after.endswith("\n") else after + "\n"
    body = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="a/app/x.py",
            tofile="b/app/x.py",
            n=3,
        )
    )
    return "### test patch\n\n" + body


def _added(patch: str) -> str:
    """Only the `+` lines of a diff.

    Assertions about a fix have to look at the added lines. A diff necessarily
    contains the *removed* text too, so asserting `"shell=True" not in patch`
    would fail on a correct patch -- and asserting on added lines is what
    actually answers "did the fix happen?".
    """
    return "\n".join(
        line for line in patch.splitlines() if line.startswith("+") and not line.startswith("+++")
    )


def _removed(patch: str) -> str:
    return "\n".join(
        line for line in patch.splitlines() if line.startswith("-") and not line.startswith("---")
    )
