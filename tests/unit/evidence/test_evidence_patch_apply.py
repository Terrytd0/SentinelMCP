"""`apply_patch`: the capability the pipeline did not have, and its guarantees.

A patch that has never been applied to a file has never been tested. These tests
are mostly about the ways it can *fail*, because `apply_patch` is used by a
verification harness and a harness that quietly skips the patch it was measuring
is worse than no harness.
"""

from __future__ import annotations

import pytest

from backend.evidence.patch_apply import (
    STRATEGY_AMBIGUOUS,
    STRATEGY_AT_ANCHOR,
    STRATEGY_UNIQUE_IGNORING_INDENT,
    STRATEGY_UNIQUE_MATCH,
    apply_patch,
    split_diff,
)

SAMPLE = "line one\nline two\nline three\nline four\n"


def _patch(*, removed: list[str], added: list[str], header: str = "app/x.py") -> str:
    body = [f"--- a/{header}", f"+++ b/{header}", "@@ -1,1 +1,1 @@"]
    body += [f"-{line}" for line in removed]
    body += [f"+{line}" for line in added]
    return "\n".join(body) + "\n"


# --- split_diff ---------------------------------------------------------


def test_the_preamble_and_hunk_header_are_not_diff_content() -> None:
    """The diff renderer writes `### ...` lines above the `---` block.

    A `patch(1)` tool would choke on them. More to the point, treating `###` as
    content would put a comment into the source, which is the exact bug the
    preamble was introduced to avoid.
    """
    patch = (
        "### SentinelMCP remediation (round 1)\n"
        "### target: app/x.py\n"
        "### fix: use ast.literal_eval()\n"
        "\n"
        "--- a/app/x.py\n"
        "+++ b/app/x.py\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+new\n"
    )
    removed, added = split_diff(patch)
    assert removed == ["old"]
    assert added == ["new"]


def test_the_file_headers_are_not_removed_or_added_lines() -> None:
    removed, added = split_diff("--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-old\n+new\n")
    assert removed == ["old"]
    assert added == ["new"]


# --- application --------------------------------------------------------


def test_a_patch_applies_at_the_reported_line() -> None:
    result = apply_patch(SAMPLE, _patch(removed=["line three"], added=["THREE"]), anchor_line=3)
    assert result.applied
    assert result.strategy == STRATEGY_AT_ANCHOR
    assert result.line == 3
    assert result.text == "line one\nline two\nTHREE\nline four\n"


def test_a_wrong_anchor_falls_through_to_a_content_search() -> None:
    """The anchor is a hint, not a constraint.

    A patch applied to the wrong line produces a confidently wrong measurement,
    so a wrong hint must be ignored rather than obeyed -- but the patch still has
    to be applied, and the report has to say it was located by search.
    """
    result = apply_patch(SAMPLE, _patch(removed=["line two"], added=["TWO"]), anchor_line=1)
    assert result.applied
    assert result.strategy == STRATEGY_UNIQUE_MATCH
    assert result.line == 2
    assert result.text == "line one\nTWO\nline three\nline four\n"


def test_an_unlocatable_patch_fails_closed_and_leaves_the_text_alone() -> None:
    result = apply_patch(SAMPLE, _patch(removed=["not in the file"], added=["x"]))
    assert not result.applied
    assert result.text == SAMPLE, "a failed application must not have modified anything"
    assert "not present" in result.reason
    assert result.line is None


def test_an_ambiguous_patch_fails_rather_than_guessing() -> None:
    """Two identical lines, one diff. There is no way to know which is meant.

    Picking the first would be a coin flip that produces a *confident* wrong
    answer, and the whole point of this module is that a measurement has to be
    either right or absent.
    """
    text = "x = 1\ny = 2\nx = 1\n"
    result = apply_patch(text, _patch(removed=["x = 1"], added=["x = 2"]))
    assert not result.applied
    assert result.strategy == STRATEGY_AMBIGUOUS
    assert "2 times" in result.reason
    assert result.text == text


def test_indentation_is_forgiven_only_when_nothing_else_matches() -> None:
    """A scanner reports a snippet with the indentation the line had.

    A rewrite can change that indentation, so a byte-exact match would fail on a
    perfectly correct patch. But two lines that differ *only* in indentation can
    be genuinely different statements, so the fallback runs only after the exact
    search has found nothing.
    """
    text = "if True:\n        run(1)\n"
    result = apply_patch(text, _patch(removed=["    run(1)"], added=["    run(2)"]))
    assert result.applied
    assert result.strategy == STRATEGY_UNIQUE_IGNORING_INDENT
    assert result.text == "if True:\n    run(2)\n"


def test_indentation_is_not_forgiven_when_it_makes_the_match_ambiguous() -> None:
    text = "if True:\n    run(1)\n    run(1)\n"
    result = apply_patch(text, _patch(removed=["run(1)"], added=["run(2)"]))
    assert not result.applied
    assert result.strategy == STRATEGY_AMBIGUOUS


def test_a_diff_with_no_removals_is_reported_not_guessed_at() -> None:
    result = apply_patch(SAMPLE, _patch(removed=[], added=["brand new"]))
    assert not result.applied
    assert "removes no lines" in result.reason


def test_a_multi_line_block_is_replaced_as_a_block() -> None:
    text = "def f():\n    a = 1\n    b = 2\n    return a\n"
    patch = _patch(removed=["    a = 1", "    b = 2"], added=["    a = _safe(1)"])
    result = apply_patch(text, patch, anchor_line=2)
    assert result.applied
    assert result.text == "def f():\n    a = _safe(1)\n    return a\n"
    assert result.removed_count == 2
    assert result.added_count == 1


def test_a_trailing_newline_is_preserved_because_provenance_needs_it() -> None:
    with_newline = apply_patch(SAMPLE, _patch(removed=["line one"], added=["ONE"]))
    assert with_newline.text.endswith("\n")
    without = apply_patch(SAMPLE.rstrip("\n"), _patch(removed=["line one"], added=["ONE"]))
    assert not without.text.endswith("\n")


@pytest.mark.parametrize("anchor", [None, 0, -1, 99])
def test_an_out_of_range_anchor_is_ignored_rather_than_crashing(anchor: int | None) -> None:
    result = apply_patch(SAMPLE, _patch(removed=["line one"], added=["ONE"]), anchor_line=anchor)
    assert result.applied
    assert result.line == 1


def test_an_empty_file_and_an_empty_diff() -> None:
    assert not apply_patch("", _patch(removed=["x"], added=["y"])).applied
    assert not apply_patch(SAMPLE, "").applied
