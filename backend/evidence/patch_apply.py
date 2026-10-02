"""Apply an agent's diff to a real file. The capability the pipeline lacked.

`backend/agents/deterministic.py` renders a diff with `difflib` over a
*scanner-reported snippet* treated as a one-line document, while the
`---`/`+++` headers name the *whole file*:

    ### SentinelMCP remediation (round 1)
    ### target: app/search.py
    ### fix: bound parameter, not string interpolation

    --- a/app/search.py
    +++ b/app/search.py
    @@ -1 +1 @@
    -    cursor.execute(f"SELECT ... WHERE title LIKE '%{term}%'")
    +    cursor.execute(sql = "SELECT ... WHERE title LIKE '%%%s%%'")

`@@ -1 +1 @@` is always line 1, because the "before" side is the snippet, not
the file. `git apply` and `patch` both reject that hunk, and the project has no
git repository to apply it in anyway. Nothing in `backend/` ever wrote a
patched file to disk, so the gap was invisible: every test asserted on the diff
*string* and never on the diff *applied*.

This module closes it, which is what makes `docs/evidence.md` possible. A patch
that has never been applied to a file has never been tested, and an un-applied
security patch is a string.

## What it guarantees, and what it does not

`apply_patch` **fails closed**. If the removed lines cannot be located in the
target -- because the file moved on, because the scanner's snippet is stale, or
because the diff is ambiguous -- it returns `applied=False` with a reason and
leaves the text untouched. A verification harness that silently skipped the
patch it was measuring would be worse than no harness, so an unlocatable patch
is a reported result, never a quiet pass.

It is deliberately *not* a general unified-diff implementation. It understands
the one shape this codebase emits: a single contiguous block of removed lines
replaced by a single contiguous block of added lines, located by content rather
than by the (meaningless) hunk header. Adding hunk-offset support would be
solving a problem the producer does not have.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The preamble the diff renderer writes above the `---`/`+++` block. Not part
# of the patch; a `patch` tool would choke on it, which is part of why this
# module exists.
_PREAMBLE = re.compile(r"^###\s")

_HUNK = re.compile(r"^@@.*@@")


@dataclass(frozen=True, slots=True)
class PatchApplication:
    """The outcome of applying one diff to one piece of text.

    `applied` is the only field a caller must branch on. `line` is the 1-based
    line the patch landed on, which is what lets the Tier 3 corpus compare this
    engine's patch against a real upstream fix at line granularity.
    """

    applied: bool
    text: str
    """The patched text, or `text` unchanged when `applied` is False."""

    line: int | None = None
    """1-based line of the first replaced line, or None if not applied."""

    strategy: str = ""
    """How the location was found. One of the `STRATEGY_*` constants below."""

    reason: str = ""
    """Why it failed. Empty on success."""

    removed_count: int = 0
    added_count: int = 0


STRATEGY_AT_ANCHOR = "at-anchor"
"""Found at the scanner's reported `start_line`, with no search."""

STRATEGY_UNIQUE_MATCH = "unique-match"
"""Found by content, at exactly one place in the file."""

STRATEGY_UNIQUE_IGNORING_INDENT = "unique-match-ignoring-indent"
"""Found by content with leading whitespace stripped, at exactly one place.

    A scanner reports a snippet with whatever indentation the line had, and a
    rewrite can change that indentation. Requiring a byte-exact match would
    make the harness fail on a patch that is perfectly correct.
    """

STRATEGY_AMBIGUOUS = "ambiguous"
"""The removed lines occur more than once, so the target is ambiguous."""


def split_diff(patch: str) -> tuple[list[str], list[str]]:
    """Split a diff into `(removed_lines, added_lines)`, markers stripped.

    The `### ` preamble and the `@@` hunk header are dropped. `---`/`+++` file
    headers are dropped rather than treated as content lines -- they are the
    *only* place a leading `-`/`+` appears without being a diff marker, and
    treating them as removals would delete the file's own header from the text
    being patched.
    """
    removed: list[str] = []
    added: list[str] = []
    for raw in patch.splitlines():
        if _PREAMBLE.match(raw) or _HUNK.match(raw):
            continue
        if raw.startswith("--- ") or raw.startswith("+++ "):
            continue
        if raw.startswith("-"):
            removed.append(raw[1:].rstrip("\n"))
        elif raw.startswith("+"):
            added.append(raw[1:].rstrip("\n"))
    return removed, added


def apply_patch(text: str, patch: str, *, anchor_line: int | None = None) -> PatchApplication:
    """Apply `patch` to `text`, locating the target by content.

    `anchor_line` is the finding's 1-based `start_line`. It is a *hint*, not a
    constraint: it is tried first because it is cheap and correct most of the
    time, and a wrong hint falls through to a content search rather than
    misplacing the patch. That is the right trade for a verification harness --
    a patch applied to the wrong line would produce a confidently wrong
    measurement, so the search is content-anchored and the hint only narrows it.
    """
    removed, added = split_diff(patch)
    if not removed:
        return PatchApplication(
            applied=False,
            text=text,
            reason="the diff removes no lines, so there is nothing to locate",
            added_count=len(added),
        )

    lines = text.splitlines()

    located = _locate(lines, removed, anchor_line)
    if located.index is None:
        return PatchApplication(
            applied=False,
            text=text,
            strategy=located.strategy,
            reason=located.reason,
            removed_count=len(removed),
            added_count=len(added),
        )

    patched = lines[: located.index] + added + lines[located.index + len(removed) :]
    return PatchApplication(
        applied=True,
        text="\n".join(patched) + ("\n" if text.endswith("\n") else ""),
        line=located.index + 1,
        strategy=located.strategy,
        removed_count=len(removed),
        added_count=len(added),
    )


@dataclass(frozen=True, slots=True)
class _Located:
    index: int | None
    strategy: str
    reason: str = ""


def _locate(lines: list[str], removed: list[str], anchor_line: int | None) -> _Located:
    """Find where `removed` occurs in `lines`, trying each strategy in order."""
    span = len(removed)

    if anchor_line is not None and 1 <= anchor_line <= len(lines):
        start = anchor_line - 1
        if lines[start : start + span] == removed:
            return _Located(start, STRATEGY_AT_ANCHOR)

    exact = _indexes_of(lines, removed, ignore_indent=False)
    if len(exact) == 1:
        return _Located(exact[0], STRATEGY_UNIQUE_MATCH)
    if len(exact) > 1:
        return _Located(
            None,
            STRATEGY_AMBIGUOUS,
            f"the removed lines occur {len(exact)} times in the target, "
            "so there is no way to tell which occurrence the diff means",
        )

    loose = _indexes_of(lines, removed, ignore_indent=True)
    if len(loose) == 1:
        return _Located(loose[0], STRATEGY_UNIQUE_IGNORING_INDENT)
    if len(loose) > 1:
        return _Located(
            None,
            STRATEGY_AMBIGUOUS,
            f"the removed lines occur {len(loose)} times in the target "
            "once leading whitespace is ignored",
        )

    return _Located(None, "", "the removed lines are not present in the target")


def _indexes_of(lines: list[str], removed: list[str], *, ignore_indent: bool) -> list[int]:
    """Every index at which `removed` occurs as a contiguous block.

    Trailing whitespace is always ignored: `splitlines` on text that came from
    disk can leave `\r` behind, and a diff produced from a snippet that was read
    with universal newlines will not. Leading whitespace is ignored only on the
    fallback pass, because two lines that differ only in indentation really can
    be different statements.
    """
    span = len(removed)
    strip = (lambda line: line.lstrip()) if ignore_indent else (lambda line: line)
    haystack = [strip(line).rstrip() for line in lines]
    probe = [strip(line).rstrip() for line in removed]
    return [i for i in range(len(haystack) - span + 1) if haystack[i : i + span] == probe]
