"""How much source the remediation loop is shown, and why that is a decision.

## The problem this exists to solve

A scanner reports **one line**. `SemgrepScanner` maps Semgrep's `extra.lines`,
which for a single-line pattern match is exactly that: one line.

The reviewer then judges a multi-line patch against it. Its scope check requires
every line the diff removes to appear in the reported snippet, so:

    finding snippet   cursor.execute(f"SELECT ... WHERE title LIKE '%{term}%'")
    a real fix        removes 4 lines and adds 9, around that one line
    the reviewer      "the patch removes lines that are not present in the
                       reported snippet, so it is not scoped to this finding"

That is not a false positive in the sense of being wrong about the diff — it is
the reviewer reasoning correctly about a badly-posed question. It was given one
line and told to judge a five-line change against it.

Measured over 30 real, merged, human-reviewed security fixes: **9 of 30
rejected** with a one-line snippet, **3 of 30** given ten lines. Two-thirds of
the false rejections were the scanner starving the reviewer. See
`docs/evidence.md`.

## What this does about it

Show the loop the finding's **enclosing block** rather than the single line the
pattern matched. Three strategies, in order, each recorded in the result so the
audit trail says which one was used rather than implying a context that was not
there:

| strategy | when | what the loop sees |
|---|---|---|
| `enclosing-block` | the finding is inside an indented block | that whole block |
| `context-window` | the finding is at the top level | the line plus N either side |
| `reported` | no line numbers, or no readable file | the scanner's own text |
| `truncated` | the block exceeded `max_lines` | the block, cut, finding kept |

**Enclosing block, by indentation.** Python and Go are both indentation-
structured, so the smallest run of lines at least as indented as the finding,
plus the header that opens it, is the natural unit. It is not a parser and does
not pretend to be: it reads indentation, which is what those two languages
actually define scope with. For a brace-delimited language it degrades to
whatever the indentation happens to enclose, which is *wider* than one line —
still an improvement, still recorded as what it is.

**A finding at indentation zero has no enclosing block**, because the block would
be the file. That case falls through to the window rather than returning a
whole-file snippet, which is the failure mode a naive implementation would hit
on `HARDCODED_API_KEY = "sk_live_..."`.

## What this deliberately does not do

**It does not change what the finding records.** `findings.snippet` keeps exactly
what the scanner reported, because a finding is a statement about what the
scanner found and widening it would make the database and the MCP tool output
lie about the detector's precision. The widening happens at the point of use.

**It does not change any safety property.** The reviewer still rejects patches
that remove lines outside the block it was shown, and still enforces the
20-added-line ceiling. What changes is that it is being asked a fair question.

**It does not read files the policy gates have not cleared.** The snippet is
widened after `evaluate_auto_remediation` has confirmed the path is inside the
operator's allow-list, from the same `finding.file_path` the rest of the loop
uses. There is no new path to anywhere.

## The one case where the scanner's text is not preserved

A finding is a snapshot, and the file can have moved on since the scan. When the
file is readable, **the file wins**: the loop is shown the current content of the
lines it is about to patch, not the scanner's copy of them. A stale snapshot handed
to an agent as "the surrounding code" produces a patch that cannot apply, which is
a worse outcome than a missing line.

So `reported` is the floor only when the file cannot be read or has no line
numbers — a moved file, a permission problem, a fixture finding naming a path that
was never created. The reported text is returned untouched in every one of those
cases, which is what keeps the fixture-driven tests working.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

# Lines either side of the finding when there is no enclosing block to show.
#
# Ten is not arbitrary and not tuned: it is the width `backend/evidence/tier3.py`
# measured, and it is what took the real-fix rejection rate from 9 of 30 to 3 of
# 30. Changing it changes a number that is written down, so if you do, re-measure.
WINDOW_LINES = 10

# A blank line between the header and the body is normal style, so the walk
# continues through one. Two is not normal.
_MAX_HEADER_GAP = 2


class SnippetStrategy(StrEnum):
    """How the loop's snippet was obtained. Recorded, never assumed."""

    REPORTED = "reported"
    """The scanner's own text, unchanged. No line numbers, or no readable file."""

    ENCLOSING_BLOCK = "enclosing-block"
    """The finding's enclosing indented block, plus the header that opens it."""

    CONTEXT_WINDOW = "context-window"
    """The finding plus WINDOW_LINES either side. No enclosing block exists."""

    TRUNCATED = "truncated"
    """An enclosing block that exceeded `max_lines`, cut back to it.

        A distinct value because a truncated block is not the block, and a caller
        reading `enclosing-block` would be entitled to assume the whole thing was
        shown. The cut keeps the finding, so the lines the patch is about are
        always present.
        """


@dataclass(frozen=True, slots=True)
class EnrichedSnippet:
    """The text the loop is shown, and how it was obtained."""

    text: str
    strategy: SnippetStrategy
    start_line: int = 0
    """1-based first line of `text` in the real file. 0 when `strategy` is
    `REPORTED` and the text is not a faithful slice of the file."""

    line_count: int = 0
    """How many lines the loop is being shown, always.

        Counted for the `REPORTED` branch too, where it is the line count of the
        scanner's own text. It would be easy to leave it at zero there, on the
        reasoning that the text has no known position in the file -- and the
        result is an audit row reading `snippet_lines: 0`, which every reader
        will interpret as *the agent was shown nothing*. It was shown a line.
        A field that can mean the opposite of its name is worse than no field.
        """

    @property
    def widened(self) -> bool:
        return self.strategy is not SnippetStrategy.REPORTED


def enrich_snippet(
    *,
    file_path: str,
    reported: str,
    start_line: int | None,
    end_line: int | None = None,
    max_lines: int = 120,
    root: Path | None = None,
) -> EnrichedSnippet:
    """Return the source the remediation loop should be shown.

    Never raises and never returns less than `reported`. A scanner's own text is
    the floor, because the alternative to a wider snippet is a loop that refuses
    to fix anything, and "I could not read the file" is not a reason to make the
    agent blind.

    `root` is for tests: it points the reader at a tree other than the process's
    working directory. Production passes nothing, because the path has already
    been through the policy gate and must not be re-resolved against anything.
    """
    if start_line is None or start_line < 1 or not file_path:
        return _reported(reported)

    lines = _read(file_path, root)
    if lines is None:
        return _reported(reported)

    first = min(start_line, len(lines))
    last = max(end_line or start_line, first)

    block = _enclosing_block(lines, first, last)
    if block is not None:
        start, stop = block
        strategy = SnippetStrategy.ENCLOSING_BLOCK
    else:
        start = max(1, first - WINDOW_LINES)
        stop = min(len(lines), last + WINDOW_LINES)
        strategy = SnippetStrategy.CONTEXT_WINDOW

    text = "\n".join(lines[start - 1 : stop])
    if max_lines > 0 and (stop - start + 1) > max_lines:
        # Keep the finding. A snippet that omitted the lines it is about would be
        # worse than a truncated one, so the cut falls on the far side.
        stop -= (stop - start + 1) - max_lines
        text = "\n".join(lines[start - 1 : stop])
        strategy = SnippetStrategy.TRUNCATED
    return EnrichedSnippet(
        text=text, strategy=strategy, start_line=start, line_count=stop - start + 1
    )


def _reported(reported: str) -> EnrichedSnippet:
    """The scanner's own text, unchanged, with an honest line count.

    The count is the number of lines actually being passed to the loop, not zero
    and not "unknown" -- the audit row records it, and `0` there reads as though
    the agent was shown nothing.
    """
    return EnrichedSnippet(
        text=reported,
        strategy=SnippetStrategy.REPORTED,
        line_count=len(reported.splitlines()),
    )


def _read(file_path: str, root: Path | None) -> list[str] | None:
    """The file's lines, or None if it cannot be read.

    None rather than an exception because a file the scanner flagged may since
    have been moved, renamed, or be unreadable, and none of those should stop a
    remediation -- the reported one-liner is still a usable snippet.
    """
    path = (root / file_path) if root is not None else Path(file_path)
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None


def _indent_of(line: str) -> int | None:
    """Leading whitespace width, or None for a line with none.

    A line with no leading whitespace is at the top level. Tabs count as four,
    which is the usual convention and only ever affects which lines are judged
    "more indented"; it cannot make a wrong answer look right.
    """
    stripped = line.lstrip()
    if not stripped:
        return None
    prefix = line[: len(line) - len(stripped)]
    return len(prefix.replace("\t", "    "))


def _enclosing_block(lines: list[str], first: int, last: int) -> tuple[int, int] | None:
    """The smallest indented run containing `first..last`, plus its header.

    None when the finding is at indentation zero, because then the enclosing
    block is the whole file and a whole file is not a snippet.
    """
    anchor = _indent_of(lines[first - 1])
    if anchor is None or anchor == 0:
        return None

    # Up: the header is the first line above with a *smaller* indent. Anything
    # at or above the finding's own indent is part of the block.
    start = first
    gap = 0
    for index in range(first - 2, -1, -1):
        indent = _indent_of(lines[index])
        if indent is None:
            gap += 1
            if gap > _MAX_HEADER_GAP:
                break
            continue
        if indent < anchor:
            start = index + 1
            break
        start = index + 1
        gap = 0

    # Down: everything at the finding's indent or deeper.
    stop = last
    for index in range(last, len(lines)):
        indent = _indent_of(lines[index])
        if indent is not None and indent < anchor:
            break
        stop = index + 1

    return start, stop
