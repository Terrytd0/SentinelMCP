"""Tier 3: real CVEs, and the real upstream commits that fixed them.

The first two tiers test the engine against vulnerabilities *this project wrote
for the purpose*. That is a real weakness in both of them, and it is the same
weakness every benchmark has: the test set and the system share an author.

This tier removes it. Every case is a published GitHub Security Advisory with a
real fix commit in a real repository, fetched on demand. The label is not a
judgement call -- it is what the upstream maintainers actually wrote.

## What the label is, precisely

For an advisory with fix commit `S`, the labelled pair is the *content of the
files the fix changed*, before and after:

    git rev-list --parents -n 1 S     ->  S and its first parent P
    git show P:<path>                ->  the vulnerable file
    git show S:<path>                ->  the fixed file
    git diff -U0 P S                 ->  exactly which lines the maintainers changed

`P` rather than `S^0` because many of these advisories are fixed by a *merge*
commit, and diffing a merge against its first parent is the only way to see
what that merge brought in. A merge commit is recorded as one, because a
diff measured against the wrong parent would be a confident wrong number.

## What is measured, and what is not claimed

Three measurements, in decreasing order of how much they mean:

1. **Coverage.** For a real advisory, is there even a line in the vulnerable
   file that this engine's rule table can bite on? Most real CVEs will not be --
   the table is seven rules. This is the honest headline number and it is low.
   Recording it is the point; inflating it by loosening the matching would be
   the failure this project is trying to avoid.

2. **When it does engage: line agreement.** Did the engine's patch land on a
   line the maintainers also changed? This is a comparison against ground
   truth, not a self-assessment. It says nothing about whether our patch is
   *correct* -- a maintainer who rewrote a whole file agrees with us on
   everything -- which is why the report pairs it with the diff size rather
   than presenting it as a score.

3. **Would the real fix pass our reviewer?** A patch upstream's own maintainers
   merged, run through `DeterministicReviewer`. The minimality check caps a
   single-finding patch at 20 added lines; real security fixes routinely exceed
   that. Reporting how often a *merged, human-reviewed* fix would be rejected is
   the most useful thing this tier produces, and it is not flattering.

## The bias, stated rather than hidden

The candidate line is found by scanning the vulnerable file for lines one of the
seven rules matches. So this tier can only ever find the vulnerabilities it was
built to find -- measurement 1 is therefore an *upper* bound on coverage, and
the number is reported as "rules engaged" rather than "vulnerabilities found".

The 19 advisories are a deliberate mix: CWEs the table covers (78, 89, 95, 200,
295, 798) and CWEs it does not (77, 94, 113, 601, 670, 770). Including the
second group is the point. A corpus of only the easy cases would report a
coverage figure that means nothing.

## Cost, and why the manifest is checked in

`data/evidence/corpus.json` holds advisory metadata only -- ids, CWEs, fix commit
SHAs. No upstream source is vendored, and the only network step is a `git fetch`
of two commits per advisory into a gitignored cache under
`data/evidence/.cache/`. Semgrep's rule packs and a multi-gigabyte model
download are avoided for the same reason.

The tier skips itself, with a reason, when git is absent or the fetch fails.
It never fabricates a case to fill the table.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.agents.deterministic import (
    _REWRITES,
    AgentTurn,
    DeterministicDeveloper,
    DeterministicReviewer,
)
from backend.evidence.patch_apply import apply_patch

MANIFEST_PATH = Path("data/evidence/corpus.json")
CACHE_DIR = Path("data/evidence/.cache")
FETCH_TIMEOUT_SECONDS = 300
DIFF_TIMEOUT_SECONDS = 60

_SNIPPET_MAX_LINES = 120
"""Mirrors `Settings.remediation_snippet_max_lines`.

    Duplicated rather than read from settings so this tier measures the *shipped
    default* rather than whatever the machine running it happens to have
    configured, which would make the committed report unreproducible from a
    differently-configured checkout. A test asserts the two agree, so a change to
    one without the other fails rather than quietly measuring a stale rule.
"""

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


@dataclass(frozen=True, slots=True)
class Advisory:
    """One entry from the checked-in manifest."""

    advisory: str
    package: str
    repo: str
    cwe_ids: tuple[str, ...]
    aliases: tuple[str, ...]
    fixed_in: tuple[str, ...]
    fix_commits: tuple[str, ...]
    why: str
    summary: str


@dataclass(slots=True)
class RealFix:
    """One file's real before/after, and the lines upstream changed."""

    path: str
    before: str
    after: str
    lines_changed: tuple[int, ...]
    """1-based line numbers in `before` that the real fix removed or replaced."""

    added_lines: int
    removed_lines: int


@dataclass(slots=True)
class FileOutcome:
    """What the engine did with one real vulnerable file."""

    path: str
    cwe: str
    our_line: int | None = None
    our_rewrite: str = ""
    our_decision: str = ""
    reviewer_verdict: str = ""
    reviewer_comments: tuple[str, ...] = ()
    real_lines: tuple[int, ...] = ()
    added_lines: int = 0
    removed_lines: int = 0
    same_line_as_upstream: bool | None = None
    review_of_the_real_fix: str = ""
    real_fix_would_pass: bool | None = None
    real_fix_would_pass_with_context: bool | None = None
    """The same fix judged with the snippet `enrich_snippet` actually produces.

        The gap between the two is the measurement worth having. See `_assess`.
        """

    context_lines: int = 0
    snippet_strategy: str = ""
    """Which strategy `enrich_snippet` chose for this file, on the real path.

        Recorded because a number measured with a mechanism nobody uses is a
        number about the measurement.
        """

    snippet_lines: int = 0
    real_fix_comments: tuple[str, ...] = ()
    """The objections the reviewer actually raised, in production.

        "Changes requested (2 issues)" is not a finding. "The patch adds 67 lines
        for a single finding" is, and it is the difference between a report a
        reader can argue with and one they can only accept. These are the
        *production* verdict's comments, because that is the configuration being
        reported on -- the contextual run's comments are a separate field, and
        conflating them would classify a rejection by an objection the reviewer
        did not make.
        """

    real_fix_comments_with_context: tuple[str, ...] = ()

    notes: list[str] = field(default_factory=list)

    @property
    def size_gap(self) -> int:
        """How much bigger the real fix was than ours. Negative means ours is bigger."""
        return self.added_lines - self.our_added_lines

    our_added_lines: int = 0


@dataclass(slots=True)
class AdvisoryOutcome:
    """One advisory, across every file its fix commit touched."""

    advisory: str
    package: str
    repo: str
    cwe_ids: tuple[str, ...]
    summary: str
    status: str = "ok"
    """`ok`, `fetch-failed`, or `no-changes`."""

    detail: str = ""
    is_merge: bool = False
    first_parent: str = ""
    files: list[FileOutcome] = field(default_factory=list)

    @property
    def engaged(self) -> list[FileOutcome]:
        return [f for f in self.files if f.our_decision == "PROPOSE"]

    @property
    def declined(self) -> list[FileOutcome]:
        return [f for f in self.files if f.our_decision == "ESCALATE"]

    @property
    def no_candidate(self) -> list[FileOutcome]:
        return [f for f in self.files if f.our_decision == "no-candidate-line"]


@dataclass(slots=True)
class Tier3Result:
    runs: bool
    skipped_reason: str = ""
    duration_ms: float = 0.0
    manifest: tuple[Advisory, ...] = ()
    outcomes: list[AdvisoryOutcome] = field(default_factory=list)

    @property
    def ran(self) -> bool:
        """Alias for `runs`, so all three tier results answer the same question."""
        return self.runs

    @property
    def measured(self) -> list[AdvisoryOutcome]:
        return [o for o in self.outcomes if o.status == "ok"]

    @property
    def files_examined(self) -> list[FileOutcome]:
        return [f for o in self.measured for f in o.files]

    @property
    def advisories_with_engagement(self) -> list[AdvisoryOutcome]:
        return [o for o in self.measured if o.engaged]

    @property
    def line_agreements(self) -> int:
        return sum(
            1 for outcome in self.measured for f in outcome.engaged if f.same_line_as_upstream
        )

    @property
    def real_fixes_reviewed(self) -> list[FileOutcome]:
        return [f for f in self.files_examined if f.real_fix_would_pass is not None]

    @property
    def real_fixes_rejected(self) -> list[FileOutcome]:
        return [f for f in self.real_fixes_reviewed if not f.real_fix_would_pass]

    @property
    def real_fixes_rejected_with_context(self) -> list[FileOutcome]:
        """The same measurement with surrounding source available to the reviewer."""
        return [f for f in self.real_fixes_reviewed if f.real_fix_would_pass_with_context is False]


def load_corpus(path: Path = MANIFEST_PATH) -> tuple[Advisory, ...]:
    """Read the checked-in manifest. No network, no fallback."""
    if not path.is_file():
        raise FileNotFoundError(
            f"the advisory manifest {path} is missing; it is committed, so this is a "
            "checkout problem rather than a network problem"
        )
    document = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        Advisory(
            advisory=str(entry["advisory"]),
            package=str(entry["package"]),
            repo=str(entry["repo"]),
            cwe_ids=tuple(str(c) for c in entry.get("cwe_ids", [])),
            aliases=tuple(str(c) for c in entry.get("aliases", [])),
            fixed_in=tuple(str(c) for c in entry.get("fixed_in", [])),
            fix_commits=tuple(str(c) for c in entry.get("fix_commits", [])),
            why=str(entry.get("why", "")),
            summary=str(entry.get("summary", "")),
        )
        for entry in document.get("advisories", [])
    )


def run_tier_3(
    manifest_path: Path = MANIFEST_PATH,
    *,
    cache_dir: Path = CACHE_DIR,
    limit: int | None = None,
) -> Tier3Result:
    """Fetch each advisory's fix commit and run the engine over the vulnerable code."""
    started = time.perf_counter()
    try:
        advisories = load_corpus(manifest_path)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        return Tier3Result(runs=False, skipped_reason=str(exc))

    if not _git_available():
        return Tier3Result(
            runs=False,
            skipped_reason="git is not on PATH, so no upstream commit can be fetched",
            manifest=advisories,
        )

    selected = advisories[:limit] if limit else advisories
    outcomes: list[AdvisoryOutcome] = []
    for advisory in selected:
        outcomes.append(_run_one(advisory, cache_dir))

    return Tier3Result(
        runs=True,
        duration_ms=(time.perf_counter() - started) * 1000.0,
        manifest=advisories,
        outcomes=outcomes,
    )


def _git_available() -> bool:
    return bool(_git_version())


def _run_one(advisory: Advisory, cache_dir: Path) -> AdvisoryOutcome:
    outcome = AdvisoryOutcome(
        advisory=advisory.advisory,
        package=advisory.package,
        repo=advisory.repo,
        cwe_ids=advisory.cwe_ids,
        summary=advisory.summary,
    )
    sha = advisory.fix_commits[0] if advisory.fix_commits else ""
    if len(sha) != 40:
        outcome.status = "fetch-failed"
        outcome.detail = "the manifest has no full-length fix commit SHA"
        return outcome

    repo_dir = cache_dir / advisory.repo.replace("/", "__")
    try:
        _prepare_repo(repo_dir, advisory.repo)
        _fetch(repo_dir, sha)
        parents = _parents(repo_dir, sha)
    except _GitError as exc:
        outcome.status = "fetch-failed"
        outcome.detail = str(exc)
        return outcome

    outcome.is_merge = len(parents) > 1
    if not parents:
        outcome.status = "fetch-failed"
        outcome.detail = f"commit {sha} has no resolvable parent in the fetch"
        return outcome
    # First parent: for a merge commit this is the state the merge landed on, and
    # diffing against anything else measures the wrong change.
    outcome.first_parent = parents[0]

    fixes = _real_fixes(repo_dir, parents[0], sha)
    if not fixes:
        outcome.status = "no-changes"
        outcome.detail = (
            f"no .py/.go file changed between {parents[0][:9]} and {sha[:9]}, so there is "
            "no source to point the engine at"
        )
        return outcome

    developer = DeterministicDeveloper()
    reviewer = DeterministicReviewer(_REWRITES)
    with tempfile.TemporaryDirectory(
        prefix="sentinel-evidence-tier3-", ignore_cleanup_errors=True
    ) as raw:
        # The vulnerable content is materialised so `_enrich` can run the shipped
        # `enrich_snippet` against real bytes on disk, rather than a copy of its
        # logic operating on strings.
        root = Path(raw)
        for fix in fixes:
            outcome.files.append(_assess(developer, reviewer, advisory, fix, root))
    return outcome


class _GitError(RuntimeError):
    """A git invocation failed. The message is the command's own last line."""


def _git(
    repo_dir: Path,
    args: list[str],
    timeout: int = DIFF_TIMEOUT_SECONDS,
    *,
    ignore_failure: bool = False,
) -> str:
    """Run one git command. Raises `_GitError` unless it succeeds.

    `encoding="utf-8"` and `errors="replace"` are not defaults to be tidy about.
    `text=True` alone decodes with the *locale* encoding, which on Windows is
    cp1252, and a real Django commit message contains a byte cp1252 cannot
    decode. The failure is nastier than a `UnicodeDecodeError`: it happens on a
    subprocess reader *thread*, so `completed.stdout` silently comes back
    `None` and the next line of this module dies with
    `AttributeError: 'NoneType' object has no attribute 'endswith'`, four frames
    from the cause. Upstream source is UTF-8 by definition, so decode it as
    UTF-8 and replace rather than fail on a stray byte.

    `ignore_failure` exists for exactly one caller -- checking whether a remote
    already exists -- because a non-zero exit there is information rather than
    a failure, and it is expressed as an empty string.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "-C", str(repo_dir), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        if ignore_failure:
            return ""
        raise _GitError(f"git {args[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        if ignore_failure:
            return ""
        raise _GitError(f"git could not be executed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        if ignore_failure:
            return ""
        tail = (completed.stderr or completed.stdout or "").strip().splitlines()
        raise _GitError(tail[-1] if tail else f"git {args[0]} exited {completed.returncode}")
    return completed.stdout or ""


def _prepare_repo(repo_dir: Path, repo: str) -> None:
    """A repository with one remote, created once and reused across runs.

    The `remote add` is best-effort and idempotent: a cache directory that
    already has the remote is the normal case, and failing on `remote origin
    already exists` would make every run after the first one fail.
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    if not (repo_dir / ".git").is_dir():
        _git_init(repo_dir)
    _git(repo_dir, ["remote", "get-url", "origin"], ignore_failure=True) or _git(
        repo_dir, ["remote", "add", "origin", f"https://github.com/{repo}"]
    )


def _git_init(repo_dir: Path) -> None:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "init", "-q", str(repo_dir)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except OSError as exc:
        raise _GitError(f"git init failed: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        tail = (completed.stderr or "").strip().splitlines()
        raise _GitError(tail[-1] if tail else "git init failed")


def _git_version() -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["git", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except OSError:
        return ""
    return completed.stdout.strip() if completed.returncode == 0 else ""


def _fetch(repo_dir: Path, sha: str) -> None:
    """Fetch the fix commit and its first parent, and nothing else.

    `--depth 2 --filter=blob:none` is what makes 19 advisories across 7
    repositories affordable: two commits of history, and blobs fetched on
    demand. A full clone of `django/django` to learn what one commit changed
    would be absurd, and this is the difference between a tier that runs in a
    minute and one nobody runs.
    """
    _git(
        repo_dir,
        ["fetch", "--depth", "2", "--filter=blob:none", "--quiet", "origin", sha],
        timeout=FETCH_TIMEOUT_SECONDS,
    )


def _parents(repo_dir: Path, sha: str) -> list[str]:
    line = _git(repo_dir, ["rev-list", "--parents", "-n", "1", sha]).strip()
    parts = line.split()
    return parts[1:] if parts else []


def _real_fixes(repo_dir: Path, base: str, fix: str) -> list[RealFix]:
    """The before/after content of every source file the fix commit changed."""
    diff = _git(repo_dir, ["diff", "-U0", base, fix])
    changed: list[tuple[str, list[int], int, int]] = []
    current: str | None = None
    lines: list[int] = []
    counter = 0
    added = 0
    removed = 0
    in_hunk = False

    for line in diff.splitlines():
        if line.startswith("diff --git "):
            if current is not None:
                changed.append((current, lines, added, removed))
            current, lines, added, removed, in_hunk = None, [], 0, 0, False
            continue
        if line.startswith("--- ") or line.startswith("+++ "):
            if line.startswith("+++ ") and line[4:].strip() not in ("/dev/null", ""):
                current = line[4:].strip().removeprefix("b/")
            continue
        hunk = _HUNK.match(line)
        if hunk:
            in_hunk = True
            counter = int(hunk.group(1))
            before_span = int(hunk.group(2) or 1)
            if before_span == 0:
                # Pure insertion. There is no removed line to compare against, so
                # the comparison point is the line the content went in *before* --
                # which is exactly the line a fix like "strip the header here"
                # touches, and without it a pure-addition fix looks like it
                # agreed with nothing at all.
                lines.append(counter)
            continue
        if not in_hunk:
            continue
        if line.startswith("-"):
            lines.append(counter)
            counter += 1
            removed += 1
        elif line.startswith("+"):
            added += 1
        elif line.startswith(" "):
            counter += 1
    if current is not None:
        changed.append((current, lines, added, removed))

    results: list[RealFix] = []
    for path, touched, added_count, removed_count in changed:
        if not path.endswith((".py", ".go")) or _is_not_source(path):
            continue
        before = _git(repo_dir, ["show", f"{base}:{path}"])
        after = _git(repo_dir, ["show", f"{fix}:{path}"])
        results.append(
            RealFix(
                path=path,
                before=before,
                after=after,
                lines_changed=tuple(sorted(set(touched))),
                added_lines=added_count,
                removed_lines=removed_count,
            )
        )
    return results


# Paths a security rewrite is not meant to touch. Excluded because they are not
# vulnerable code, and because including them would quietly inflate both the
# coverage figure and the "would our reviewer reject a real fix" count with test
# files -- a fix that rewrites a test is not a fix to the vulnerability, and
# counting it as one would flatter the number.
#
# Matched on *path components* and on the file's own name, not on substrings. A
# substring rule for `"test/"` misses celery's `t/unit/backends/test_base.py`,
# because celery's test directory is `t/` and its files are named `test_*.py` --
# which is exactly the kind of miss that makes a count quietly wrong rather than
# obviously wrong.
_NOT_SOURCE_DIRS = frozenset(
    {
        "test",
        "tests",
        "testing",
        "t",
        "docs",
        "doc",
        "examples",
        "example",
        "benchmarks",
        "vendor",
        "third_party",
        "node_modules",
    }
)

_NOT_SOURCE_FILES = frozenset({"conftest.py", "setup.py", "noxfile.py", "tox.ini"})


def _is_not_source(path: str) -> bool:
    """Whether `path` is a test, doc, example or vendored file rather than source."""
    lowered = path.lower()
    parts = lowered.split("/")
    if set(parts[:-1]) & _NOT_SOURCE_DIRS:
        return True
    name = parts[-1]
    if name in _NOT_SOURCE_FILES:
        return True
    return name.startswith("test_") or name.endswith("_test.py")


def _assess(
    developer: DeterministicDeveloper,
    reviewer: DeterministicReviewer,
    advisory: Advisory,
    fix: RealFix,
    root: Path,
) -> FileOutcome:
    """Point the engine at one real vulnerable file and record what it did."""
    outcome = FileOutcome(
        path=fix.path,
        cwe=",".join(advisory.cwe_ids),
        real_lines=fix.lines_changed,
        added_lines=fix.added_lines,
        removed_lines=fix.removed_lines,
    )

    # Two verdicts, not one, and the second is the honest comparison.
    #
    # The reviewer checks that every removed line appears in the reported
    # snippet. Before `enrich_snippet` the loop was given the one line the
    # scanner reported, so `scoped` failed by construction on any multi-line fix
    # and the rejection rate was an artefact of the harness as much as a fact
    # about the reviewer. Reporting only that number as "30% of real fixes would
    # be rejected" would be presenting a test setup as a product finding.
    #
    # So: `_first_changed_line` is what the scanner hands over, and `_enrich` is
    # the same fix judged with the snippet production now builds. The gap between
    # them is the finding -- it says how much the snippet's richness is worth,
    # which is not knowable from either number alone.
    real_patch = _synthesise_patch(fix)
    production = reviewer.review(
        patch=real_patch,
        snippet=_first_changed_line(fix),
        file_path=fix.path,
        rule_id=advisory.advisory,
        round_index=1,
    )
    # What the *shipped* behaviour now is: `enrich_snippet` on the real bytes.
    # Without this second measurement the report would keep printing 9 of 30
    # forever while production quietly stopped doing that -- which is the drift
    # this tier exists to catch, applied to itself.
    widened = _enrich(fix, root)
    contextual = reviewer.review(
        patch=real_patch,
        snippet=widened.text,
        file_path=fix.path,
        rule_id=advisory.advisory,
        round_index=1,
    )
    outcome.real_fix_would_pass = production.decision.name == "APPROVE"
    outcome.real_fix_would_pass_with_context = contextual.decision.name == "APPROVE"
    outcome.context_lines = widened.line_count
    outcome.snippet_strategy = widened.strategy.value
    outcome.snippet_lines = widened.line_count
    outcome.real_fix_comments = _comments(production)
    outcome.real_fix_comments_with_context = _comments(contextual)

    candidates = _candidate_lines(fix.before, fix.path)
    if not candidates:
        outcome.our_decision = "no-candidate-line"
        outcome.notes.append("no line in the vulnerable file matches any of the six rewrites")
        return outcome

    # One candidate is enough: the first line any rule can bite on, which is the
    # line upstream most likely also touched. Using all of them would count one
    # advisory several times and inflate the coverage figure.
    line_number, line_text, rule = candidates[0]
    outcome.our_line = line_number
    outcome.our_rewrite = rule.name
    turn = developer.develop(
        snippet=line_text,
        file_path=fix.path,
        rule_id=rule.rule_hints[0],
        cwe_ids=sorted(rule.cwes),
        feedback=[],
        round_index=1,
    )
    outcome.our_decision = turn.decision.name
    if turn.decision.name != "PROPOSE" or not turn.patch:
        outcome.notes.append(turn.summary)
        return outcome

    application = apply_patch(fix.before, turn.patch, anchor_line=line_number)
    if not application.applied:
        outcome.notes.append(f"the patch did not apply to the real file: {application.reason}")
        outcome.our_decision = "patch-did-not-apply"
        return outcome

    outcome.our_added_lines = application.added_count
    outcome.same_line_as_upstream = line_number in fix.lines_changed
    if not outcome.same_line_as_upstream:
        outcome.notes.append(
            f"our patch landed on line {line_number}; upstream changed "
            f"{_summarise_lines(fix.lines_changed)}"
        )

    verdict = reviewer.review(
        patch=turn.patch,
        snippet=line_text,
        file_path=fix.path,
        rule_id=rule.rule_hints[0],
        round_index=1,
    )
    outcome.reviewer_verdict = verdict.decision.name
    outcome.reviewer_comments = tuple(
        line[2:] for line in verdict.message.splitlines() if line.startswith("- ")
    )
    return outcome


def _candidate_lines(text: str, file_path: str) -> list[tuple[int, str, Any]]:
    """Every line the rule table can act on, in file order."""
    found: list[tuple[int, str, Any]] = []
    for index, line in enumerate(text.splitlines(), start=1):
        for rule in _REWRITES:
            if rule.pattern.search(line) and rule.applies_to_language(file_path):
                found.append((index, line, rule))
                break
    return found


def _enrich(fix: RealFix, root: Path) -> Any:
    """The shipped `enrich_snippet`, run against this file's real content.

    The vulnerable content is written to `root` and the production function is
    called on it, rather than reimplementing the block-walk here. A second copy of
    the rule would be a second thing to be wrong, and this tier's whole value is
    that it measures the shipped code -- `RemediationService._widen_snippet` calls
    exactly this function on exactly these bytes.

    **Anchored on the first changed line only.** An earlier version passed
    `min(lines_changed)..max(lines_changed)`, which is not a finding at all -- it
    is the whole diff, and it spans several functions in most of this corpus. That
    produced a nonsense "block" running from one function's header to a later
    function's end, and a 21-line `context-window` that came out at 88 lines. A
    scanner reports the lines its pattern matched, which for these rules is one
    line, so one line is what the anchor has to be.
    """
    from backend.scanners.snippet import enrich_snippet  # noqa: PLC0415

    target = root / fix.path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(fix.before, encoding="utf-8")
    first = min(fix.lines_changed) if fix.lines_changed else None
    return enrich_snippet(
        file_path=fix.path,
        reported=_first_changed_line(fix),
        start_line=first,
        end_line=first,
        max_lines=_SNIPPET_MAX_LINES,
        root=root,
    )


def _comments(verdict: AgentTurn) -> tuple[str, ...]:
    """The reviewer's objections, in order, as clean text.

    Takes a verdict rather than re-running the review, because classifying a
    rejection needs the *same* verdict that produced the rejection. Reading the
    comments off a second, differently-configured run attributed objections the
    reviewer never made.
    """
    return tuple(line[2:].strip() for line in verdict.message.splitlines() if line.startswith("- "))


def _first_changed_line(fix: RealFix) -> str:
    """What a scanner actually hands the reviewer: one line.

    Semgrep's `extra.lines` is one line for a single-line pattern match, so this
    is the production input, not a simplification of it. Recorded as such because
    judging an 18-line fix against it and reporting the result as a fact about the
    reviewer would be measuring the harness.
    """
    lines = fix.before.splitlines()
    if fix.lines_changed:
        return lines[fix.lines_changed[0] - 1]
    return lines[0] if lines else ""


def _synthesise_patch(fix: RealFix) -> str:
    """Render upstream's own diff in the shape our reviewer reads.

    Built from the before/after *content* rather than from git's diff output,
    because the reviewer's parser expects `+`/`-` lines and git's includes
    headers and hunk markers it does not strip. Same reasoning as
    `backend/agents/deterministic.py::_unified_diff`.
    """
    import difflib

    before = fix.before if fix.before.endswith("\n") else fix.before + "\n"
    after = fix.after if fix.after.endswith("\n") else fix.after + "\n"
    body = "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile=f"a/{fix.path}",
            tofile=f"b/{fix.path}",
            n=3,
        )
    )
    return f"### upstream fix (SentinelMCP evidence tier 3)\n### target: {fix.path}\n\n{body}"


def _summarise_lines(lines: tuple[int, ...]) -> str:
    if not lines:
        return "nothing"
    if len(lines) == 1:
        return f"line {lines[0]}"
    return f"{len(lines)} lines ({lines[0]}-{lines[-1]})"
