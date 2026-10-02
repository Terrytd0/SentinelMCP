"""Tier 2: does an *independent* detector stop reporting the vulnerability?

Tier 1 asks whether the exploit stops working. This tier asks a different
question that Tier 1 cannot: does a static analyser whose rules this project did
not write stop reporting the finding? That catches the failure mode Tier 1
cannot see on its own -- a patch that stops the exploit in the one way this
harness happens to test, while the pattern is still there for every other tool
in the estate.

The detector is Semgrep, run over `data/samples/vulnerable_app/`, which is real
source with real vulnerabilities in it. The rules are Semgrep's, from pinned
registry configurations.

## The vacuity guard, and why it is not optional

**`semgrep --config <a URL that is not a rule> --json` exits 0 and reports
zero findings.** There is no error, no warning, no non-zero status. A rule id
that does not exist is indistinguishable from a clean scan.

That was not theoretical: while building this, four of eleven guessed rule ids
resolved to nothing and reported "0 hits" in exactly the way a *fixed*
vulnerability would. A harness built on that assumption would have reported a
perfect score for a rule set that never ran.

So this tier asserts two things before it will claim anything:

1. **At least one pinned rule must fire on the unpatched tree.** If nothing
   fires, the whole tier reports `vacuous` and the report says so. A tier that
   cannot prove it looked has not proven anything.
2. **Each finding it credits as fixed must have a rule that fired before.** A
   rule that never fired cannot be "stopped", and counting it as one would pad
   the score with rules that were never applicable.

## Parse errors are results, not noise

`p/secrets` fires on `const StripeSecretKey = "sk_live_..."` in
`data/samples/vulnerable_app/gateway.go`, and the engine's secret rewrite
replaces it with `StripeSecretKey = os.environ["StripeSecretKey"]` -- a Python
expression, in a Go file. Semgrep cannot parse the result.

That is a real finding about the rewrite, and it is why parse errors are
collected and reported rather than discarded: a security rewrite that emits code
in the wrong language breaks every static analyser in the estate, not just this
one. It is the same class of defect as `math-rand-to-crypto-rand` substituting
`secrets.randbelow` into Go, and Tier 2 is what makes it visible.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from backend.agents.deterministic import DeterministicDeveloper, DeterministicReviewer
from backend.evidence.patch_apply import apply_patch
from backend.scanners.semgrep import DEFAULT_TIMEOUT_SECONDS, SemgrepScanner

SAMPLE_TARGET = Path("data/samples/vulnerable_app")

# Registry configurations, pinned by name.
#
# `p/security-audit` and `p/golang` are Semgrep's own packs; the third is a
# single rule fetched by URL, because the SQL-injection rule is not in either
# pack and without it CWE-89 has no independent detector at all. Each was
# verified to resolve *and to fire* on the unpatched sample -- see the module
# docstring for why the second half of that sentence is the part that matters.
#
# Not pinned: `p/golang`'s TLS rules. Several plausible rule ids for
# `InsecureSkipVerify: true` were tried and none of them fired, so CWE-295 has no
# independent detector here. `docs/evidence.md` records that as a coverage gap
# rather than a pass, and Tier 1 records the same rule as not executable. Two
# tiers agreeing that a rule is unverified is a result; one tier quietly
# reporting it as verified would not be.
PINNED_CONFIGS: tuple[str, ...] = (
    "p/security-audit",
    "p/golang",
    "p/secrets",
    "https://semgrep.dev/r/python.lang.security.audit.formatted-sql-query",
)

SEMGREP_EXTRA_ARGS: tuple[str, ...] = (
    # Reproducibility, not taste: without these, a rule pack update changes the
    # numbers in `docs/evidence.md` with no commit to explain the change, and a
    # telemetry call reaches the network on every run.
    "--metrics",
    "off",
    "--disable-version-check",
    "--quiet",
    "--json",
)


@dataclass(slots=True)
class RuleHit:
    """One Semgrep result, reduced to what a comparison needs."""

    check_id: str
    path: str
    line: int
    cwe: str = ""

    @property
    def key(self) -> str:
        return f"{self.check_id}@{self.path}"


@dataclass(slots=True)
class PatchedFile:
    """One file the engine was able to patch, and how."""

    path: str
    line: int
    rewrite: str
    reviewer_verdict: str
    applied: bool
    reason: str = ""


@dataclass(slots=True)
class RuleOutcome:
    """Did a pinned rule stop firing, and what did we start from?"""

    check_id: str
    path: str
    line_before: int
    cwe: str
    stopped_firing: bool
    rewrite: str = ""
    attempted: bool = False
    """The engine proposed a patch on this line."""

    escalated: bool = False
    """The engine recognised the class and declined, e.g. wrong language.

    Kept distinct from `not attempted`. A rule that still fires on a line the
    engine escalated is a *correct* outcome -- the engine declined rather than
    emitting something that would not compile -- and must not be scored as a
    failed fix.
    """

    @property
    def credit(self) -> str:
        """How this outcome should be read. Reported verbatim; never scored twice."""
        if self.stopped_firing and self.attempted:
            return "fixed"
        if self.escalated:
            return "declined-correctly"
        if self.stopped_firing:
            return "stopped-without-a-patch"
        if not self.attempted:
            return "no-rewrite-available"
        return "still-firing"


@dataclass(slots=True)
class Tier2Result:
    runs: bool
    skipped_reason: str = ""
    duration_ms: float = 0.0
    semgrep_version: str = ""
    configs: tuple[str, ...] = PINNED_CONFIGS
    vacuous: bool = False
    hits_before: list[RuleHit] = field(default_factory=list)
    hits_after: list[RuleHit] = field(default_factory=list)
    outcomes: list[RuleOutcome] = field(default_factory=list)
    patched_files: list[PatchedFile] = field(default_factory=list)
    unpatched_lines: list[str] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)

    @property
    def ran(self) -> bool:
        """Alias for `runs`, so all three tier results answer the same question.

        The report asks every tier the same thing and a reader should not have to
        remember which attribute each one spells it with.
        """
        return self.runs

    @property
    def fixed(self) -> list[RuleOutcome]:
        return [o for o in self.outcomes if o.stopped_firing]

    @property
    def still_firing(self) -> list[RuleOutcome]:
        return [o for o in self.outcomes if not o.stopped_firing]

    @property
    def cwes_covered(self) -> set[str]:
        return {o.cwe.split(":")[0].strip() for o in self.outcomes if o.cwe}

    @property
    def cwes_credited(self) -> set[str]:
        return {o.cwe.split(":")[0].strip() for o in self.fixed if o.cwe}


def run_tier_2(
    target: Path = SAMPLE_TARGET,
    *,
    configs: tuple[str, ...] = PINNED_CONFIGS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> Tier2Result:
    """Patch the sample, then ask Semgrep whether the findings went away."""
    started = time.perf_counter()

    scanner = SemgrepScanner()
    binary = scanner.resolved_binary or _binary_beside_the_interpreter()
    if binary is None:
        return Tier2Result(
            runs=False,
            skipped_reason=scanner.unavailable_reason or "semgrep is not installed",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    if not target.is_dir():
        return Tier2Result(
            runs=False,
            skipped_reason=f"the sample target {target} does not exist",
            duration_ms=(time.perf_counter() - started) * 1000.0,
        )

    import tempfile

    with tempfile.TemporaryDirectory(
        prefix="sentinel-evidence-tier2-", ignore_cleanup_errors=True
    ) as raw:
        # Both trees are copies at the *same* depth, so Semgrep reports the same
        # relative path for both and the two runs can be joined on it. Scanning
        # the real `data/samples/` for "before" and a temp copy for "after" would
        # report `app.py` versus `vulnerable_app/app.py`, and every outcome would
        # silently fail to attribute to a rewrite.
        root = Path(raw)
        before_tree = root / "before" / target.name
        after_tree = root / "after" / target.name
        before_tree.parent.mkdir(parents=True, exist_ok=True)
        after_tree.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(target, before_tree)
        shutil.copytree(target, after_tree)

        patched_files, unpatched = _patch_tree(after_tree)

        version = _semgrep_version(binary, timeout_seconds)
        before = _run_semgrep(binary, before_tree, configs, timeout_seconds)
        after = _run_semgrep(binary, after_tree, configs, timeout_seconds)

    result = Tier2Result(
        runs=True,
        duration_ms=(time.perf_counter() - started) * 1000.0,
        semgrep_version=version,
        hits_before=before.hits,
        hits_after=after.hits,
        patched_files=patched_files,
        unpatched_lines=unpatched,
        parse_errors=sorted({*before.parse_errors, *after.parse_errors}),
        fetch_errors=sorted({*before.fetch_errors, *after.fetch_errors}),
    )

    # Guard 1: a rule set that reports nothing on the unpatched tree has not
    # been shown to work, so nothing it says about the patched tree counts.
    if not before.hits:
        result.vacuous = True
        result.outcomes = []
        return result

    # A hit on a line the engine patched is credited to that rewrite. A hit on a
    # line it did not touch -- or escalated -- is a finding the engine correctly
    # did not attempt, and the report says so rather than scoring it either way.
    rewrite_by_location = {(f.path, f.line): f.rewrite for f in patched_files if f.applied}
    attempted = {(f.path, f.line) for f in patched_files}
    escalated = _escalated_locations(unpatched)
    after_keys = {hit.key for hit in after.hits}
    for hit in before.hits:
        location = (hit.path, hit.line)
        result.outcomes.append(
            RuleOutcome(
                check_id=hit.check_id,
                path=hit.path,
                line_before=hit.line,
                cwe=hit.cwe,
                stopped_firing=hit.key not in after_keys,
                rewrite=rewrite_by_location.get(location, ""),
                attempted=location in attempted,
                escalated=location in escalated,
            )
        )
    return result


@dataclass(slots=True)
class _ScanOutput:
    hits: list[RuleHit] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    fetch_errors: list[str] = field(default_factory=list)


def _binary_beside_the_interpreter() -> str | None:
    """Semgrep from the virtualenv this process is running in, if it is there.

    `SemgrepScanner` resolves against `PATH`, which is the right answer for a
    deployed process. It is the wrong answer for a developer who ran
    `.venv\\Scripts\\python -m pytest` in a shell where the venv was never
    activated -- which is the documented way to run this project's suite on
    plain Windows (`CLAUDE.md`, README), and therefore how this harness is
    usually run.

    Only a *fallback*, and only here. Deliberately not in `SemgrepScanner`:
    making the production scanner look available because a venv happens to have
    Semgrep installed would change what `Health.available_scanners` reports, and
    a capability report that overstates itself is the thing this project has
    spent its whole effort avoiding.
    """
    candidate = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if candidate.is_file():
        return str(candidate)
    return None


def _escalated_locations(notes: list[str]) -> set[tuple[str, int]]:
    """`(path, line)` pairs the engine recognised and declined.

    Parsed back out of the human-readable note list rather than carried
    separately, because a second record of the same fact is a second thing that
    can drift. The line number is coerced: the note is a string and the hit is
    an int, and comparing them unequal would silently mark every escalation as
    un-attempted.
    """
    locations: set[tuple[str, int]] = set()
    for note in notes:
        head = note.split()[0] if note.split() else ""
        if " -> ESCALATE" not in note or ":" not in head:
            continue
        path, _, line = head.rpartition(":")
        if path and line.isdigit():
            locations.add((path, int(line)))
    return locations


def _run_semgrep(
    binary: str, target: Path, configs: tuple[str, ...], timeout_seconds: int
) -> _ScanOutput:
    """Run Semgrep over `target` with every pinned config in one pass."""
    command = [binary, *SEMGREP_EXTRA_ARGS]
    for config in configs:
        command += ["--config", config]
    command.append(str(target))

    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            command, capture_output=True, text=True, timeout=timeout_seconds, check=False
        )
    except subprocess.TimeoutExpired:
        return _ScanOutput(fetch_errors=[f"semgrep timed out after {timeout_seconds}s"])
    except OSError as exc:
        return _ScanOutput(fetch_errors=[f"semgrep could not be executed: {type(exc).__name__}"])

    if not completed.stdout.strip():
        tail = (completed.stderr or "").strip().splitlines()
        return _ScanOutput(
            fetch_errors=[tail[-1] if tail else f"semgrep exited {completed.returncode}"]
        )

    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return _ScanOutput(fetch_errors=["semgrep output was not valid JSON"])

    return _ScanOutput(
        hits=[hit for hit in (_map_hit(r, target) for r in document.get("results", [])) if hit],
        parse_errors=[
            str(e.get("long_msg") or e.get("short_msg") or e)[:300]
            for e in document.get("errors", [])
            if isinstance(e, dict) and e.get("type") in ("SyntaxError", "SemgrepError", "Fatal")
        ],
    )


def _map_hit(record: dict[str, Any], base: Path) -> RuleHit | None:
    if not isinstance(record, dict):
        return None
    check_id = record.get("check_id")
    raw_path = record.get("path")
    if not isinstance(check_id, str) or not isinstance(raw_path, str):
        return None
    start = record.get("start") or {}
    metadata = (record.get("extra") or {}).get("metadata") or {}
    cwe = metadata.get("cwe")
    cwe_text = cwe if isinstance(cwe, str) else (cwe[0] if isinstance(cwe, list) and cwe else "")
    try:
        relative = Path(raw_path).resolve().relative_to(base.resolve()).as_posix()
    except (ValueError, OSError):
        relative = Path(raw_path).as_posix()
    return RuleHit(
        check_id=check_id,
        path=relative,
        line=int(start.get("line", 0)) if isinstance(start, dict) else 0,
        cwe=str(cwe_text)[:80],
    )


def _semgrep_version(binary: str, timeout_seconds: int) -> str:
    """The Semgrep version, for the report.

    Recorded because the rule packs are third-party and versioned: without this,
    a changed number cannot be attributed to anything.
    """
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [binary, "--version"], capture_output=True, text=True, timeout=60, check=False
        )
    except (subprocess.TimeoutExpired, OSError):
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _patch_tree(tree: Path) -> tuple[list[PatchedFile], list[str]]:
    """Run the real loop over every source line and apply what it proposes.

    A finding is synthesised per line, because the pipeline's finding source here
    is a *directory of sample code* rather than a scanned repository, and because
    the question this tier asks -- "does the pattern survive" -- is a question
    about lines, not about scanner bookkeeping. The synthetic `rule_id` is the
    rewrite's own first hint, which is the same string the pipeline would have
    matched on a real finding.
    """
    developer = DeterministicDeveloper()
    reviewer = DeterministicReviewer(developer._rules)  # noqa: SLF001 - same table
    patched: list[PatchedFile] = []
    unpatched: list[str] = []

    for path in sorted(tree.rglob("*")):
        if not path.is_file() or path.suffix not in {".py", ".go", ".ts", ".js"}:
            continue
        # Relative to the scan root, because that is how Semgrep reports it and
        # the two have to be joinable to attribute an outcome to a rewrite.
        relative = path.relative_to(tree).as_posix()
        text = path.read_text(encoding="utf-8")
        for index, line in enumerate(text.splitlines(), start=1):
            for rule in developer._rules:  # noqa: SLF001 - the table is the point
                if not (rule.pattern.search(line) and rule.applies_to(rule.rule_hints[0], [])):
                    continue
                turn = developer.develop(
                    snippet=line,
                    file_path=relative,
                    rule_id=rule.rule_hints[0],
                    cwe_ids=sorted(rule.cwes),
                    feedback=[],
                    round_index=1,
                )
                if turn.decision.name != "PROPOSE" or not turn.patch:
                    unpatched.append(
                        f"{relative}:{index} {rule.name} -> {turn.decision.name}"
                        f"{': ' + turn.message if turn.message else ''}"
                    )
                    break
                verdict = reviewer.review(
                    patch=turn.patch,
                    snippet=line,
                    file_path=relative,
                    rule_id=rule.rule_hints[0],
                    round_index=1,
                )
                application = apply_patch(text, turn.patch, anchor_line=index)
                if not application.applied:
                    unpatched.append(f"{relative}:{index} {rule.name}: {application.reason}")
                    break
                text = application.text
                path.write_text(text, encoding="utf-8")
                patched.append(
                    PatchedFile(
                        path=relative,
                        line=index,
                        rewrite=rule.name,
                        reviewer_verdict=verdict.decision.name,
                        applied=True,
                    )
                )
                break
    return patched, unpatched
