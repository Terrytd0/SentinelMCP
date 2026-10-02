"""Render the three tiers as one report, in text and in Markdown.

## Why the headline is not a pass rate

A security tool that reports "92% of patches verified" is claiming a number it
cannot support, because the denominators are chosen by the thing being measured.
The rule table is seven rewrites; the Tier 1 cases are eight, six of which were
written *about* the rules they test; the Tier 3 corpus is 19 advisories the
project picked. Every one of those denominators is flattering by construction.

So the report leads with what each tier *could not* check, and the counts of
patches that are incomplete, that regress the function, that needed a human step
to run at all, and that no tier covers. Those are the numbers that are hard to
fake, and they are the ones a reviewer should read first.

The report is a `str` for the terminal and a `str` for the file, from one
structure, so the two cannot disagree. A report that is generated twice by two
code paths is a report that eventually disagrees with itself in public.
"""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass, field
from typing import Any

from backend.evidence.tier1 import TierResult as Tier1Result
from backend.evidence.tier2 import Tier2Result
from backend.evidence.tier3 import Tier3Result

# Findings the evidence tiers are known *not* to cover. Printed unconditionally,
# never derived from a run, because the set of known blind spots is a property of
# the rule table and does not change when a run happens to go well.
KNOWN_GAPS: tuple[str, ...] = (
    "CWE-295 (TLS verification) has no execution coverage here -- the rewrite is "
    "Go-only and there is no Go toolchain -- and no pinned Semgrep rule was found "
    "that fires on `InsecureSkipVerify: true`. Tier 1 and Tier 2 independently "
    "record it as unverified.",
    "CWE-200 (credential forwarded across a redirect) is verifiable only by "
    "execution. No static analyser flags `allow_redirects=True`; it is a library "
    "behaviour, not a pattern. Tier 1 covers it with two real HTTP servers.",
    "CWE-338 (weak randomness) has no rewrite. The rule that used to claim it "
    "emitted a Python name into a Go file, and `math/rand.Int` and `crypto/rand.Int` "
    "have incompatible signatures, so it was removed rather than patched. These "
    "findings escalate to a human.",
    "CWE-489 (debug mode), CWE-1336 (server-side template injection), CWE-190 "
    "(integer overflow), CWE-352 and CWE-319 in `data/fixtures/` all have no "
    "rewrite. Escalating is the correct behaviour and is what the engine does.",
    "No tier can see a vulnerability whose vulnerable line is not a single line "
    "the rule table matches. Tier 3 measures how often that is, and the answer "
    "is most of the time.",
)


@dataclass(slots=True)
class EvidenceReport:
    """The whole run, renderable two ways."""

    tier1: Tier1Result | None = None
    tier2: Tier2Result | None = None
    tier3: Tier3Result | None = None
    environment: dict[str, str] = field(default_factory=dict)

    @property
    def tiers_ran(self) -> int:
        return sum(1 for t in (self.tier1, self.tier2, self.tier3) if t is not None and t.ran)

    @property
    def _rule_count(self) -> int:
        from backend.agents.deterministic import _REWRITES  # noqa: PLC0415

        return len(_REWRITES)

    @property
    def _tier1_case_count(self) -> int:
        return len(self.tier1.cases) if self.tier1 else 0

    @property
    def _advisory_count(self) -> int:
        return len(self.tier3.manifest) if self.tier3 else 0

    @property
    def headline_failures(self) -> list[str]:
        """Anything a reader must not miss. Empty is a claim too, so it is earned."""
        problems: list[str] = []
        if self.tier1 and self.tier1.ran:
            for case in self.tier1.failed:
                problems.append(f"tier 1: {case.name} -- {case.detail}")
        if self.tier2 and self.tier2.runs and self.tier2.vacuous:
            problems.append(
                "tier 2: vacuous -- no pinned rule fired on the unpatched sample, so the "
                "rule set cannot be shown to work and nothing it reported counts"
            )
        if self.tier3 and self.tier3.runs:
            fetch_failures = [o for o in self.tier3.outcomes if o.status == "fetch-failed"]
            if fetch_failures:
                problems.append(
                    f"tier 3: {len(fetch_failures)} advisory(ies) could not be fetched and "
                    "are absent from every count below"
                )
        return problems

    def to_text(self) -> str:
        lines: list[str] = []
        add = lines.append
        add("SentinelMCP -- measured evidence about the remediation engine")
        add("=" * 70)
        add("")
        for key, value in self.environment.items():
            add(f"  {key:<22} {value}")
        add("")

        failures = self.headline_failures
        if failures:
            add("READ THIS FIRST")
            add("-" * 70)
            for problem in failures:
                add(f"  ! {problem}")
            add("")

        add(_render_tier1(self.tier1))
        add(_render_tier2(self.tier2))
        add(_render_tier3(self.tier3))
        add(_render_gaps())
        add("")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        lines: list[str] = []
        add = lines.append
        add("# Measured evidence: does the remediation engine actually fix things?")
        add("")
        add(
            "> **This is a generated snapshot.** Produced by "
            "`python scripts/evidence_report.py --all --markdown`, not written by "
            "hand. Regenerate it rather than editing it, and treat a number here that "
            "disagrees with a fresh run as a question about the engine, not about the "
            "file."
        )
        add("")
        add(
            "Every number below is produced by running the engine, not by asserting on "
            "its output. Read [how to read this](#how-to-read-this) and "
            "[known blind spots](#known-blind-spots) before the numbers. The "
            "narrative version, including what the tiers found and why the gates are "
            "shaped the way they are, is in [evidence.md](evidence.md)."
        )
        add("")
        add("## How to read this")
        add("")
        add(
            "There is deliberately **no single pass rate**. Every denominator available "
            f"here -- {self._rule_count} rewrites in the rule table, "
            f"{self._tier1_case_count} hand-written execution cases, "
            f"{self._advisory_count} advisories this project chose -- is flattering by "
            "construction, and a percentage built on one of them would be a claim the "
            "evidence does not support."
        )
        add("")
        add("| tier | question | whose answer |")
        add("| --- | --- | --- |")
        add("| 1 execution | does the patch stop a real exploit? | ours, by running it |")
        add("| 2 static | does an independent detector stop reporting it? | Semgrep's |")
        add("| 3 corpus | what happens on real CVEs and real upstream fixes? | upstream's |")
        add("")
        add("## The run")
        add("")
        add("| | |")
        add("| --- | --- |")
        for key, value in self.environment.items():
            add(f"| {key} | `{value}` |")
        add(f"| tiers run | {self.tiers_ran} of 3 |")
        failures = self.headline_failures
        add(f"| things a reader must not miss | {len(failures)} |")
        add("")

        if self.tier1:
            add(_tier1_markdown(self.tier1))
        if self.tier2:
            add(_tier2_markdown(self.tier2))
        if self.tier3:
            add(_tier3_markdown(self.tier3))
        add(_gaps_markdown())
        return "\n".join(lines) + "\n"


def default_environment() -> dict[str, str]:
    return {
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
    }


# --------------------------------------------------------------------------
# Tier 1
# --------------------------------------------------------------------------


def _tier1_numbers(result: Tier1Result) -> dict[str, Any]:
    measured = result.measured
    blocked = [c for c in measured if c.exploit_after is False]
    return {
        "cases": len(result.cases),
        "measured": len(measured),
        "skipped": len(result.cases) - len(measured),
        "passed": len(result.passed),
        "failed": len(result.failed),
        "exploit_blocked": len(blocked),
        "behaviour_regressed": len(result.regressed),
        "human_steps": result.human_steps,
        "reviewer_approved": sum(1 for c in measured if c.reviewer_verdict == "APPROVE"),
    }


def _render_tier1(result: Tier1Result | None) -> str:
    lines: list[str] = ["TIER 1  execution -- does the patch stop a real exploit?", "-" * 70]
    if result is None:
        lines.append("  not run")
        return "\n".join(lines)
    if not result.ran:
        lines.append(f"  SKIPPED: {result.skipped_reason}")
        return "\n".join(lines)

    n = _tier1_numbers(result)
    lines.append(
        f"  {n['measured']} of {n['cases']} cases measurable ({n['skipped']} declared "
        f"skipped)   {n['passed']} passed, {n['failed']} failed   {result.duration_ms:.0f}ms"
    )
    lines.append(
        f"  exploit blocked: {n['exploit_blocked']}   behaviour regressed: "
        f"{n['behaviour_regressed']}   needed a human step to run: {n['human_steps']}"
    )
    lines.append(
        f"  the deterministic reviewer approved {n['reviewer_approved']} of these. "
        "Approval is not evidence of a fix; it is evidence of three structural checks."
    )
    lines.append("")
    for case in result.cases:
        if case.status == "skipped":
            lines.append(f"  [skip] {case.name} ({', '.join(case.cwe_ids)})")
            lines.append(f"         {case.detail[:150]}")
            continue
        verdict = {
            "blocks-exploit": "exploit blocked",
            "regresses": "exploit blocked, function regressed",
        }.get(case.expected_behaviour, case.expected_behaviour)
        mark = "ok  " if case.status == "ok" else "FAIL"
        lines.append(f"  [{mark}] {case.name} ({', '.join(case.cwe_ids)}) -- {verdict}")
        if case.status == "failed":
            lines.append(f"         {case.detail[:200]}")
        if case.human_steps:
            for step in case.human_steps:
                lines.append(f"         human step: {step[:100]}")
        if case.reviewer_comments:
            for comment in case.reviewer_comments:
                lines.append(f"         reviewer: {comment[:100]}")
        for key in (
            "selects_the_same_rows",
            "renders_as_documented",
            "fails_closed_without_the_env_var",
        ):
            if key in case.extras:
                lines.append(f"         {key}: {str(case.extras[key])[:120]}")
    return "\n".join(lines)


def _tier1_markdown(result: Tier1Result) -> str:
    n = _tier1_numbers(result)
    if not result.ran:
        return f"## Tier 1: execution\n\n**Skipped.** {result.skipped_reason}\n"

    lines = ["## Tier 1: execution", ""]
    lines.append(
        f"{n['measured']} of {n['cases']} cases measurable, {n['skipped']} declared "
        f"skipped with a reason. **{n['passed']} passed, {n['failed']} failed.** "
        f"Exploit blocked in {n['exploit_blocked']}, behaviour regressed in "
        f"{n['behaviour_regressed']}, {n['human_steps']} needed a declared human step "
        f"before the patched module would run at all."
    )
    lines.append("")
    lines.append(
        f"> The deterministic reviewer approved **{n['reviewer_approved']}** of these "
        "patches. That is the point of the tier: the reviewer's approval is not "
        "evidence that a patch fixes anything, and only execution distinguishes the "
        "two."
    )
    lines.append("")
    lines.append("| case | CWE | outcome | reviewer | human steps needed |")
    lines.append("| --- | --- | --- | --- | --- |")
    for case in result.cases:
        if case.status == "skipped":
            lines.append(
                f"| `{case.name}` | {', '.join(case.cwe_ids)} | _skipped: "
                f"{case.detail.split('.')[0]}_ | not reached | 0 |"
            )
            continue
        outcome = {
            "blocks-exploit": "exploit blocked, behaviour preserved",
            "regresses": "exploit blocked, **behaviour regressed**",
        }.get(case.expected_behaviour, case.expected_behaviour)
        if case.status == "failed":
            outcome = f"**FAILED: {case.detail.split('.')[0]}**"
        lines.append(
            f"| `{case.name}` | {', '.join(case.cwe_ids)} | {outcome} | "
            f"{case.reviewer_verdict} | {case.human_step_count} |"
        )
    lines.append("")
    notable = [c for c in result.measured if c.extras.get("selects_the_same_rows") is not None]
    for case in notable:
        lines.append(
            f"**`{case.name}`, on the statement itself:** the rewrite emits "
            f"`{str(case.extras.get('statement'))[:90]}`, which binds as the note "
            f"instructs to `{str(case.extras.get('renders_as_documented'))[:90]}`, and "
            f"selects the same rows as the original query: "
            f"`{case.extras.get('selects_the_same_rows')}`. The statement is never "
            "executed as emitted -- the rewrite leaves `execute(sql = ...)`, which is a "
            "`TypeError`, because writing the bind call is the human's job."
        )
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Tier 2
# --------------------------------------------------------------------------


def _render_tier2(result: Tier2Result | None) -> str:
    lines: list[str] = ["", "TIER 2  static analysis -- does Semgrep stop reporting it?", "-" * 70]
    if result is None:
        lines.append("  not run")
        return "\n".join(lines)
    if not result.runs:
        lines.append(f"  SKIPPED: {result.skipped_reason}")
        return "\n".join(lines)
    if result.vacuous:
        lines.append("  VACUOUS: no pinned rule fired on the unpatched sample.")
        lines.append("  Nothing below counts. See the module docstring for why this matters.")
        return "\n".join(lines)

    lines.append(
        f"  semgrep {result.semgrep_version}   {len(result.hits_before)} findings before, "
        f"{len(result.hits_after)} after   {result.duration_ms:.0f}ms"
    )
    lines.append(f"  rules: {', '.join(result.configs)}")
    lines.append("")
    for outcome in result.outcomes:
        lines.append(
            f"  {outcome.credit:24s} {outcome.check_id:58s} {outcome.path}:{outcome.line_before}"
        )
        if outcome.rewrite:
            lines.append(f"  {'':24s} via {outcome.rewrite}")
    if result.unpatched_lines:
        lines.append("")
        lines.append("  declined, by design:")
        for note in result.unpatched_lines:
            lines.append(f"    {note[:120]}")
    if result.parse_errors:
        lines.append("")
        lines.append("  semgrep parse errors (a patch that broke the file for the analyser):")
        for error in result.parse_errors:
            lines.append(f"    {error[:140]}")
    return "\n".join(lines)


def _tier2_markdown(result: Tier2Result) -> str:
    if not result.runs:
        return f"## Tier 2: static analysis\n\n**Skipped.** {result.skipped_reason}\n"
    if result.vacuous:
        return (
            "## Tier 2: static analysis\n\n**Vacuous.** No pinned rule fired on the "
            "unpatched sample, so the rule set cannot be shown to work and no result "
            "from it is reported. A `--config` URL that is not a rule exits 0 and "
            "reports nothing, so this guard is load-bearing, not decoration.\n"
        )

    by_credit: dict[str, list[Any]] = {}
    for outcome in result.outcomes:
        by_credit.setdefault(outcome.credit, []).append(outcome)

    lines = ["## Tier 2: static analysis", ""]
    lines.append(
        f"Semgrep `{result.semgrep_version}`, pinned rules "
        f"(`{'`, `'.join(result.configs)}`). "
        f"**{len(result.hits_before)} findings before, {len(result.hits_after)} after.**"
    )
    lines.append("")
    lines.append("| outcome | n | meaning |")
    lines.append("| --- | --- | --- |")
    meanings = {
        "fixed": "we patched the line, and the rule stopped firing",
        "declined-correctly": "we recognised the class and refused, e.g. the fix would not compile",
        "no-rewrite-available": "no rule covers this class, so the engine escalated",
        "stopped-without-a-patch": "the rule stopped firing but we produced no patch",
        "still-firing": "we patched the line and the rule still fires",
    }
    for credit, items in sorted(by_credit.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"| `{credit}` | {len(items)} | {meanings.get(credit, '')} |")
    lines.append("")
    lines.append("| rule | location | CWE | rewrite | outcome |")
    lines.append("| --- | --- | --- | --- | --- |")
    for outcome in result.outcomes:
        lines.append(
            f"| `{outcome.check_id}` | `{outcome.path}:{outcome.line_before}` | "
            f"{outcome.cwe.split(':')[0]} | `{outcome.rewrite or '--'}` | "
            f"{outcome.credit} |"
        )
    lines.append("")
    lines.append(
        f"Credited CWE classes: "
        f"{', '.join(f'`{c}`' for c in sorted(result.cwes_credited)) or 'none'}."
    )
    lines.append("")
    if result.unpatched_lines:
        lines.append("Declined, with the reason:")
        lines.append("")
        for note in result.unpatched_lines:
            lines.append(f"- `{note}`")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Tier 3
# --------------------------------------------------------------------------


def _tier3_numbers(result: Tier3Result) -> dict[str, Any]:
    files = result.files_examined
    engaged = [f for o in result.measured for f in o.engaged]
    no_candidate = [f for o in result.measured for f in o.no_candidate]
    reviewed = result.real_fixes_reviewed
    with_context = result.real_fixes_rejected_with_context
    snippet_lines = [f.snippet_lines for f in reviewed if f.snippet_lines]
    return {
        "advisories": len(result.manifest),
        "measured": len(result.measured),
        "fetch_failed": sum(1 for o in result.outcomes if o.status == "fetch-failed"),
        "no_changes": sum(1 for o in result.outcomes if o.status == "no-changes"),
        "files": len(files),
        "engaged": len(engaged),
        "declined": sum(1 for o in result.measured for f in o.declined),
        "no_candidate": len(no_candidate),
        "agreements": result.line_agreements,
        "real_reviewed": len(reviewed),
        "real_rejected": len(result.real_fixes_rejected),
        "real_rejected_with_context": len(with_context),
        "snippet_lines": sum(snippet_lines) // len(snippet_lines) if snippet_lines else 0,
        "snippet_strategies": ", ".join(
            sorted({f.snippet_strategy for f in reviewed if f.snippet_strategy})
        )
        or "n/a",
    }


def _render_tier3(result: Tier3Result | None) -> str:
    lines: list[str] = ["", "TIER 3  real CVEs -- what happens on upstream's own fixes?", "-" * 70]
    if result is None:
        lines.append("  not run")
        return "\n".join(lines)
    if not result.runs:
        lines.append(f"  SKIPPED: {result.skipped_reason}")
        return "\n".join(lines)

    n = _tier3_numbers(result)
    lines.append(
        f"  {n['advisories']} advisories in the manifest, {n['measured']} fetched, "
        f"{n['files']} real source files   {result.duration_ms / 1000:.1f}s"
    )
    if n["fetch_failed"]:
        lines.append(f"  ! {n['fetch_failed']} fetch failures -- these are absent from every count")
    lines.append(
        f"  rules engaged on: {n['engaged']} of {n['files']} files "
        f"({100 * n['engaged'] // max(n['files'], 1)}%). "
        f"NO CANDIDATE LINE: {n['no_candidate']}."
    )
    lines.append(
        f"  of the {n['engaged']} patches, {n['agreements']} landed on a line upstream "
        "also changed."
    )
    lines.append("")
    lines.append(
        f"  THE NUMBER THAT MATTERS MOST: run through our own reviewer, "
        f"{n['real_rejected']} of {n['real_reviewed']} real, merged, human-reviewed "
        f"security fixes would be REJECTED on the one line a scanner reports. Given "
        f"the enclosing block the loop is actually shown ({n['snippet_strategies']}, "
        f"~{n['snippet_lines']} lines): {n['real_rejected_with_context']} of "
        f"{n['real_reviewed']}. The residual is not a context problem -- see below."
    )
    breakdown = _rejection_reasons(result)
    if breakdown:
        lines.append("    by which check:")
        for reason, count, _ in breakdown:
            lines.append(f"      {reason:22s} {count}")
    lines.append("")
    for outcome in result.outcomes:
        if outcome.status != "ok":
            continue
        engaged = outcome.engaged
        if not engaged and not outcome.declined:
            continue
        mark = "engaged" if engaged else "declined"
        lines.append(
            f"  {mark:8s} {outcome.advisory}  {outcome.repo}  cwes={','.join(outcome.cwe_ids)}"
        )
        if outcome.is_merge:
            lines.append("           (fix is a merge commit; diffed against first parent)")
        for f in engaged:
            lines.append(
                f"           {f.path}:{f.our_line}  {f.our_rewrite}  "
                f"upstream touched {len(f.real_lines)} line(s); "
                f"same line: {f.same_line_as_upstream}"
            )
    return "\n".join(lines)


def _tier3_markdown(result: Tier3Result) -> str:
    if not result.runs:
        return f"## Tier 3: real CVEs\n\n**Skipped.** {result.skipped_reason}\n"

    n = _tier3_numbers(result)
    lines = ["## Tier 3: real CVEs and the real commits that fixed them", ""]
    lines.append(
        f"{n['advisories']} GitHub Security Advisories, fetched from their upstream fix "
        f"commits. **{n['measured']} fetched, {n['files']} real source files examined** "
        f"({result.duration_ms / 1000:.1f}s)."
    )
    if n["fetch_failed"]:
        lines.append("")
        lines.append(
            f"> {n['fetch_failed']} advisories could not be fetched and are **absent** "
            "from every count below. They are not counted as passes."
        )
    lines.append("")
    lines.append("### Coverage: how often does a real CVE have a line this engine can act on?")
    lines.append("")
    lines.append("| | count | of |")
    lines.append("| --- | --- | --- |")
    lines.append(f"| files where a rule engaged | {n['engaged']} | {n['files']} |")
    lines.append(f"| files with no candidate line at all | {n['no_candidate']} | {n['files']} |")
    lines.append(f"| files where the engine declined | {n['declined']} | {n['files']} |")
    lines.append("")
    lines.append(
        f"**{n['engaged']} of {n['files']}** -- "
        f"{100 * n['engaged'] // max(n['files'], 1)}%. That is the honest coverage "
        "number for a six-rule table, and it is low. The candidate line is found by "
        "scanning for a pattern the table already matches, so this is an *upper* bound "
        "on what the engine could find, not a measurement of how many real "
        "vulnerabilities it detects."
    )
    lines.append("")
    lines.append("### Line agreement with the real fix")
    lines.append("")
    lines.append(
        f"Of the {n['engaged']} patches proposed, **{n['agreements']} landed on a line "
        "upstream also changed.** This is a comparison against ground truth, not a "
        "self-assessment -- and it says nothing about whether a patch is *correct*, "
        "which is why it is reported as a count and never as a percentage."
    )
    lines.append("")
    lines.append("| advisory | repository | CWEs | our line | upstream lines | agree |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for outcome in result.measured:
        for f in outcome.engaged:
            lines.append(
                f"| `{outcome.advisory}` | `{outcome.repo}` | "
                f"{', '.join(outcome.cwe_ids)} | `{f.path}:{f.our_line}` | "
                f"{len(f.real_lines)} | {'yes' if f.same_line_as_upstream else 'no'} |"
            )
    lines.append("")
    lines.append("### Would a real, merged fix pass our own reviewer?")
    lines.append("")
    reviewed = n["real_reviewed"] or 1
    lines.append(
        f"**{n['real_rejected']} of {n['real_reviewed']}** real, merged, human-reviewed "
        f"security fixes ({100 * n['real_rejected'] // reviewed}%) would be rejected by "
        "`DeterministicReviewer` given the one line a scanner reports."
    )
    lines.append("")
    lines.append(
        f"With the enclosing block the loop is actually shown "
        f"(`{n['snippet_strategies']}`, averaging {n['snippet_lines']} lines): "
        f"**{n['real_rejected_with_context']} of {n['real_reviewed']}** "
        f"({100 * n['real_rejected_with_context'] // reviewed}%)."
    )
    lines.append("")
    lines.append(
        "**That is a smaller win than it looks, and the reason is the interesting part.** "
        "The scope check fires when *no* removed line of the patch appears in the "
        "snippet. A real fix usually also edits something a long way from the reported "
        "finding — an import, a declaration, a type — and no snippet anchored on one "
        "line reaches it. The ceiling here exists precisely to stop the snippet "
        "becoming the whole file, so this cannot be closed by showing more: it is not a "
        "context problem."
    )
    lines.append("")
    lines.append(
        "Which is the finding. The residual objections are mostly the reviewer being "
        "*right* — a patch that also edits an import 400 lines away does deserve a "
        "second look. It is raised here against upstream's own merged fixes, so it is a "
        "precision problem, not a correctness one. See "
        "[docs/architecture.md §13](architecture.md)."
    )
    lines.append("")
    lines.append(
        "The widening is still worth having, for a reason this measurement cannot see: "
        "the AutoGen engine drafts from the same snippet, and drafting a patch from one "
        "line of a 200-line function is worse than drafting from the function. That part "
        "is not measured here and is not claimed to be."
    )
    lines.append("")
    breakdown = _rejection_reasons(result)
    if breakdown:
        lines.append("Which check objected, and how often:")
        lines.append("")
        lines.append("| check | objections | what it asserts |")
        lines.append("| --- | --- | --- |")
        for reason, count, asserts in breakdown:
            lines.append(f"| `{reason}` | {count} | {asserts} |")
        lines.append("")
    lines.append(
        "What is still missing is the other half of the measurement, and it is the half "
        "that matters: **this corpus is all good patches.** A reviewer that rejects "
        "even 10% of correct work is bad news, but the number that would settle whether "
        "this gate earns its place is how often it rejects a patch that is *wrong* — "
        "which needs a corpus of bad patches labelled by a human, and does not exist. "
        "[docs/architecture.md §13](architecture.md) argues the two readings of what "
        "the gate is for."
    )
    lines.append("")
    lines.append("| rejected | advisory | file | upstream size | what we said |")
    lines.append("| --- | --- | --- | --- | --- |")
    for outcome in result.measured:
        for f in result.real_fixes_rejected:
            if f not in outcome.files:
                continue
            reason = "; ".join(f.real_fix_comments) or "no objection recorded"
            lines.append(
                f"| yes | `{outcome.advisory}` | `{f.path}` | "
                f"+{f.added_lines}/-{f.removed_lines} | {reason[:150]} |"
            )
    lines.append("")
    return "\n".join(lines)


# The reviewer's checks, keyed by a stable fragment of their comment text rather
# than by position. Classifying by the comment means the breakdown describes what
# the reviewer actually said, and it goes stale loudly -- an unrecognised comment
# becomes its own `unrecognised` row -- rather than quietly attributing a
# rejection to the wrong cause.
_REVIEWER_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "vulnerable-construct",
        "still introduces",
        "the vulnerable construct is gone",
    ),
    ("parses", "does not parse", "the patched source compiles"),
    (
        "scoped",
        "not present in the reported snippet",
        "the change is confined to the reported lines",
    ),
    (
        "size",
        "reviewable in one sitting",
        "a single-finding patch stays under 20 added lines",
    ),
)


def _rejection_reasons(result: Tier3Result) -> list[tuple[str, int, str]]:
    """How many rejections each reviewer check caused, in check order."""
    counts: dict[str, int] = {}
    for file_outcome in result.real_fixes_rejected:
        blob = " ".join(file_outcome.real_fix_comments)
        recognised = False
        for key, fragment, _ in _REVIEWER_CHECKS:
            if fragment in blob:
                counts[key] = counts.get(key, 0) + 1
                recognised = True
        if not recognised:
            counts["unrecognised"] = counts.get("unrecognised", 0) + 1
    order = {key: index for index, (key, _, _) in enumerate(_REVIEWER_CHECKS)}
    assertions = {key: asserts for key, _, asserts in _REVIEWER_CHECKS}
    return [
        (
            key,
            counts[key],
            assertions.get(key, "a check this report does not recognise -- see the commit"),
        )
        for key in sorted(counts, key=lambda k: (order.get(k, 99), k))
    ]


# --------------------------------------------------------------------------
# Gaps
# --------------------------------------------------------------------------


def _render_gaps() -> str:
    lines = ["", "KNOWN BLIND SPOTS", "-" * 70]
    lines.append("  Printed unconditionally. These do not change when a run goes well.")
    for gap in KNOWN_GAPS:
        first, _, rest = gap.partition(". ")
        lines.append(f"  - {first}.")
        if rest:
            for chunk in _wrap(rest, 96):
                lines.append(f"    {chunk}")
    return "\n".join(lines)


def _gaps_markdown() -> str:
    lines = ["## Known blind spots", ""]
    lines.append(
        "Unconditional: a set of known blind spots that does not change when a run "
        "happens to go well."
    )
    lines.append("")
    for gap in KNOWN_GAPS:
        first, _, rest = gap.partition(". ")
        lines.append(f"- **{first}.** {rest}" if rest else f"- **{first}.**")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current: list[str] = []
    length = 0
    for word in words:
        if length + len(word) + 1 > width:
            lines.append(" ".join(current))
            current, length = [word], len(word)
        else:
            current.append(word)
            length += len(word) + 1
    if current:
        lines.append(" ".join(current))
    return lines
