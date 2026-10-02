"""Simulated git publication.

**This module never contacts a git host.** No GitHub token is read, no remote
is configured, no HTTP request is made. A portfolio project that can push to a
real repository the moment someone clones it and sets an environment variable
is a hazard, not a feature.

What it does instead is produce the *artifacts* a real publisher would: a
branch name, a diff URL, and a pull request body. Everything downstream --
the `pull_requests` table, the human approval gate, the dashboard -- operates
on those artifacts exactly as it would against a live GitHub, so swapping in a
real publisher is a change to this file and nowhere else.

`merge_pull_request` exists solely to refuse. It is not dead code: it is the
named answer to "what happens if something tries to merge?", and
`tests/integration/test_api_and_approval.py` asserts it raises. See
`backend/policy/rules.py::assert_merge_refused`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from backend.config.settings import get_settings
from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.policy.rules import assert_merge_refused

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for type checking only
    from backend.agents.autogen_loop import LoopResult
    from backend.database.models.finding import Finding
    from backend.database.models.remediation import RemediationProposal

logger = get_logger(__name__)

_SLUG = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True, slots=True)
class PublishedDraft:
    """What a real `git push` + "open pull request" would have produced."""

    branch: str
    base_branch: str
    target_repo: str
    diff_url: str
    patch: str


def build_branch_name(finding: Finding, *, correlation_id: str | None = None) -> str:
    """A deterministic-per-finding remediation branch name.

    Derived from the finding's rule id rather than a random suffix so that
    re-running remediation for the same finding targets the same branch, which
    is what a real publisher needs to avoid opening duplicate PRs.
    """
    slug = _SLUG.sub("-", f"{finding.severity.value}-{finding.rule_id}".lower()).strip("-")
    slug = slug[:48]
    suffix = (correlation_id or new_correlation_id())[:8]
    return f"sentinel/{finding.severity.value}/{slug}-{suffix}"


def publish_draft(
    *,
    title: str,
    body: str,
    patch: str,
    file_path: str,
    correlation_id: str | None = None,
) -> PublishedDraft:
    """Simulate opening a draft pull request.

    Synchronous, because it does no I/O. It returns the same shape a real
    GitHub publisher would, and the caller (`RemediationService`) cannot tell
    the difference.
    """
    settings = get_settings()
    slug = _SLUG.sub("-", title.lower()).strip("-")[:60] or "remediation"
    branch = f"sentinel/{slug}"[:100]

    logger.info(
        "simulated draft publication repo=%s branch=%s file=%s (no remote contacted)",
        settings.target_repo,
        branch,
        file_path,
    )
    return PublishedDraft(
        branch=branch,
        base_branch=settings.target_base_branch,
        target_repo=settings.target_repo,
        diff_url=f"https://example.invalid/{settings.target_repo}/compare/{settings.target_base_branch}...{branch}?diff=split&w=1",
        patch=patch,
    )


def merge_pull_request(pull_request_id: Any, *, actor: str = "system") -> None:
    """Always raises. There is no machine merge, by design.

    Present as a named function rather than omitted so the absence is explicit
    in the code and greppable, and so any future caller that reaches for it
    gets a clear, specific refusal rather than an `AttributeError`.
    """
    assert_merge_refused(actor=actor)
    raise AssertionError(  # pragma: no cover - assert_merge_refused always raises first
        "unreachable: assert_merge_refused() must raise"
    )


def build_pull_request_body(
    *,
    finding: Finding,
    proposal: RemediationProposal,
    result: LoopResult,
) -> str:
    """Render the markdown body a human approver reads first.

    Structured so the human's first question -- *should I trust this?* -- is
    answered before they read a line of the diff. The finding, the severity,
    the agent's own rationale, and the reviewer's verdict come first; the diff
    comes last, under its own heading.
    """
    reviewer_lines = result.all_feedback()
    transcript_rows = [
        f"| {entry['round']} | {entry['developer_decision']} | "
        f"{entry['reviewer_decision'] or '-'} |"
        for entry in result.transcript()
    ]

    return "\n".join(
        [
            "> **Draft. Not merged, and not mergeable by machine.** This pull request was",
            "> opened by SentinelMCP's agent loop. A human approver has to review it",
            "> before it becomes visible for merge. `auto_merge_blocked` is `true`.",
            "",
            "## Finding",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Title | {finding.title} |",
            f"| Severity | **{finding.severity.value}** |",
            f"| Confidence | {finding.confidence.value} |",
            f"| Rule | `{finding.rule_id}` |",
            f"| Location | `{finding.file_path}:{finding.start_line}` |",
            f"| CWE | {', '.join(finding.cwe_ids) or 'n/a'} |",
            f"| CVE | {', '.join(finding.cve_ids) or 'n/a'} |",
            f"| Fingerprint | `{finding.fingerprint}` |",
            f"| First seen | {finding.first_seen_at.isoformat()} |",
            f"| SLA due | {finding.sla_due_at.isoformat() if finding.sla_due_at else 'n/a'} |",
            "",
            f"{finding.description}",
            "",
            "## What the agent changed, and why",
            "",
            f"{result.rationale}",
            "",
            f"**Summary:** {result.summary}",
            "",
            "## Agent dialogue",
            "",
            f"Engine: `{result.llm_model or 'deterministic (no LLM calls)'}`  ",
            f"Rounds: {result.rounds_completed}  ",
            f"LLM calls: {result.llm_calls}  ",
            f"Tokens: {result.tokens_used}  ",
            f"Cost: ${result.cost_usd:.6f}  ",
            f"Wall time: {result.latency_ms:.0f} ms",
            "",
            "| Round | Developer | Reviewer |",
            "| --- | --- | --- |",
            *(transcript_rows or ["| - | (no rounds completed) | - |"]),
            "",
            (
                "### Reviewer comments carried through\n\n"
                + "\n".join(f"- {c}" for c in reviewer_lines)
                if reviewer_lines
                else "### Reviewer comments carried through\n\n_None: approved on the first round._"
            ),
            "",
            "## Reviewer check before you approve",
            "",
            "Automated review passing is **necessary but not sufficient**. Check, in order:",
            "",
            "1. Does this remove the vulnerability, or only rearrange it?",
            "2. Does the patched code still parse and behave the same for valid input?",
            "3. Is the change minimal, or did it silently drop a validation?",
            "4. If a credential was exposed, has it been **rotated**? Moving it to an",
            "   environment variable does not un-leak a value that is already in git",
            "   history -- the rotation is a separate, required step.",
            "5. Is there a test that fails before this change and passes after it?",
            "",
            "## Diff",
            "",
            "```diff",
            result.patch or "(no patch)",
            "```",
            "",
            "---",
            "",
            f"Proposal `{proposal.id}` · correlation id `{result.correlation_id}`",
            "",
        ]
    )
