# 001 — The system proposes code; a human merges it

**Status:** accepted

## Context

This is a security-triage system. Its most powerful capability is drafting a
patch that fixes a vulnerability in someone else's codebase. Get that wrong and
it is not a security tool, it is an attack with a responsible job title.

The failure mode is specific and does not look like a failure. An agent that
drafts a plausible-looking patch for a real finding *is* mostly right, often
enough that an approval reflex forms. Then one of them lands. Nobody can tell
afterwards which was the one, because the agent's confidence and the human's
attention are both terrible at the 95% case.

So the question is not "should we allow automated remediation". It is: **where
exactly does the line sit, and what stops the line from eroding?**

Erosion is the real threat. Not a bad actor — a hundred reasonable small
decisions:

- "the reviewer agent already approved it, let me just open the PR as ready"
- "it's a typo fix, surely that doesn't need a human"
- "let me add a `--auto-merge` flag behind an env var, we just won't set it"
- "the CI already passed the tests, so the review is redundant"

Each is individually reasonable. Together they delete the guarantee in a
quarter. A guarantee that depends on nobody ever finding the exception is not a
guarantee, it is a convention.

## Decision

**The system can propose, review, and draft. It cannot merge. Ever. There is
no code path, no configuration, and no flag that enables merging.**

Concretely:

- `publisher.merge_pull_request()` exists and its entire body raises
  `MergePolicyViolation`. It is kept rather than deleted so the interface
  answers "can this merge?" with a clear no instead of by omission.
- `pull_requests.auto_merge_blocked` is `Boolean` with a **column-level default
  of `True`**, and every insert hardcodes `True`. The database would have to be
  altered to store an unblocked pull request.
- `SENTINEL_ALLOW_AUTO_MERGE` is read at startup **only in order to raise**. It
  is a tripwire, not a switch.
- `ProposalStatus` has no `MERGED` member. Merging is a `PullRequest` state,
  recorded as an observation of something a human did in a git host.
- The only code that writes `PullRequestStatus.MERGED` is
  `ApprovalService.record_external_merge`, which contacts no git host and
  refuses unless a human approval is already recorded.
- Approval moves the finding to `IN_PROGRESS`, never `REMEDIATED`. An approved
  draft is not a merged change.

## Consequences

**Good.** The guarantee is checkable rather than aspirational:
`tests/unit/policy/test_safety_rails.py` AST-walks every module under `backend/`
and asserts that no assignment anywhere sets `auto_merge_blocked` to anything
but the literal `True`, and that exactly one function in the codebase writes
`MERGED`. A new feature cannot quietly add a merge path without failing the
build. The AST test is the part that matters — the other four mechanisms would
all be defeated by one new `UPDATE`, and this one is not.

**Inconvenient, and kept anyway.** Every remediation costs a human. For a
managed security provider facing hundreds of findings a week that is a real tax,
and the honest answer to "can we automate the boring ones?" is: not in this
system. The batching that would make it bearable is a *human* batching problem
(`GET /pull-requests/awaiting-approval` exists for exactly that), and a queue an
approver can clear in ten minutes is worth more than a merge button.

**Also inconvenient:** a finding approved but not merged sits in `IN_PROGRESS`
and keeps its SLA clock, so it keeps showing up in dashboards as needing
attention. That is correct — it *is* still needing attention.

## Alternatives considered

**Auto-merge low-severity fixes with a confidence threshold.** The most common
proposal and the one this record exists to refuse. The threshold is the problem,
not the solution: nothing measures the distribution of "wrong but confident" for
your codebase, the distribution shifts as the codebase changes, and the failure
mode is a security regression landing silently. A system that merges at 95%
confidence is a system that will eventually merge a backdoor at 95% confidence.

**Let the reviewer *agent* be the approver for trivial patches.** It already
reads the diff. It is also the same model that wrote the diff, so its approval
carries the information content of "the model liked its own output". Adding a
second call to the same model does not create a second opinion.

**Make merging a deployment-time concern — block it in CI, or in the git
provider's branch protection.** Necessary and not sufficient: it protects one
repository through a control the user can change, and this project has no
standing to configure anyone's branch protection. A control in the application
is one fewer thing to remember.

**Gate on a human but allow a `--yes` flag for trusted environments.** This is
the `--auto-merge` flag with better manners, and it is worse, because a flag
whose name contains "yes" and whose effect is "skip the human" is exactly what
gets added on a deadline. The tripwire (`SENTINEL_ALLOW_AUTO_MERGE` raises) is
the version of this idea that is safe: setting it stops the system instead of
loosening it.
