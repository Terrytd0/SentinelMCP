"""Business rules and safety rails.

Everything in this module is a *rule*, not a mechanism: it decides, it does
not execute. That separation is the point. The rules here are the difference
between "an AI can write code" and "an AI can write code and be stopped":

    `sla_hours_for()`            how long a severity has to be fixed
    `evaluate_auto_remediation()` whether the agent may draft a patch at all
    `assert_human_merge_required()`  the hard, non-negotiable guarantee

The last one has no override and no flag. `SENTINEL_ALLOW_AUTO_MERGE` exists
in settings purely so that startup can *refuse to boot* when it is set to
`True` -- there is no code path that honours it, and
`tests/unit/policy/test_safety_rails.py` asserts that setting it raises rather than
enabling anything. If a future contributor adds a merge capability, they have
to delete that test, which is the intended speed bump.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from backend.config.settings import Settings, get_settings
from backend.core.clock import ensure_aware, hours_between, utc_now
from backend.core.logging import get_logger
from backend.database.enums import Confidence, Severity

logger = get_logger(__name__)


class AutoRemediationRefusal(StrEnum):
    """Why the agent was not allowed to draft a patch.

    Returned rather than a bare boolean so the refusal reason can be stored on
    the finding, shown to the operator, and asserted in a test. "It said no"
    without a reason is not an answerable question.
    """

    ELIGIBLE = "eligible"
    SEVERITY_NOT_ACTIONABLE = "severity_not_actionable"
    CONFIDENCE_TOO_LOW = "confidence_too_low"
    PATH_OUTSIDE_SOURCE_ROOTS = "path_outside_source_roots"
    NO_SOURCE_LOCATION = "no_source_location"
    STATUS_NOT_ACTIONABLE = "status_not_actionable"
    NO_SNIPPET = "no_snippet"
    ATTEMPT_BUDGET_EXHAUSTED = "attempt_budget_exhausted"


class MergePolicyViolation(RuntimeError):
    """Raised when something attempts a machine merge.

    There is no caller that catches this and proceeds. It exists so that the
    forbidden operation fails loudly and specifically if it is ever added,
    instead of being quietly permitted.
    """


@dataclass(frozen=True, slots=True)
class RemediationDecision:
    """Whether the agent may draft a patch, and why."""

    eligible: bool
    refusal: AutoRemediationRefusal
    reason: str

    @classmethod
    def allow(cls) -> RemediationDecision:
        return cls(
            True, AutoRemediationRefusal.ELIGIBLE, "finding is eligible for auto-remediation"
        )

    @classmethod
    def deny(cls, refusal: AutoRemediationRefusal, reason: str) -> RemediationDecision:
        return cls(False, refusal, reason)


@dataclass(frozen=True, slots=True)
class SlaState:
    """Where one finding stands against its SLA deadline."""

    severity: Severity
    due_at: datetime | None
    hours_remaining: float | None
    state: str
    """`not_started` | `on_track` | `at_risk` | `breached` | `met` | `stopped`."""

    breached: bool
    fraction_elapsed: float
    notes: list[str] = field(default_factory=list)


# Severities at or above this may be auto-remediated without a human
# pre-approving the attempt. Everything below needs a human to ask for it.
# LOW is included on purpose: a hardcoded secret should get a drafted patch
# even though it is not an active breach vector.
AUTO_REMEDIATION_MIN_CONFIDENCE = Confidence.MEDIUM

# How many agent loops may run against one finding before policy refuses
# further attempts and routes it to a human. A finding that has survived three
# developer/reviewer rounds is usually one the agents do not understand, and
# continuing just burns tokens.
MAX_REMEDIATION_ATTEMPTS = 3

# Path prefixes the agent is permitted to draft patches for. Anything outside
# this list is refused. Deliberately narrow: an agent that can write a patch
# for `infra/terraform/prod/` is an agent that can break production.
DEFAULT_SOURCE_ROOTS = ("app/", "src/", "services/", "lib/", "config/")


def sla_hours_for(severity: Severity, settings: Settings | None = None) -> int:
    """How many hours a finding of `severity` has to be remediated.

    Configurable per severity because the right number is a business decision,
    not a technical one: the same CRITICAL finding means something different to
    a payments team and an internal tools team.
    """
    resolved = settings or get_settings()
    return {
        Severity.CRITICAL: resolved.sla_critical_hours,
        Severity.HIGH: resolved.sla_high_hours,
        Severity.MEDIUM: resolved.sla_medium_hours,
        Severity.LOW: resolved.sla_low_hours,
        Severity.INFO: resolved.sla_info_hours,
        # An unclassified finding gets the most generous deadline available.
        # Tightening it would create a flood of phantom breaches the moment a
        # new scanner arrives and reports something we cannot classify.
        Severity.UNSPECIFIED: resolved.sla_low_hours,
    }[severity]


def sla_deadline_for(severity: Severity, settings: Settings | None = None) -> datetime:
    """The absolute deadline for a finding of `severity`, measured from now."""
    return utc_now() + timedelta(hours=sla_hours_for(severity, settings))


def evaluate_sla(
    *,
    severity: Severity,
    due_at: datetime | None,
    first_seen_at: datetime | None = None,
    closed_at: datetime | None = None,
    settings: Settings | None = None,
) -> SlaState:
    """Classify one finding against its SLA.

    Three states people routinely get wrong, and which this function gets
    right:

    * **stopped.** A finding that reached a terminal state stops accruing
      breach time. An `ACCEPTED_RISK` finding three weeks old is not a
      three-week-old breach; the decision was made and the clock stopped.
    * **met.** A finding remediated before its deadline is *not* a breach, and
      must not appear in a breach count just because `due_at` is now in the
      past.
    * **not_started.** A finding with no deadline yet (severity unclassified at
      scan time) is neither on track nor breaching.
    """
    resolved = settings or get_settings()
    now = utc_now()

    if closed_at is not None:
        stop = ensure_aware(closed_at)
        if due_at is None:
            state, breached = "stopped", False
        elif stop <= ensure_aware(due_at):
            state, breached = "met", False
        else:
            # Closed late. Still a breach -- the fix did not land in time -- but
            # the elapsed time is measured to the close, not to now, so a
            # finding closed six weeks ago reports a six-week breach rather
            # than a growing one.
            state = "breached"
            breached = True
        return SlaState(
            severity=severity,
            due_at=due_at,
            hours_remaining=None,
            state=state,
            breached=breached,
            fraction_elapsed=1.0,
        )

    if due_at is None:
        return SlaState(
            severity=severity,
            due_at=None,
            hours_remaining=None,
            state="not_started",
            breached=False,
            fraction_elapsed=0.0,
            notes=["no SLA deadline set"],
        )

    due = ensure_aware(due_at)
    hours_remaining = hours_between(now, due)
    total = sla_hours_for(severity, resolved)
    elapsed = max(0.0, total - hours_remaining)
    fraction = min(1.0, elapsed / total) if total > 0 else 1.0

    if hours_remaining <= 0:
        state, breached = "breached", True
    elif fraction >= resolved.sla_at_risk_fraction:
        state, breached = "at_risk", False
    else:
        state, breached = "on_track", False

    return SlaState(
        severity=severity,
        due_at=due,
        hours_remaining=hours_remaining,
        state=state,
        breached=breached,
        fraction_elapsed=fraction,
    )


def evaluate_auto_remediation(
    *,
    severity: Severity,
    confidence: Confidence,
    status: Any,
    file_path: str | None,
    snippet: str | None,
    remediation_attempts: int = 0,
    source_roots: tuple[str, ...] | None = None,
) -> RemediationDecision:
    """Decide whether the agent may draft a remediation patch for a finding.

    Ordered cheapest-check-first, and the order is also the explanation order:
    a caller that gets a refusal can show the first reason that applied. The
    checks are conjunctive -- all must pass.

    Note what is *not* checked: whether the finding is interesting. Policy
    gates *safety*, not priority. Deciding that a CRITICAL should be fixed
    before a MEDIUM is the queue's job (`SlaState`), not a safety rail, and
    mixing the two would mean loosening safety to reprioritise work.
    """
    # A finding that is already closed has nothing to remediate.
    is_terminal = getattr(status, "is_terminal", False)
    if is_terminal:
        return RemediationDecision.deny(
            AutoRemediationRefusal.STATUS_NOT_ACTIONABLE,
            f"finding is in a terminal state ({getattr(status, 'value', status)})",
        )

    if not severity.is_actionable:
        return RemediationDecision.deny(
            AutoRemediationRefusal.SEVERITY_NOT_ACTIONABLE,
            f"severity {severity.value} is informational and never auto-remediated",
        )

    if _confidence_rank(confidence) < _confidence_rank(AUTO_REMEDIATION_MIN_CONFIDENCE):
        return RemediationDecision.deny(
            AutoRemediationRefusal.CONFIDENCE_TOO_LOW,
            f"confidence {confidence.value} is below the "
            f"{AUTO_REMEDIATION_MIN_CONFIDENCE.value} required to draft a patch",
        )

    if not file_path:
        return RemediationDecision.deny(
            AutoRemediationRefusal.NO_SOURCE_LOCATION,
            "finding has no file path, so there is nothing to patch",
        )

    # `None` means "caller did not care", so the module default applies. An
    # explicitly empty tuple means the operator configured *no* writable roots,
    # and must fail closed -- `source_roots or DEFAULT` would treat the two the
    # same and silently hand the agent the defaults, which is the opposite of
    # what someone who just set an empty list asked for.
    roots = DEFAULT_SOURCE_ROOTS if source_roots is None else source_roots
    if not _path_within_roots(file_path, roots):
        return RemediationDecision.deny(
            AutoRemediationRefusal.PATH_OUTSIDE_SOURCE_ROOTS,
            f"file path is outside the permitted source roots {list(roots)}",
        )

    if not snippet or not snippet.strip():
        return RemediationDecision.deny(
            AutoRemediationRefusal.NO_SNIPPET,
            "finding has no source snippet, so a patch cannot be built against it",
        )

    if remediation_attempts >= MAX_REMEDIATION_ATTEMPTS:
        return RemediationDecision.deny(
            AutoRemediationRefusal.ATTEMPT_BUDGET_EXHAUSTED,
            f"finding has already been attempted {remediation_attempts} times "
            f"(limit {MAX_REMEDIATION_ATTEMPTS}); escalating to a human",
        )

    return RemediationDecision.allow()


def _confidence_rank(confidence: Confidence) -> int:
    order = {
        Confidence.UNSPECIFIED: 0,
        Confidence.LOW: 1,
        Confidence.MEDIUM: 2,
        Confidence.HIGH: 3,
    }
    return order.get(confidence, 0)


def _path_within_roots(file_path: str, roots: tuple[str, ...]) -> bool:
    """Whether `file_path` sits under one of `roots`, traversal-safe.

    Both sides are normalized to absolute `PurePosixPath`s before comparison
    so that `app/../../etc/passwd` and `/app/x.py` resolve to the same answer.
    Comparing strings would let `../` walk straight out of a permitted root,
    which is precisely the bug this function exists to prevent.
    """
    resolved = _resolve_posix(file_path)
    if resolved is None:
        return False
    for root in roots:
        normalized_root = _resolve_posix(root)
        if normalized_root is None or len(normalized_root.parts) < 2:
            # A root of "/" would permit the entire filesystem, and a root that
            # resolves to nothing is a configuration mistake. Both are refused
            # rather than treated as "match everything".
            continue
        if resolved.parts[: len(normalized_root.parts)] == normalized_root.parts:
            return True
    return False


def _resolve_posix(path: str) -> PurePosixPath | None:
    """Normalize a path to an absolute POSIX path with `..` collapsed.

    `PurePosixPath` does not collapse `..` (it has no filesystem to consult),
    so the segments are resolved by hand against a root of `/`.
    """
    if not isinstance(path, str) or not path.strip():
        return None
    parts: list[str] = []
    for segment in path.replace("\\", "/").split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if parts:
                parts.pop()
            continue
        parts.append(segment)
    return PurePosixPath("/" + "/".join(parts))


def assert_human_merge_required(*, actor: str, allow_auto_merge: bool) -> None:
    """Refuse to proceed if a machine merge has been configured.

    Called at FastAPI startup from `backend/main.py`, and on demand from
    `GET /health/policy`. If `SENTINEL_ALLOW_AUTO_MERGE` is `True`, this raises
    rather than returning: the setting is treated as a hard misconfiguration,
    because the only possible outcome of honouring it is a system that can merge
    its own code into a repository with no human in the loop.

    There is deliberately no code path that reads this flag and enables a
    merge. Passing `allow_auto_merge=False` does not unlock anything; it only
    avoids raising.
    """
    if allow_auto_merge:
        raise MergePolicyViolation(
            "SENTINEL_ALLOW_AUTO_MERGE is set, but machine merge is not implemented and "
            "will not be. Remediation pull requests are opened as drafts and require an "
            f"explicit human approval by an APPROVER or ADMIN. (requested by {actor})"
        )
    logger.debug("human-merge-required policy verified actor=%s", actor)


def assert_merge_refused(actor: str = "system") -> None:
    """The unconditional form: there is no merge, full stop.

    Called by `backend/services/publisher.py::merge_pull_request`, which exists
    only to raise. Keeping a named function (rather than deleting the method)
    means the interface still answers "can this merge?" with a clear "no", and
    the refusal is discoverable in the code rather than inferred from an
    absence.
    """
    raise MergePolicyViolation(
        f"{actor} may not merge a remediation pull request. "
        "This system can propose changes, review them, and open a draft pull request. "
        "Merging is a human action taken in the git host."
    )
