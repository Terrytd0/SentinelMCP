"""Enumerations shared by the ORM models, the API schemas, and the SLA engine.

These are `str, Enum` (not `enum.StrEnum`) on purpose. SQLAlchemy's `Enum`
type stores the enum *member's value* in the database, and `StrEnum` members
are `str` subclasses, which makes "is this loaded value a member or a plain
str?" ambiguous in exactly the places that are painful to debug (a severity
coming back from Postgres and being compared against a string in a policy
rule). The explicit `str` mixin keeps the column type and the in-memory type
unambiguous. See the `UP042` ignore in `pyproject.toml` for the lint that
would otherwise flag this.
"""

from __future__ import annotations

from enum import Enum


class StrEnum(str, Enum):
    """`str`-valued enum with a readable `str()` and stable `.value`."""

    def __str__(self) -> str:
        return str(self.value)


class Severity(StrEnum):
    """How bad a finding is if real. Ordered by triage urgency.

    The integer ordering is load-bearing: the SLA engine picks a deadline by
    taking the *max* severity present, and the dashboard sorts by it. Adding a
    tier means inserting a new member above `LOW`, never renumbering, so that
    stored rows keep meaning what they meant.
    """

    UNSPECIFIED = "unspecified"
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 = most urgent. Drives sorting and SLA selection."""
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.UNSPECIFIED: 5,
        }
        return order[self]

    @property
    def is_actionable(self) -> bool:
        """Whether this severity should enter the remediation pipeline at all.

        `INFO` and `UNSPECIFIED` never do: auto-drafting a patch for a
        style-level finding is noise that trains analysts to ignore the agent.
        """
        return self in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


class Confidence(StrEnum):
    """How much an analyst can trust a finding, independent of its severity.

    Kept orthogonal to `Severity` on purpose. A speculative CRITICAL and a
    confirmed CRITICAL are the same queue priority but very different amounts
    of work, and conflating them is how triage queues fill up with noise.
    """

    UNSPECIFIED = "unspecified"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ScannerKind(StrEnum):
    """Which tool produced a finding.

    Mirrors `sentinel.v1.ScannerKind`. A scanner this enum does not know about
    still round-trips (the model stores the raw string via
    `ScannerKind.custom` behavior in the repository layer) rather than being
    rejected -- adding a scanner to the fleet must not require migrating
    historical rows.
    """

    UNSPECIFIED = "unspecified"
    FIXTURE = "fixture"
    SEMGREP = "semgrep"
    ZAP = "zap"
    DEPENDENCY = "dependency"


class FindingStatus(StrEnum):
    """Where a finding sits in the remediation lifecycle.

    The terminal states (`FALSE_POSITIVE`, `ACCEPTED_RISK`, `REMEDIATED`) stop
    the SLA clock. That matters: an SLA that keeps running after a human has
    decided to accept the risk reports a permanently-breached queue that
    nobody can act on, and people stop looking at the dashboard.
    """

    OPEN = "open"
    TRIAGED = "triaged"
    IN_PROGRESS = "in_progress"
    PROPOSED = "proposed"
    AWAITING_REVIEW = "awaiting_review"
    REMEDIATED = "remediated"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"

    @property
    def is_terminal(self) -> bool:
        return self in (
            FindingStatus.REMEDIATED,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.FALSE_POSITIVE,
        )


class TicketStatus(StrEnum):
    """Workflow state of a tracked remediation ticket."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    CLOSED = "closed"

    @property
    def is_open(self) -> bool:
        return self in (TicketStatus.OPEN, TicketStatus.IN_PROGRESS, TicketStatus.BLOCKED)


class ProposalStatus(StrEnum):
    """State of an agent-drafted remediation.

    Note what is *absent*: there is no `MERGED`. A proposal can be approved by
    the reviewer agent and can be approved by a human, and it still does not
    merge itself -- merging is an action on a pull request, taken by a person
    in a git host, and the code that would allow it is not written. See
    `backend/policy/rules.py::assert_human_merge_required`.
    """

    DRAFTING = "drafting"
    UNDER_REVIEW = "under_review"
    REVISION_REQUESTED = "revision_requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    SUPERSEDED = "superseded"

    @property
    def is_final(self) -> bool:
        return self in (
            ProposalStatus.APPROVED,
            ProposalStatus.REJECTED,
            ProposalStatus.ESCALATED,
            ProposalStatus.SUPERSEDED,
        )


class PullRequestStatus(StrEnum):
    """State of a drafted remediation pull request.

    `MERGED` exists only as an *observed* state that a human (or their git
    host) can move the record into. Nothing in this codebase transitions a PR
    into `MERGED`.
    """

    DRAFT = "draft"
    OPEN = "open"
    MERGED = "merged"
    CLOSED = "closed"


class AgentRole(StrEnum):
    """Which participant in the developer/reviewer loop produced a record."""

    DEVELOPER = "developer"
    REVIEWER = "reviewer"
    SYSTEM = "system"
    HUMAN = "human"


class AgentDecision(StrEnum):
    """A single decision an agent (or a human) recorded.

    `ESCALATE` is a first-class decision, not a failure. An agent that cannot
    agree with its reviewer should hand the problem to a human rather than
    keep arguing or quietly accept a bad patch.
    """

    PROPOSE = "propose"
    REQUEST_CHANGES = "request_changes"
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"
    ACCEPT = "accept"
    WITHDRAW = "withdraw"


class UserRole(StrEnum):
    """Authorization roles, coarse and explicit.

    `ANALYST` reads and triages. `APPROVER` additionally authorizes the
    human gate that lets a pull request be opened. `ADMIN` is the only role
    allowed to change policy configuration.
    """

    ANALYST = "analyst"
    APPROVER = "approver"
    ADMIN = "admin"

    @property
    def can_approve_remediation(self) -> bool:
        return self in (UserRole.APPROVER, UserRole.ADMIN)


class AuditAction(StrEnum):
    """Every mutation the system performs gets one of these.

    An explicit enum rather than a free-text string so "what actions exist?" is
    answerable by reading one file, and so the audit log cannot accumulate
    typos like `"approve"` vs `"aprovded"` that make a forensic search miss.
    """

    SCAN_RUN = "scan.run"
    FINDING_CREATED = "finding.created"
    FINDING_UPDATED = "finding.updated"
    FINDING_STATUS_CHANGED = "finding.status_changed"
    FINDING_REOPENED = "finding.reopened"
    TICKET_CREATED = "ticket.created"
    TICKET_UPDATED = "ticket.updated"
    REMEDIATION_PROPOSED = "remediation.proposed"
    REMEDIATION_REVISED = "remediation.revised"
    REMEDIATION_REJECTED = "remediation.rejected"
    REMEDIATION_ESCALATED = "remediation.escalated"
    PULL_REQUEST_DRAFTED = "pull_request.drafted"
    PULL_REQUEST_APPROVED = "pull_request.approved"
    PULL_REQUEST_REJECTED = "pull_request.rejected"
    AUTO_MERGE_BLOCKED = "pull_request.auto_merge_blocked"
    MCP_TOOL_INVOKED = "mcp.tool_invoked"
