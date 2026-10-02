"""The agent-authored side of the system: remediation proposals, pull requests,
and every decision an agent made to get there.

These three tables plus `audit_logs` are what turn "an AI wrote some code" into
"here is the exact chain of reasoning, every round, with token and latency
cost attached, that a human can review before it is allowed to become a pull
request".
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from backend.database.enums import (
    AgentDecision,
    AgentRole,
    ProposalStatus,
    PullRequestStatus,
)
from backend.database.models.finding import _enum

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for type checkers only
    from backend.database.models.finding import Finding


class RemediationProposal(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One agent-drafted remediation, and the review dialogue that followed.

    A new row per attempt rather than an in-place update: when the reviewer
    rejects revision 1, revision 2 has to be able to point at what it was
    fixing, and "what the agent tried first" is evidence an auditor asks for.
    Superseded proposals are marked `SUPERSEDED` rather than deleted.
    """

    __tablename__ = "remediation_proposals"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[ProposalStatus] = mapped_column(
        _enum(ProposalStatus, "proposal_status"),
        default=ProposalStatus.DRAFTING,
        nullable=False,
    )

    # --- The work product ------------------------------------------------
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    """Repo-relative path the patch applies to. Constrained to the configured
    source roots by `backend/policy/rules.py` before the agent ever sees it."""

    original_snippet: Mapped[str] = mapped_column(Text, nullable=False)
    """The vulnerable lines as the scanner reported them. Kept verbatim so a
    reviewer can confirm the patch was built against the real code."""

    final_patch: Mapped[str | None] = mapped_column(Text, default=None)
    """Unified diff, after the last revision. Null while still drafting."""

    rationale: Mapped[str | None] = mapped_column(Text, default=None)
    """The developer's own explanation of the change, in its own words. Carried
    into the pull request body so the human approver reads the agent's
    reasoning rather than being asked to reverse-engineer it from the diff."""

    summary: Mapped[str | None] = mapped_column(String(500), default=None)

    # --- The review dialogue --------------------------------------------
    rounds_completed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    reviewer_feedback: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    """Append-only critique history: `[{round, reviewer_message, decision, ...}]`.
    Kept as a list rather than a separate table because it is only ever read
    as a whole, in order, attached to its proposal."""

    escalated_reason: Mapped[str | None] = mapped_column(Text, default=None)
    """Why the loop gave up, when it gave up. A non-null value here is the
    single most useful field for a human picking up the queue: it says the
    agents tried and could not converge, rather than that nobody looked."""

    # --- Cost attribution (feeds the Aegis fleet cost dashboard) ---------
    llm_calls: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    llm_model: Mapped[str | None] = mapped_column(String(120), default=None)
    """`None` for the deterministic loop, which makes "how much of the
    remediation volume was actually LLM-driven?" a single GROUP BY."""

    finding: Mapped[Finding] = relationship(back_populates="proposals")  # noqa: F821
    pull_request: Mapped[PullRequest | None] = relationship(  # noqa: F821
        back_populates="proposal", uselist=False, lazy="selectin"
    )
    agent_runs: Mapped[list[AgentRun]] = relationship(  # noqa: F821
        back_populates="proposal", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (Index("ix_remediation_proposals_status", "status"),)


class PullRequest(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A drafted remediation pull request awaiting human approval.

    **This table has no code path that sets `status = MERGED`.** The column
    exists because a human merging the branch in a real git host is a real
    outcome the system must be able to *record* -- but the write that would
    make the system itself able to cause a merge does not exist. The
    `auto_merge_blocked` boolean below is the enforced, auditable version of
    that claim: `backend/services/approvals.py` sets it to `True` on every
    pull request it creates, and
    `tests/integration/test_api_and_approval.py::test_no_code_path_merges_a_pull_request`
    is the regression test that keeps it true.

    The git side is simulated (`backend/services/publisher.py`): this project
    will not push to a real repository, so `branch` and `diff_url` are
    deterministic fakes and no credentials are ever required or read.
    """

    __tablename__ = "pull_requests"

    proposal_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("remediation_proposals.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )

    number: Mapped[int] = mapped_column(Integer, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    branch: Mapped[str] = mapped_column(String(255), nullable=False)
    base_branch: Mapped[str] = mapped_column(String(255), nullable=False)
    target_repo: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[PullRequestStatus] = mapped_column(
        _enum(PullRequestStatus, "pull_request_status"),
        default=PullRequestStatus.DRAFT,
        nullable=False,
    )
    diff_url: Mapped[str | None] = mapped_column(String(1000), default=None)

    auto_merge_blocked: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    """Always `True`. Present so the guarantee is a queryable, auditable fact
    about every row rather than a claim in a README -- an operator can run one
    query and prove no pull request in the system is mergeable by machine."""

    # --- Human gate ------------------------------------------------------
    human_approver: Mapped[str | None] = mapped_column(String(255), default=None)
    human_approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    rejected_by: Mapped[str | None] = mapped_column(String(255), default=None)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    rejection_reason: Mapped[str | None] = mapped_column(Text, default=None)

    proposal: Mapped[RemediationProposal] = relationship(back_populates="pull_request")  # noqa: F821

    @property
    def is_awaiting_human(self) -> bool:
        """Drafted by the agents, not yet authorized by a person."""
        return self.status == PullRequestStatus.DRAFT and self.human_approved_at is None


class AgentRun(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """One agent turn: a prompt in, a decision and a patch out, with cost.

    This is the row that makes the system auditable rather than merely
    automatic. Every loop iteration, every reviewer critique, every escalation
    is one of these, in order, with the model that produced it and what it
    cost. "Why did the agent touch this file?" is answered by reading the
    `proposal_id` chain here, not by re-running anything.
    """

    __tablename__ = "agent_runs"

    proposal_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("remediation_proposals.id", ondelete="CASCADE"), default=None, index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(default=None, index=True)

    role: Mapped[AgentRole] = mapped_column(_enum(AgentRole, "agent_role"), nullable=False)
    round_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    decision: Mapped[AgentDecision] = mapped_column(
        _enum(AgentDecision, "agent_decision"), nullable=False
    )
    """What this turn concluded. The developer's first turn is `PROPOSE`, the
    reviewer's is `APPROVE` or `REQUEST_CHANGES`, and a loop that runs out of
    rounds ends in `ESCALATE`."""

    rationale: Mapped[str | None] = mapped_column(Text, default=None)
    """The agent's stated reasoning. Optional in principle, but in practice
    this is the field an auditor reads first, so the prompts require it."""

    message: Mapped[str | None] = mapped_column(Text, default=None)
    """Raw agent output, truncated. Kept for debugging a bad patch; may
    contain a source snippet, so it is never emitted to telemetry."""

    llm_model: Mapped[str | None] = mapped_column(String(120), default=None)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(120), default=None)

    proposal: Mapped[RemediationProposal | None] = relationship(back_populates="agent_runs")  # noqa: F821

    __table_args__ = (
        Index("ix_agent_runs_proposal_round", "proposal_id", "round_index"),
        Index("ix_agent_runs_finding_created", "finding_id", "created_at"),
    )
