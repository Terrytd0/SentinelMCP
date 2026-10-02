"""Remediation repositories: proposals, pull requests, and agent runs.

Grouped in one module because they are one aggregate -- a proposal has
decisions and at most one pull request -- and splitting them would mean three
files to read to answer "what happened to this finding?".
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.core.clock import utc_now
from backend.core.logging import get_logger
from backend.database.enums import (
    AgentDecision,
    AgentRole,
    ProposalStatus,
    PullRequestStatus,
)
from backend.database.models.remediation import (
    AgentRun,
    PullRequest,
    RemediationProposal,
)

logger = get_logger(__name__)


class RemediationRepository:
    """Data access for `remediation_proposals`, `pull_requests`, `agent_runs`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # --- Proposals -------------------------------------------------------

    async def create_proposal(
        self,
        *,
        finding_id: uuid.UUID,
        file_path: str,
        original_snippet: str,
        status: ProposalStatus = ProposalStatus.DRAFTING,
    ) -> RemediationProposal:
        """Start a new remediation attempt for a finding.

        Any earlier non-final proposal is marked `SUPERSEDED` first, so
        "the current attempt" is always the newest row and the rejected ones
        remain readable as history.
        """
        await self._supersede_open_proposals(finding_id)

        proposal = RemediationProposal(
            finding_id=finding_id,
            file_path=file_path,
            original_snippet=original_snippet,
            status=status,
        )
        self._session.add(proposal)
        await self._session.flush()
        logger.info(
            "created remediation proposal proposal_id=%s finding_id=%s", proposal.id, finding_id
        )
        return proposal

    async def _supersede_open_proposals(self, finding_id: uuid.UUID) -> None:
        open_states = [
            ProposalStatus.DRAFTING,
            ProposalStatus.UNDER_REVIEW,
            ProposalStatus.REVISION_REQUESTED,
        ]
        result = await self._session.execute(
            select(RemediationProposal).where(
                RemediationProposal.finding_id == finding_id,
                RemediationProposal.status.in_(open_states),
            )
        )
        for proposal in result.scalars().all():
            proposal.status = ProposalStatus.SUPERSEDED
        await self._session.flush()

    async def get_proposal(
        self, proposal_id: uuid.UUID, *, with_relations: bool = True
    ) -> RemediationProposal | None:
        statement = select(RemediationProposal).where(RemediationProposal.id == proposal_id)
        if with_relations:
            statement = statement.options(
                selectinload(RemediationProposal.pull_request),
                selectinload(RemediationProposal.agent_runs),
            )
        result = await self._session.execute(statement)
        return result.scalar_one_or_none()

    async def list_proposals_for_finding(
        self, finding_id: uuid.UUID, *, limit: int = 20
    ) -> list[RemediationProposal]:
        result = await self._session.execute(
            select(RemediationProposal)
            .where(RemediationProposal.finding_id == finding_id)
            .order_by(RemediationProposal.created_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def latest_proposal_for_finding(
        self, finding_id: uuid.UUID
    ) -> RemediationProposal | None:
        proposals = await self.list_proposals_for_finding(finding_id, limit=1)
        return proposals[0] if proposals else None

    async def record_patch(
        self,
        proposal_id: uuid.UUID,
        *,
        patch: str,
        summary: str,
        rationale: str,
    ) -> RemediationProposal | None:
        """Store the developer's output for a round."""
        proposal = await self.get_proposal(proposal_id, with_relations=False)
        if proposal is None:
            return None
        proposal.final_patch = patch
        proposal.summary = summary[:500]
        proposal.rationale = rationale
        await self._session.flush()
        return proposal

    async def record_review(
        self,
        proposal_id: uuid.UUID,
        *,
        round_index: int,
        decision: AgentDecision,
        message: str,
    ) -> RemediationProposal | None:
        """Append one reviewer's critique to the proposal's dialogue history."""
        proposal = await self.get_proposal(proposal_id, with_relations=False)
        if proposal is None:
            return None
        history = list(proposal.reviewer_feedback)
        history.append(
            {
                "round": round_index,
                "decision": decision.value,
                "message": message,
                "at": utc_now().isoformat(),
            }
        )
        proposal.reviewer_feedback = history
        proposal.rounds_completed = max(proposal.rounds_completed, round_index)
        await self._session.flush()
        return proposal

    async def finalize_proposal(
        self,
        proposal_id: uuid.UUID,
        *,
        status: ProposalStatus,
        escalated_reason: str | None = None,
    ) -> RemediationProposal | None:
        """Move a proposal to a final state, optionally with an escalation reason."""
        proposal = await self.get_proposal(proposal_id, with_relations=False)
        if proposal is None:
            return None
        proposal.status = status
        if escalated_reason is not None:
            proposal.escalated_reason = escalated_reason
        await self._session.flush()
        return proposal

    async def add_cost(
        self,
        proposal_id: uuid.UUID,
        *,
        llm_calls: int,
        tokens_used: int,
        cost_usd: float,
        latency_ms: float,
        llm_model: str | None,
    ) -> None:
        """Accumulate loop cost onto a proposal.

        Additive rather than overwriting so the per-round figures roll up to a
        total, which is what the fleet cost dashboard actually needs.
        """
        proposal = await self.get_proposal(proposal_id, with_relations=False)
        if proposal is None:
            return
        proposal.llm_calls += llm_calls
        proposal.tokens_used += tokens_used
        proposal.cost_usd = round(proposal.cost_usd + cost_usd, 6)
        proposal.latency_ms = round(proposal.latency_ms + latency_ms, 3)
        if llm_model:
            proposal.llm_model = llm_model
        await self._session.flush()

    # --- Agent runs ------------------------------------------------------

    async def add_agent_run(
        self,
        *,
        role: AgentRole,
        decision: AgentDecision,
        round_index: int,
        finding_id: uuid.UUID | None = None,
        proposal_id: uuid.UUID | None = None,
        rationale: str | None = None,
        message: str | None = None,
        llm_model: str | None = None,
        tokens_used: int = 0,
        cost_usd: float = 0.0,
        latency_ms: float = 0.0,
        correlation_id: str | None = None,
    ) -> AgentRun:
        """Record one agent turn.

        Every call is a row, including failed and escalating turns. A run that
        gave up after three rounds is *more* interesting to an auditor than one
        that succeeded first time, and it is exactly the run a system that only
        logs successes would lose.
        """
        run = AgentRun(
            role=role,
            decision=decision,
            round_index=round_index,
            finding_id=finding_id,
            proposal_id=proposal_id,
            rationale=rationale,
            # Truncated: an agent message can embed a whole source file, and
            # `message` exists for debugging, not as the durable record. The
            # durable record is `rationale` plus the patch on the proposal.
            message=message[:4000] if message else None,
            llm_model=llm_model,
            tokens_used=tokens_used,
            cost_usd=cost_usd,
            latency_ms=latency_ms,
            correlation_id=correlation_id,
        )
        self._session.add(run)
        await self._session.flush()
        return run

    async def list_agent_runs(
        self, *, proposal_id: uuid.UUID | None = None, finding_id: uuid.UUID | None = None
    ) -> list[AgentRun]:
        statement = select(AgentRun)
        if proposal_id is not None:
            statement = statement.where(AgentRun.proposal_id == proposal_id)
        if finding_id is not None:
            statement = statement.where(AgentRun.finding_id == finding_id)
        result = await self._session.execute(
            statement.order_by(AgentRun.round_index.asc(), AgentRun.created_at.asc())
        )
        return list(result.scalars().all())

    # --- Pull requests ---------------------------------------------------

    async def create_pull_request(
        self,
        *,
        proposal_id: uuid.UUID,
        number: int,
        title: str,
        body: str,
        branch: str,
        base_branch: str,
        target_repo: str,
        diff_url: str,
    ) -> PullRequest:
        """Create the draft pull request for an approved proposal.

        `auto_merge_blocked=True` is passed unconditionally. It is the only
        value this codebase will ever write to that column, and the default on
        the column is also `True`, so the guarantee does not depend on any
        caller remembering to pass it.
        """
        pull_request = PullRequest(
            proposal_id=proposal_id,
            number=number,
            title=title,
            body=body,
            branch=branch,
            base_branch=base_branch,
            target_repo=target_repo,
            diff_url=diff_url,
            status=PullRequestStatus.DRAFT,
            auto_merge_blocked=True,
        )
        self._session.add(pull_request)
        await self._session.flush()
        logger.info(
            "created draft pull request number=%d proposal_id=%s auto_merge_blocked=true",
            number,
            proposal_id,
        )
        return pull_request

    async def get_pull_request(self, pull_request_id: uuid.UUID) -> PullRequest | None:
        return await self._session.get(PullRequest, pull_request_id)

    async def get_pull_request_by_number(self, number: int) -> PullRequest | None:
        result = await self._session.execute(
            select(PullRequest).where(PullRequest.number == number)
        )
        return result.scalar_one_or_none()

    async def get_pull_request_for_proposal(self, proposal_id: uuid.UUID) -> PullRequest | None:
        result = await self._session.execute(
            select(PullRequest).where(PullRequest.proposal_id == proposal_id)
        )
        return result.scalar_one_or_none()

    async def list_pull_requests(
        self, *, statuses: Sequence[PullRequestStatus] | None = None, limit: int = 100
    ) -> list[PullRequest]:
        statement = select(PullRequest)
        if statuses:
            statement = statement.where(PullRequest.status.in_(list(statuses)))
        result = await self._session.execute(
            statement.order_by(PullRequest.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def list_awaiting_human(self, *, limit: int = 100) -> list[PullRequest]:
        """Drafts that no person has authorized yet.

        The approver's queue. Filters on `human_approved_at IS NULL` as well as
        status, so a record whose status was edited by a migration without its
        approval timestamp still shows up as pending rather than silently
        disappearing from the queue.
        """
        result = await self._session.execute(
            select(PullRequest)
            .where(
                PullRequest.status == PullRequestStatus.DRAFT,
                PullRequest.human_approved_at.is_(None),
            )
            .order_by(PullRequest.created_at.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def record_human_approval(
        self, pull_request_id: uuid.UUID, *, approver: str, now: datetime | None = None
    ) -> PullRequest | None:
        """Record that a person authorized the draft.

        This is the gate the whole design turns on. It sets a timestamp and an
        approver's name, and moves the record from `draft` to `open` -- which
        is a *label* meaning "a human has now looked at this and let it
        become visible for review in the git host". It does not merge
        anything; see `backend/services/approvals.py`.
        """
        pull_request = await self.get_pull_request(pull_request_id)
        if pull_request is None:
            return None
        moment = now or utc_now()
        pull_request.human_approver = approver
        pull_request.human_approved_at = moment
        pull_request.status = PullRequestStatus.OPEN
        await self._session.flush()
        logger.info(
            "recorded human approval pull_request_id=%s approver=%s", pull_request_id, approver
        )
        return pull_request

    async def record_human_rejection(
        self, pull_request_id: uuid.UUID, *, reviewer: str, reason: str
    ) -> PullRequest | None:
        pull_request = await self.get_pull_request(pull_request_id)
        if pull_request is None:
            return None
        pull_request.rejected_by = reviewer
        pull_request.rejected_at = utc_now()
        pull_request.rejection_reason = reason
        pull_request.status = PullRequestStatus.CLOSED
        await self._session.flush()
        return pull_request

    # --- Aggregates ------------------------------------------------------

    async def remediation_stats(self) -> dict[str, Any]:
        """Headline counters for the dashboard.

        Every one of these is a "how much of the queue is unattended?" number,
        which is the question the dashboard exists to answer.
        """
        proposal_rows = await self._session.execute(
            select(RemediationProposal.status, func.count()).group_by(RemediationProposal.status)
        )
        pull_request_rows = await self._session.execute(
            select(PullRequest.status, func.count()).group_by(PullRequest.status)
        )
        cost_row = await self._session.execute(
            select(
                func.coalesce(func.sum(RemediationProposal.cost_usd), 0.0),
                func.coalesce(func.sum(RemediationProposal.tokens_used), 0),
                func.count(),
            )
        )
        total_cost, total_tokens, proposal_count = cost_row.one()

        awaiting = await self._session.execute(
            select(func.count())
            .select_from(PullRequest)
            .where(
                PullRequest.status == PullRequestStatus.DRAFT,
                PullRequest.human_approved_at.is_(None),
            )
        )

        return {
            "proposals_by_status": {str(s): c for s, c in proposal_rows.all()},
            "pull_requests_by_status": {str(s): c for s, c in pull_request_rows.all()},
            "awaiting_human_approval": awaiting.scalar_one(),
            "total_llm_cost_usd": round(float(total_cost), 6),
            "total_llm_tokens": int(total_tokens),
            "total_proposals": int(proposal_count),
        }
