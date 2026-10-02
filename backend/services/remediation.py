"""The remediation service: run the agent loop, persist everything, open a draft PR.

The orchestrator for the AI half of the system. Its job is to make the loop's
decision *auditable* -- every turn becomes an `agent_runs` row, every draft
becomes a `remediation_proposals` row, and the outcome is written to
`audit_logs` before the loop's caller is told anything.

The ordering here is deliberate and is the safety property:

    1. policy gate           -- may the agent touch this finding at all?
    2. create the proposal   -- a row exists *before* any code is generated
    3. run the loop          -- with every turn persisted as it happens
    4. finalize the proposal -- approved / rejected / escalated, with a reason
    5. only if approved      -- draft a pull request, still blocked from merge

Step 5's condition is the important one. A rejected or escalated loop leaves a
proposal and a full transcript and creates *no* pull request, so there is
nothing a human can be tricked into opening. The proposal is the record; the
PR is the artifact.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents.autogen_loop import (
    LoopResult,
    build_engine,
    run_remediation_loop,
)
from backend.agents.deterministic import RemediationEngine
from backend.config.settings import get_settings
from backend.core.asyncio_utils import run_sync
from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import (
    AgentDecision,
    AgentRole,
    AuditAction,
    FindingStatus,
    ProposalStatus,
)
from backend.database.models.finding import Finding
from backend.database.models.remediation import RemediationProposal
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.policy.rules import (
    AutoRemediationRefusal,
    evaluate_auto_remediation,
)
from backend.scanners.snippet import EnrichedSnippet, enrich_snippet
from backend.telemetry import get_telemetry_client
from backend.telemetry.events import EventStatus

logger = get_logger(__name__)


class RemediationRefusedError(RuntimeError):
    """Policy refused to let the agent remediate this finding.

    Carries the machine-readable refusal so an MCP client or an API caller can
    branch on it, and the human-readable reason to show the operator.
    """

    def __init__(self, refusal: AutoRemediationRefusal, reason: str) -> None:
        super().__init__(reason)
        self.refusal = refusal
        self.reason = reason


@dataclass(slots=True)
class RemediationOutcome:
    """What the agent did about a finding."""

    finding: Finding
    proposal: RemediationProposal
    result: LoopResult
    pull_request_id: uuid.UUID | None = None
    correlation_id: str = ""

    @property
    def approved(self) -> bool:
        return self.result.approved

    @property
    def draft_ready(self) -> bool:
        """A draft PR exists and is waiting for a human. Never merged."""
        return self.pull_request_id is not None

    def summary(self) -> dict[str, Any]:
        return {
            "finding_id": str(self.finding.id),
            "proposal_id": str(self.proposal.id),
            "outcome": self.result.outcome,
            "approved": self.result.approved,
            "rounds": self.result.rounds_completed,
            "llm_calls": self.result.llm_calls,
            "tokens_used": self.result.tokens_used,
            "cost_usd": self.result.cost_usd,
            "latency_ms": round(self.result.latency_ms, 2),
            "llm_model": self.result.llm_model,
            "draft_pull_request_id": str(self.pull_request_id) if self.pull_request_id else None,
            "requires_human_approval": self.draft_ready,
            "correlation_id": self.correlation_id,
        }


class RemediationService:
    """Drives the agent loop against a finding and records all of it."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        engine: RemediationEngine | None = None,
        audit: AuditRepository | None = None,
    ) -> None:
        self._session = session
        self._engine = engine
        self._findings = FindingRepository(session)
        self._remediations = RemediationRepository(session)
        self._audit = audit or AuditRepository(session)
        self._tickets = TicketRepository(session)
        self._telemetry = get_telemetry_client()

    def _resolve_engine(self) -> RemediationEngine:
        return self._engine if self._engine is not None else build_engine()

    async def remediate(
        self,
        finding_id: uuid.UUID,
        *,
        actor: str = "agent:developer",
        correlation_id: str | None = None,
        open_ticket: bool = True,
    ) -> RemediationOutcome:
        """Draft a remediation for one finding, then draft a PR if it is approved."""
        correlation = correlation_id or new_correlation_id()

        finding = await self._findings.get(finding_id)
        if finding is None:
            raise LookupError(f"finding {finding_id} does not exist")

        self._assert_allowed(finding)

        # The scanner reported one line. The reviewer judges a multi-line patch,
        # and its scope check needs enough source to judge against -- so the loop
        # is shown the finding's enclosing block. Measured over 30 real merged
        # security fixes, that is the difference between 9 rejections and 3.
        # See backend/scanners/snippet.py and docs/evidence.md.
        #
        # `finding.snippet` is deliberately *not* rewritten: a finding records
        # what the detector found, and widening it would make the database and
        # the MCP tool output misstate the detector's precision. The proposal
        # row below records what the agent was actually shown, which is the
        # honest thing for an audit trail to hold.
        snippet = self._widen_snippet(finding)

        # 2. The proposal row exists before any code is generated, so a crash
        #    mid-loop leaves a "drafting" record rather than no trace at all.
        proposal = await self._remediations.create_proposal(
            finding_id=finding_id,
            file_path=finding.file_path or "",
            original_snippet=snippet.text,
            status=ProposalStatus.DRAFTING,
        )
        await self._findings.increment_remediation_attempts([finding_id])
        await self._findings.update_status(finding_id, FindingStatus.IN_PROGRESS)
        await self._audit.append(
            actor=actor,
            action=AuditAction.REMEDIATION_PROPOSED,
            entity_type="remediation_proposal",
            entity_id=proposal.id,
            correlation_id=correlation,
            summary=f"agent started remediation for {finding.title!r}",
            payload={
                "finding_id": str(finding_id),
                "file_path": finding.file_path,
                "severity": finding.severity.value,
                "engine": (self._resolve_engine().model_name or "deterministic"),
                "snippet_strategy": snippet.strategy.value,
                "snippet_lines": snippet.line_count,
            },
        )

        with self._telemetry.measure(
            "remediation.loop",
            correlation_id=correlation,
            metadata={"finding_id": str(finding_id), "severity": finding.severity.value},
        ) as measurement:
            result: LoopResult = await run_sync(
                run_remediation_loop,
                self._resolve_engine(),
                snippet=snippet.text,
                file_path=finding.file_path or "",
                rule_id=finding.rule_id,
                cwe_ids=list(finding.cwe_ids),
                correlation_id=correlation,
            )
            measurement.tokens_used = result.tokens_used
            measurement.cost = result.cost_usd
            measurement.metadata = {
                "finding_id": str(finding_id),
                "outcome": result.outcome,
                "rounds": result.rounds_completed,
                "llm_calls": result.llm_calls,
            }

        await self._persist_transcript(
            proposal, result, finding_id=finding_id, correlation=correlation
        )

        pull_request_id: uuid.UUID | None = None
        if result.approved:
            pull_request_id = await self._draft_pull_request(
                finding=finding,
                proposal=proposal,
                result=result,
                actor=actor,
                correlation=correlation,
            )
        else:
            await self._record_negative_outcome(
                finding=finding, proposal=proposal, result=result, correlation=correlation
            )

        if open_ticket:
            await self._ensure_ticket(
                finding=finding, result=result, actor=actor, correlation=correlation
            )

        refreshed = await self._findings.get(finding_id)
        return RemediationOutcome(
            finding=refreshed or finding,
            proposal=proposal,
            result=result,
            pull_request_id=pull_request_id,
            correlation_id=correlation,
        )

    # --- Policy ----------------------------------------------------------

    def _widen_snippet(self, finding: Finding) -> EnrichedSnippet:
        """The source the loop is shown, widened from the scanner's one line.

        Runs *after* `_assert_allowed`, so the path has already been through the
        operator's allow-list and this reads the same file the rest of the loop
        is about to patch. Never raises: a file that has moved, or a finding with
        no line numbers, leaves the scanner's own text in place.
        """
        return enrich_snippet(
            file_path=finding.file_path or "",
            reported=finding.snippet or "",
            start_line=finding.start_line,
            end_line=finding.end_line,
            max_lines=get_settings().remediation_snippet_max_lines,
        )

    def _assert_allowed(self, finding: Finding) -> None:
        """Refuse unless policy allows auto-remediation of this finding.

        Evaluated fresh here rather than trusting the stored
        `auto_remediation_eligible` flag. The flag was written at scan time;
        between then and now the finding may have been triaged, closed, or
        retried past the attempt budget. Re-checking is one cheap call and
        closes the window in which a stale flag would let the agent act.

        `source_roots` is read from settings rather than left to the policy
        module's default, so `SENTINEL_REMEDIATION_SOURCE_ROOTS` is the single
        place the writable-area policy is defined. An agent that can patch
        `infra/terraform/prod/` can break production, so the allow-list has to
        be operator-configurable rather than a constant buried in a rule module.
        """
        from backend.config.settings import get_settings

        decision = evaluate_auto_remediation(
            severity=finding.severity,
            confidence=finding.confidence,
            status=finding.status,
            file_path=finding.file_path,
            snippet=finding.snippet,
            remediation_attempts=finding.remediation_attempts,
            source_roots=tuple(get_settings().remediation_source_roots),
        )
        if not decision.eligible:
            logger.info(
                "auto-remediation refused finding_id=%s refusal=%s", finding.id, decision.refusal
            )
            raise RemediationRefusedError(decision.refusal, decision.reason)

    # --- Persistence -----------------------------------------------------

    async def _persist_transcript(
        self,
        proposal: RemediationProposal,
        result: LoopResult,
        *,
        finding_id: uuid.UUID,
        correlation: str,
    ) -> None:
        """Write every agent turn, then finalize the proposal.

        Turns are persisted as they complete inside the loop *and* the summary
        is written here, so the proposal row is consistent with the run history
        even if the loop is interrupted between the two.
        """
        for entry in result.transcript():
            await self._remediations.add_agent_run(
                role=AgentRole.DEVELOPER,
                decision=AgentDecision(entry["developer_decision"]),
                round_index=entry["round"],
                finding_id=finding_id,
                proposal_id=proposal.id,
                rationale=entry["developer_rationale"],
                message=entry["developer_summary"],
                tokens_used=entry["developer_tokens"],
                cost_usd=entry["developer_cost_usd"],
                correlation_id=correlation,
            )
            if entry["reviewer_decision"] is not None:
                await self._remediations.add_agent_run(
                    role=AgentRole.REVIEWER,
                    decision=AgentDecision(entry["reviewer_decision"]),
                    round_index=entry["round"],
                    finding_id=finding_id,
                    proposal_id=proposal.id,
                    message=entry["reviewer_message"],
                    correlation_id=correlation,
                )

        await self._remediations.add_cost(
            proposal.id,
            llm_calls=result.llm_calls,
            tokens_used=result.tokens_used,
            cost_usd=result.cost_usd,
            latency_ms=result.latency_ms,
            llm_model=result.llm_model,
        )

        if result.patch:
            await self._remediations.record_patch(
                proposal.id,
                patch=result.patch,
                summary=result.summary,
                rationale=result.rationale,
            )
        for record in result.rounds:
            if record.reviewer is not None:
                await self._remediations.record_review(
                    proposal.id,
                    round_index=record.round_index,
                    decision=record.reviewer.decision,
                    message=record.reviewer.message,
                )

        status = {
            "approved": ProposalStatus.APPROVED,
            "rejected": ProposalStatus.REJECTED,
            "escalated": ProposalStatus.ESCALATED,
        }[result.outcome]
        await self._remediations.finalize_proposal(
            proposal.id, status=status, escalated_reason=result.escalated_reason
        )

    async def _record_negative_outcome(
        self,
        *,
        finding: Finding,
        proposal: RemediationProposal,
        result: LoopResult,
        correlation: str,
    ) -> None:
        """Record a rejected or escalated loop.

        The finding goes to `TRIAGED`, not back to `OPEN` and not left in
        `IN_PROGRESS`. `OPEN` would claim nobody has looked at it, when an agent
        has now looked and declined; `IN_PROGRESS` would park it in a state no
        human is watching. `TRIAGED` is the honest middle: a human has to make a
        call, and the SLA clock keeps running.
        """
        action = (
            AuditAction.REMEDIATION_REJECTED
            if result.outcome == "rejected"
            else AuditAction.REMEDIATION_ESCALATED
        )
        await self._findings.update_status(finding.id, FindingStatus.TRIAGED)
        await self._audit.append(
            actor="agent:reviewer",
            action=action,
            entity_type="remediation_proposal",
            entity_id=proposal.id,
            correlation_id=correlation,
            summary=f"agent {result.outcome} remediation for {finding.title!r}",
            payload={
                "finding_id": str(finding.id),
                "outcome": result.outcome,
                "rounds": result.rounds_completed,
                "reason": result.escalated_reason,
                "reviewer_comments": result.all_feedback()[:10],
            },
        )
        self._telemetry.emit(
            "remediation.outcome",
            status=EventStatus.SUCCESS,
            correlation_id=correlation,
            tokens_used=result.tokens_used,
            cost=result.cost_usd,
            metadata={"finding_id": str(finding.id), "outcome": result.outcome},
        )

    # --- Pull requests ---------------------------------------------------

    async def _draft_pull_request(
        self,
        *,
        finding: Finding,
        proposal: RemediationProposal,
        result: LoopResult,
        actor: str,
        correlation: str,
    ) -> uuid.UUID:
        """Open a *draft* pull request for an agent-approved patch.

        The draft is the end of the automated pipeline. Opening it does not
        merge it, and `auto_merge_blocked` is set to `True` by the repository
        layer unconditionally, so there is no branch in the code that produces
        a mergeable pull request.
        """
        from backend.services.publisher import (
            PublishedDraft,
            build_pull_request_body,
            publish_draft,
        )

        body = build_pull_request_body(
            finding=finding,
            proposal=proposal,
            result=result,
        )
        published: PublishedDraft = await run_sync(
            publish_draft,
            title=f"[SentinelMCP] {result.summary}"[:500],
            body=body,
            patch=result.patch or "",
            file_path=finding.file_path or "",
        )

        existing = await self._remediations.get_pull_request_for_proposal(proposal.id)
        if existing is not None:
            return existing.id

        number = await self._next_pull_request_number()
        pull_request = await self._remediations.create_pull_request(
            proposal_id=proposal.id,
            number=number,
            title=f"[SentinelMCP] {result.summary}"[:500],
            body=body,
            branch=published.branch,
            base_branch=published.base_branch,
            target_repo=published.target_repo,
            diff_url=published.diff_url,
        )
        await self._findings.update_status(finding.id, FindingStatus.AWAITING_REVIEW)
        await self._audit.append(
            actor=actor,
            action=AuditAction.PULL_REQUEST_DRAFTED,
            entity_type="pull_request",
            entity_id=pull_request.id,
            correlation_id=correlation,
            summary=f"drafted PR #{number} for {finding.title!r}",
            payload={
                "finding_id": str(finding.id),
                "proposal_id": str(proposal.id),
                "number": number,
                "branch": published.branch,
                "auto_merge_blocked": True,
            },
        )
        return pull_request.id

    async def _next_pull_request_number(self) -> int:
        """Monotonic PR number.

        Derived from the count of existing pull requests rather than a database
        sequence, because a gap in the numbering is cosmetic and a duplicate
        is not. In a real deployment this would be the PR number the git host
        assigns on push; here it is a local counter that stands in for it.
        """
        existing = await self._remediations.list_pull_requests(limit=10_000)
        return (max((pr.number for pr in existing), default=1000)) + 1

    # --- Tickets ---------------------------------------------------------

    async def _ensure_ticket(
        self,
        *,
        finding: Finding,
        result: LoopResult,
        actor: str,
        correlation: str,
    ) -> None:
        """Open a ticket so a human always ends up with a work item.

        For an approved remediation the ticket is "review the draft PR". For an
        escalation it is "the agents could not fix this, please look". Either
        way nothing the agent does leaves a finding with no human-visible
        action, which is the property that makes the whole thing safe to run
        unattended.
        """
        existing = await self._tickets.list_for_finding(finding.id)
        if existing:
            return

        title = (
            f"Review draft remediation for {finding.title}"
            if result.approved
            else f"Agent escalated: {finding.title}"
        )
        description = (
            f"Rule: {finding.rule_id}\n"
            f"File: {finding.file_path}:{finding.start_line}\n"
            f"Severity: {finding.severity.value} (confidence {finding.confidence.value})\n\n"
            f"Agent outcome: {result.outcome} after {result.rounds_completed} round(s).\n"
            f"Reason: {result.escalated_reason or 'see proposal for the full transcript'}\n"
        )
        ticket = await self._tickets.create_ticket(
            finding_id=finding.id,
            title=title,
            description=description,
            priority=finding.severity,
            created_by=actor,
        )
        await self._audit.append(
            actor=actor,
            action=AuditAction.TICKET_CREATED,
            entity_type="ticket",
            entity_id=ticket.id,
            correlation_id=correlation,
            summary=f"opened {ticket.ticket_key} for {finding.title!r}",
            payload={
                "finding_id": str(finding.id),
                "ticket_key": ticket.ticket_key,
                "agent_outcome": result.outcome,
            },
        )
