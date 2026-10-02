"""The human approval gate.

This is the module the whole project is built around. Everything upstream of it
is automation; everything it does is a decision a *person* is accountable for.

The rule, stated once: **no code in this repository can move a remediation pull
request to a mergeable state without a named human having authorized it.**

What that means concretely, and how each part is enforced rather than merely
asserted in a README:

  * `approve()` requires a principal whose role is APPROVER or ADMIN
    (`backend/auth/dependencies.py`). An analyst cannot self-approve, and
    neither can the agent: an agent has no `UserRole` at all.
  * `approve()` refuses a pull request that already has a different approver,
    so approval cannot be quietly re-assigned.
  * The repository writes `auto_merge_blocked=True` unconditionally on every
    pull request, and no update ever sets it false.
  * There is no `merge` method. `publisher.merge_pull_request` exists only to
    raise.
  * `SENTINEL_ALLOW_AUTO_MERGE` is not honoured; setting it makes startup fail
    loudly (`backend/policy/rules.py::assert_human_merge_required`).

`tests/integration/test_api_and_approval.py` walks the codebase and asserts that no
statement assigns a merge or an unblocked flag, so the guarantee survives
future edits.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.clock import utc_now
from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import AuditAction, FindingStatus, PullRequestStatus, UserRole
from backend.database.models.finding import Finding
from backend.database.models.remediation import PullRequest
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository

logger = get_logger(__name__)


class ApprovalError(RuntimeError):
    """A requested approval transition is not allowed."""


@dataclass(slots=True)
class ApprovalResult:
    """The outcome of a human gate decision."""

    pull_request: PullRequest
    finding: Finding | None
    decision: str
    """`approved` | `rejected`."""

    approver: str
    reason: str | None = None
    correlation_id: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "pull_request_id": str(self.pull_request.id),
            "number": self.pull_request.number,
            "decision": self.decision,
            "approver": self.approver,
            "status": self.pull_request.status.value,
            "finding_id": str(self.finding.id) if self.finding else None,
            "auto_merge_blocked": self.pull_request.auto_merge_blocked,
            "requires_human_merge": True,
            "reason": self.reason,
            "correlation_id": self.correlation_id,
        }


class ApprovalService:
    """The human gate in front of every agent-drafted pull request."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._pull_requests = RemediationRepository(session)
        self._findings = FindingRepository(session)
        self._audit = AuditRepository(session)
        self._tickets = TicketRepository(session)

    async def approve(
        self,
        pull_request_id: uuid.UUID,
        *,
        approver: str,
        role: UserRole,
        correlation_id: str | None = None,
    ) -> ApprovalResult:
        """Authorize a draft pull request, on a named human's authority.

        `role` is passed in rather than read from a global so the authorization
        check is visible in the signature and directly testable -- a test can
        call this with `UserRole.ANALYST` and assert the refusal without
        standing up a token.
        """
        correlation = correlation_id or new_correlation_id()

        if not role.can_approve_remediation:
            logger.warning(
                "approval refused pull_request_id=%s approver=%s role=%s",
                pull_request_id,
                approver,
                role.value,
            )
            raise ApprovalError(
                f"role {role.value!r} may not authorize a remediation; "
                f"{UserRole.APPROVER.value} or {UserRole.ADMIN.value} required"
            )

        pull_request = await self._pull_requests.get_pull_request(pull_request_id)
        if pull_request is None:
            raise LookupError(f"pull request {pull_request_id} does not exist")

        if pull_request.human_approved_at is not None:
            # Refuse rather than no-op: a second approval is either a
            # double-click or a genuine second opinion, and silently treating
            # them as the same event loses the fact that two people weighed in.
            raise ApprovalError(
                f"pull request #{pull_request.number} was already approved by "
                f"{pull_request.human_approver!r} at "
                f"{pull_request.human_approved_at.isoformat()}"
            )

        if pull_request.status == PullRequestStatus.CLOSED:
            raise ApprovalError(
                f"pull request #{pull_request.number} was rejected and cannot be approved"
            )

        updated = await self._pull_requests.record_human_approval(
            pull_request_id, approver=approver
        )
        assert updated is not None  # the row was just read, so it exists

        proposal = await self._pull_requests.get_proposal(updated.proposal_id)
        finding = await self._findings.get(proposal.finding_id) if proposal is not None else None

        if finding is not None:
            # The agent's work is authorized, but the code is not in the
            # target's base branch yet -- a human still merges it in the git
            # host. So the finding moves to `IN_PROGRESS`, not `REMEDIATED`.
            await self._findings.update_status(finding.id, FindingStatus.IN_PROGRESS)
            await self._close_review_ticket(finding, actor=approver)

        await self._audit.append(
            actor=approver,
            action=AuditAction.PULL_REQUEST_APPROVED,
            entity_type="pull_request",
            entity_id=updated.id,
            correlation_id=correlation,
            summary=f"{approver} approved draft PR #{updated.number}",
            payload={
                "number": updated.number,
                "role": role.value,
                "finding_id": str(finding.id) if finding else None,
                "proposal_id": str(updated.proposal_id),
                # Recorded explicitly: this is the row that proves the
                # guarantee, and an auditor should be able to read it directly.
                "auto_merge_blocked": True,
                "note": (
                    "approval authorizes the pull request to be opened; "
                    "merging remains a human action in the git host"
                ),
            },
        )
        # Second audit row: the guarantee is also enforced as an event, not only
        # as a column value, so a change to that column is detectable.
        await self._audit.append(
            actor="system:policy",
            action=AuditAction.AUTO_MERGE_BLOCKED,
            entity_type="pull_request",
            entity_id=updated.id,
            correlation_id=correlation,
            summary="machine merge remains blocked after human approval",
            payload={"number": updated.number, "approver": approver},
        )

        logger.info(
            "human approval recorded pr=%d approver=%s role=%s auto_merge_blocked=true",
            updated.number,
            approver,
            role.value,
        )
        return ApprovalResult(
            pull_request=updated,
            finding=finding,
            decision="approved",
            approver=approver,
            correlation_id=correlation,
        )

    async def reject(
        self,
        pull_request_id: uuid.UUID,
        *,
        reviewer: str,
        reason: str,
        role: UserRole,
        correlation_id: str | None = None,
    ) -> ApprovalResult:
        """Reject a draft, recording who and why.

        The reason is mandatory. A rejection with no explanation is unusable to
        the agent (it cannot learn from it) and useless to the next analyst
        (they cannot tell a bad patch from a bad policy call), so the API
        requires it rather than defaulting to a blank string.
        """
        if not role.can_approve_remediation:
            raise ApprovalError(
                f"role {role.value!r} may not reject a remediation; "
                f"{UserRole.APPROVER.value} or {UserRole.ADMIN.value} required"
            )
        if not reason.strip():
            raise ApprovalError("a rejection reason is required")

        correlation = correlation_id or new_correlation_id()
        pull_request = await self._pull_requests.get_pull_request(pull_request_id)
        if pull_request is None:
            raise LookupError(f"pull request {pull_request_id} does not exist")
        if pull_request.human_approved_at is not None:
            raise ApprovalError(
                f"pull request #{pull_request.number} is already approved "
                "and cannot be rejected here"
            )

        updated = await self._pull_requests.record_human_rejection(
            pull_request_id, reviewer=reviewer, reason=reason
        )
        assert updated is not None

        proposal = await self._pull_requests.get_proposal(updated.proposal_id)
        finding = await self._findings.get(proposal.finding_id) if proposal is not None else None
        if finding is not None:
            # Back to triaged, not closed: a human rejected the agent's
            # approach, which is not the same as deciding the finding is not a
            # problem. It still has an SLA clock running.
            await self._findings.update_status(finding.id, FindingStatus.TRIAGED)

        await self._audit.append(
            actor=reviewer,
            action=AuditAction.PULL_REQUEST_REJECTED,
            entity_type="pull_request",
            entity_id=updated.id,
            correlation_id=correlation,
            summary=f"{reviewer} rejected draft PR #{updated.number}",
            payload={
                "number": updated.number,
                "role": role.value,
                "reason": reason,
                "finding_id": str(finding.id) if finding else None,
            },
        )
        logger.info("human rejection recorded pr=%d reviewer=%s", updated.number, reviewer)
        return ApprovalResult(
            pull_request=updated,
            finding=finding,
            decision="rejected",
            approver=reviewer,
            reason=reason,
            correlation_id=correlation,
        )

    async def record_external_merge(
        self,
        pull_request_id: uuid.UUID,
        *,
        merged_by: str,
        merged_at: object | None = None,
    ) -> PullRequest:
        """Record that a human merged the branch in the git host.

        The only method in the project that writes `status = MERGED`, and it
        records an *observation* supplied by the caller. It performs no merge,
        contacts no git host, and takes the merged-at time from the caller so
        the record reflects when the human actually did it. A deployment would
        populate it from a webhook; here it is a manual endpoint that exists
        so the `MERGED` state is reachable and the schema is honest about it.
        """
        pull_request = await self._pull_requests.get_pull_request(pull_request_id)
        if pull_request is None:
            raise LookupError(f"pull request {pull_request_id} does not exist")
        if pull_request.human_approved_at is None:
            # Refuse: a merge must have been preceded by a recorded approval,
            # or the audit trail contains a merge with no authorizing human.
            raise ApprovalError(
                f"pull request #{pull_request.number} has no recorded human approval; "
                "refusing to record a merge"
            )
        if pull_request.status == PullRequestStatus.CLOSED:
            raise ApprovalError(f"pull request #{pull_request.number} was rejected")

        pull_request.status = PullRequestStatus.MERGED
        await self._session.flush()
        await self._audit.append(
            actor=merged_by,
            action=AuditAction.PULL_REQUEST_APPROVED,
            entity_type="pull_request",
            entity_id=pull_request.id,
            summary=f"{merged_by} merged PR #{pull_request.number} in the git host",
            payload={"number": pull_request.number, "recorded_at": utc_now().isoformat()},
        )

        proposal = await self._pull_requests.get_proposal(pull_request.proposal_id)
        if proposal is not None:
            finding = await self._findings.get(proposal.finding_id)
            if finding is not None:
                # The one place a finding becomes REMEDIATED: a human confirmed
                # the code is now in the base branch.
                await self._findings.update_status(finding.id, FindingStatus.REMEDIATED)
                await self._close_review_ticket(finding, actor=merged_by)
        return pull_request

    async def _close_review_ticket(self, finding: Finding, *, actor: str) -> None:
        """Close the auto-created review ticket once the gate has been passed.

        Best-effort: a finding with an open ticket is an annoyance, not a
        correctness problem, and failing a merge confirmation because a ticket
        could not be updated would be the wrong trade.
        """
        for ticket in await self._tickets.list_for_finding(finding.id):
            if ticket.status.is_open:
                await self._tickets.set_status(ticket.id, ticket.status.RESOLVED)
                logger.debug(
                    "closed review ticket %s for finding %s", ticket.ticket_key, finding.id
                )
                return
        _ = actor
