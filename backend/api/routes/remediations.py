"""Remediation and pull-request routes -- including the human approval gate.

This is the module where the safety property is exposed over HTTP, and the
route signatures are the documentation for it:

    POST /remediations                     run the loop, draft a PR    ANALYST
    POST /pull-requests/{id}/approve       authorize the draft         APPROVER
    POST /pull-requests/{id}/reject        reject it, with a reason    APPROVER
    POST /pull-requests/{id}/merged        record an observed merge    APPROVER

The role requirement is declared in each signature via `ApproverPrincipal`, so
it appears in the generated OpenAPI schema as well as being enforced in code.

And there is no `POST /pull-requests/{id}/merge` route, because there is no
such operation. `tests/integration/test_api_and_approval.py` asserts that the
route table contains no merge endpoint, so adding one cannot happen quietly.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query, status

from backend.api.dependencies import (
    ApproverPrincipal,
    CurrentPrincipal,
    DbSession,
)
from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import PullRequestStatus
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.schemas.contracts import (
    AgentRunResponse,
    ApprovePullRequestRequest,
    PullRequestResponse,
    RecordMergeRequest,
    RejectPullRequestRequest,
    RemediateRequest,
    RemediateResponse,
    RemediationProposalResponse,
)
from backend.services.approvals import ApprovalError, ApprovalService
from backend.services.remediation import RemediationRefusedError, RemediationService

logger = get_logger(__name__)

router = APIRouter(tags=["remediation"])


@router.post("/remediations", response_model=RemediateResponse)
async def remediate(
    payload: RemediateRequest,
    session: DbSession,
    principal: CurrentPrincipal,
) -> RemediateResponse:
    """Run the developer/reviewer loop against one finding.

    Any analyst may trigger this. What they may not do is merge the result, and
    `requires_human_approval` in the response is always true when a draft was
    opened.
    """
    correlation_id = payload.correlation_id or new_correlation_id()
    service = RemediationService(session)

    try:
        outcome = await service.remediate(
            payload.finding_id,
            actor=principal.audit_actor,
            correlation_id=correlation_id,
            open_ticket=payload.open_ticket,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except RemediationRefusedError as exc:
        # 422, not 403: the caller is authorized, the *request* is not possible.
        # The machine-readable refusal is in the detail so a client can branch.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "error": "policy_refused",
                "refusal": exc.refusal.value,
                "reason": exc.reason,
            },
        ) from exc

    result = outcome.result
    return RemediateResponse(
        finding_id=outcome.finding.id,
        proposal_id=outcome.proposal.id,
        outcome=result.outcome,
        approved=result.approved,
        rounds=result.rounds_completed,
        llm_calls=result.llm_calls,
        tokens_used=result.tokens_used,
        cost_usd=result.cost_usd,
        latency_ms=result.latency_ms,
        llm_model=result.llm_model,
        draft_pull_request_id=outcome.pull_request_id,
        requires_human_approval=outcome.draft_ready,
        escalated_reason=result.escalated_reason,
        correlation_id=outcome.correlation_id,
    )


@router.get("/remediations/{proposal_id}", response_model=RemediationProposalResponse)
async def get_proposal(proposal_id: uuid.UUID, session: DbSession) -> RemediationProposalResponse:
    """One remediation proposal, with the patch and the review dialogue."""
    proposal = await RemediationRepository(session).get_proposal(proposal_id)
    if proposal is None:
        raise HTTPException(status_code=404, detail="proposal not found")
    return RemediationProposalResponse.from_model(proposal)


@router.get("/findings/{finding_id}/agent-runs", response_model=list[AgentRunResponse])
async def agent_runs_for_finding(
    finding_id: uuid.UUID,
    session: DbSession,
    limit: int = Query(default=100, ge=1, le=500),
) -> list[AgentRunResponse]:
    """Every agent turn recorded against a finding, in order.

    The audit trail for the AI half of the system: which agent, which round,
    which decision, what it cost, what it said. Available to any analyst,
    because "why did the agent touch this file?" is a question an analyst must
    be able to answer without filing a ticket.
    """
    if await FindingRepository(session).get(finding_id) is None:
        raise HTTPException(status_code=404, detail="finding not found")
    runs = await RemediationRepository(session).list_agent_runs(finding_id=finding_id)
    return [AgentRunResponse.model_validate(run) for run in runs[:limit]]


@router.get("/pull-requests", response_model=list[PullRequestResponse])
async def list_pull_requests(
    session: DbSession,
    pull_request_status: list[PullRequestStatus] | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[PullRequestResponse]:
    """Drafted remediation pull requests."""
    found = await RemediationRepository(session).list_pull_requests(
        statuses=pull_request_status, limit=limit
    )
    return [PullRequestResponse.from_model(pr) for pr in found]


@router.get("/pull-requests/awaiting-approval", response_model=list[PullRequestResponse])
async def awaiting_approval(
    session: DbSession,
    limit: int = Query(default=50, ge=1, le=200),
) -> list[PullRequestResponse]:
    """The approver's queue: drafts no human has authorized yet."""
    pending = await RemediationRepository(session).list_awaiting_human(limit=limit)
    return [PullRequestResponse.from_model(pr) for pr in pending]


@router.get("/pull-requests/{pull_request_id}", response_model=PullRequestResponse)
async def get_pull_request(pull_request_id: uuid.UUID, session: DbSession) -> PullRequestResponse:
    """One pull request, including the full body the approver is meant to read."""
    found = await RemediationRepository(session).get_pull_request(pull_request_id)
    if found is None:
        raise HTTPException(status_code=404, detail="pull request not found")
    return PullRequestResponse.from_model(found)


@router.post("/pull-requests/{pull_request_id}/approve", response_model=dict[str, object])
async def approve_pull_request(
    pull_request_id: uuid.UUID,
    payload: ApprovePullRequestRequest,
    session: DbSession,
    approver: ApproverPrincipal,
) -> dict[str, object]:
    """Authorize a draft pull request. Requires an APPROVER or ADMIN.

    This is the gate. It records a named human's decision and moves the record
    from `draft` to `open` -- which means "a person reviewed this and let it
    become visible for merge in the git host". It does not merge anything, and
    the response says so in `requires_human_merge`.
    """
    try:
        result = await ApprovalService(session).approve(
            pull_request_id,
            approver=approver.username,
            role=approver.role,
            correlation_id=payload.correlation_id or new_correlation_id(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalError as exc:
        # 409 rather than 400: every ApprovalError is a conflict with the
        # current state (already approved, already rejected, wrong role) rather
        # than a malformed request.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    if payload.reason:
        logger.info("approver noted a reason on PR #%s", result.pull_request.number)

    return result.as_dict()


@router.post("/pull-requests/{pull_request_id}/reject", response_model=dict[str, object])
async def reject_pull_request(
    pull_request_id: uuid.UUID,
    payload: RejectPullRequestRequest,
    session: DbSession,
    approver: ApproverPrincipal,
) -> dict[str, object]:
    """Reject a draft. A reason is required.

    A rejection with no explanation is unusable to the agent (it cannot learn
    from it) and useless to the next analyst (they cannot tell a bad patch from
    a bad policy call), so `reason` is a required field rather than a nullable
    one.
    """
    try:
        result = await ApprovalService(session).reject(
            pull_request_id,
            reviewer=approver.username,
            reason=payload.reason,
            role=approver.role,
            correlation_id=payload.correlation_id or new_correlation_id(),
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return result.as_dict()


@router.post("/pull-requests/{pull_request_id}/merged", response_model=dict[str, object])
async def record_merge(
    pull_request_id: uuid.UUID,
    payload: RecordMergeRequest,
    session: DbSession,
    approver: ApproverPrincipal,
) -> dict[str, object]:
    """Record that a human merged the branch in the git host.

    **This does not merge anything.** It is how a deployment reports an event
    that happened elsewhere, so the record can reach `merged` and the finding
    can be marked remediated. The service refuses the call if no human
    approval was ever recorded, so the audit trail can never contain a merge
    without an authorizing person.
    """
    try:
        pull_request = await ApprovalService(session).record_external_merge(
            pull_request_id, merged_by=payload.merged_by or approver.username
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ApprovalError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return {
        "pull_request_id": str(pull_request.id),
        "number": pull_request.number,
        "status": pull_request.status.value,
        "merged_by": payload.merged_by,
        "note": "recorded an external human merge; this endpoint performed no merge itself",
    }
