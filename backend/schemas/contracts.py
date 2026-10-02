"""Pydantic request/response contracts.

Rules this package follows:

  * Nothing crossing the HTTP or MCP boundary is an ORM model. A route returns
    a schema built from the row, so adding a column to `findings` cannot
    accidentally leak it -- including a hashed password, an internal cost
    figure, or a raw scanner payload.
  * Every schema is `from_attributes=True`, so a route can pass the ORM
    object directly and let Pydantic project the fields it wants.
  * Response schemas are separate from request schemas even where the shape is
    similar, because a field that only appears in responses (a fingerprint, a
    SLA state) is a field a client must never be able to set.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.database.enums import (
    Confidence,
    FindingStatus,
    ProposalStatus,
    PullRequestStatus,
    ScannerKind,
    Severity,
    TicketStatus,
    UserRole,
)


class ORMModel(BaseModel):
    """Base for every response schema."""

    model_config = ConfigDict(from_attributes=True)


# --- Auth ---------------------------------------------------------------


class LoginRequest(BaseModel):
    """Credentials. `username` is not length-capped: a 10k-character username
    is a valid login *attempt* and must produce a 401, not a 422 that tells the
    caller their guess was malformed."""

    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=512)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    role: UserRole
    expires_in_minutes: int


class WhoAmIResponse(BaseModel):
    username: str
    role: UserRole
    is_authenticated: bool
    can_approve_remediation: bool


# --- Findings -----------------------------------------------------------


class SlaStateResponse(BaseModel):
    """Derived, never stored. See `backend/policy/rules.py::evaluate_sla`."""

    state: str
    breached: bool
    hours_remaining: float | None = None
    due_at: datetime | None = None
    fraction_elapsed: float = 0.0


class FindingResponse(ORMModel):
    finding_id: uuid.UUID
    fingerprint: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    scanner_kind: ScannerKind
    status: FindingStatus
    target: str
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    snippet: str | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    first_seen_at: datetime
    last_seen_at: datetime
    sla_due_at: datetime | None = None
    triaged_at: datetime | None = None
    remediated_at: datetime | None = None
    closed_at: datetime | None = None
    remediation_attempts: int = 0
    auto_remediation_eligible: bool = False

    @classmethod
    def from_model(cls, finding: Any, *, include_snippet: bool = True) -> FindingResponse:
        """Project an ORM `Finding` onto the response schema.

        `include_snippet=False` is what the *list* endpoints use. A triage
        queue can show 200 findings without 200 source snippets, and the
        snippet is the most sensitive thing in this system -- shipping it in a
        list response means it lands in browser caches and proxy logs for every
        finding, whether or not anyone looked at it.
        """
        return cls(
            finding_id=finding.id,
            fingerprint=finding.fingerprint,
            rule_id=finding.rule_id,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            confidence=finding.confidence,
            scanner_kind=finding.scanner_kind,
            status=finding.status,
            target=finding.target,
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            snippet=finding.snippet if include_snippet else None,
            cwe_ids=list(finding.cwe_ids),
            cve_ids=list(finding.cve_ids),
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            sla_due_at=finding.sla_due_at,
            triaged_at=finding.triaged_at,
            remediated_at=finding.remediated_at,
            closed_at=finding.closed_at,
            remediation_attempts=finding.remediation_attempts,
            auto_remediation_eligible=finding.auto_remediation_eligible,
        )


class FindingListResponse(BaseModel):
    findings: list[FindingResponse]
    total: int
    """Count of everything matching the filter, not of this page. A client
    paginating needs the real total to render "showing 25 of 340"."""

    limit: int
    offset: int


class FindingDetailResponse(FindingResponse):
    """A single finding with everything a triage decision needs."""

    raw_payload: dict[str, Any] = Field(default_factory=dict)
    sla: SlaStateResponse | None = None
    ticket_keys: list[str] = Field(default_factory=list)
    latest_proposal_status: ProposalStatus | None = None


class FindingStatusUpdateRequest(BaseModel):
    status: FindingStatus
    reason: str | None = Field(default=None, max_length=1000)
    """Optional context recorded in the audit log. Not required, but a status
    change with no reason is very hard to review later."""

    expected_current_status: FindingStatus | None = None
    """Optimistic concurrency. If set and does not match, the update is
    rejected -- two analysts triaging the same finding from two tabs is a real
    scenario, and last-write-wins would silently discard one of them."""


# --- Scans --------------------------------------------------------------


class ScanRequestBody(BaseModel):
    target: str = Field(min_length=1, max_length=1000)
    scanners: list[ScannerKind] = Field(default_factory=list)
    min_severity: Severity | None = None
    correlation_id: str | None = Field(default=None, max_length=120)


class ScanResponseBody(BaseModel):
    scan_id: uuid.UUID
    correlation_id: str
    target: str
    new_findings: int
    refreshed_findings: int
    total_findings: int
    counts_by_severity: dict[str, int]
    duration_ms: float
    partial: bool
    created: list[FindingResponse] = Field(default_factory=list)


class ScanTargetsResponse(BaseModel):
    """What the configured scanners can be pointed at.

    A named model rather than `dict[str, list[str]]`, because a prose `note`
    field is a string and a `dict[str, list[str]]` response model would reject
    it at serialization time -- which is exactly the kind of thing a test only
    catches when it calls the endpoint.
    """

    fixture_targets: list[str] = Field(default_factory=list)
    available_scanners: list[str] = Field(default_factory=list)
    note: str = ""


# --- Tickets ------------------------------------------------------------


class _IdProjectionMixin:
    """Shared note for the response schemas that rename the primary key.

    Every aggregate in this schema renames `id` to `<resource>_id`, so a client
    holding a value can tell what it is without consulting the schema. The
    `from_model` classmethods are therefore explicit projections rather than
    `model_validate` -- which would need the ORM column renamed, leaking the
    ORM's naming into the API and breaking every other query that uses `id`.
    """


class TicketResponse(ORMModel):
    ticket_id: uuid.UUID
    ticket_key: str
    finding_id: uuid.UUID
    title: str
    description: str
    status: TicketStatus
    priority: Severity
    assignee: str | None = None
    created_by: str
    created_at: datetime
    resolved_at: datetime | None = None

    @classmethod
    def from_model(cls, ticket: Any) -> TicketResponse:
        """Project a `Ticket` row.

        The primary key is exposed as `ticket_id` rather than `id`, so a client
        holding a value can tell what it is without consulting the schema. An
        explicit projection rather than `model_validate`, because the latter
        would require renaming the ORM column and leaking the ORM's naming into
        the API.
        """
        return cls(
            ticket_id=ticket.id,
            ticket_key=ticket.ticket_key,
            finding_id=ticket.finding_id,
            title=ticket.title,
            description=ticket.description,
            status=ticket.status,
            priority=ticket.priority,
            assignee=ticket.assignee,
            created_by=ticket.created_by,
            created_at=ticket.created_at,
            resolved_at=ticket.resolved_at,
        )


class CreateTicketRequest(BaseModel):
    finding_id: uuid.UUID
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=8000)
    assignee: str | None = Field(default=None, max_length=255)


# --- Remediation --------------------------------------------------------


class AgentRunResponse(ORMModel):
    role: str
    decision: str
    round_index: int
    rationale: str | None = None
    message: str | None = None
    llm_model: str | None = None
    tokens_used: int
    cost_usd: float
    latency_ms: float
    created_at: datetime


class RemediationProposalResponse(ORMModel):
    proposal_id: uuid.UUID
    finding_id: uuid.UUID
    status: ProposalStatus
    file_path: str
    summary: str | None = None
    rationale: str | None = None
    final_patch: str | None = None
    rounds_completed: int
    reviewer_feedback: list[dict[str, Any]] = Field(default_factory=list)
    escalated_reason: str | None = None
    llm_calls: int
    tokens_used: int
    cost_usd: float
    latency_ms: float
    llm_model: str | None = None
    created_at: datetime

    @classmethod
    def from_model(cls, proposal: Any) -> RemediationProposalResponse:
        return cls(
            proposal_id=proposal.id,
            finding_id=proposal.finding_id,
            status=proposal.status,
            file_path=proposal.file_path,
            summary=proposal.summary,
            rationale=proposal.rationale,
            final_patch=proposal.final_patch,
            rounds_completed=proposal.rounds_completed,
            reviewer_feedback=list(proposal.reviewer_feedback),
            escalated_reason=proposal.escalated_reason,
            llm_calls=proposal.llm_calls,
            tokens_used=proposal.tokens_used,
            cost_usd=proposal.cost_usd,
            latency_ms=proposal.latency_ms,
            llm_model=proposal.llm_model,
            created_at=proposal.created_at,
        )


class RemediateRequest(BaseModel):
    finding_id: uuid.UUID
    open_ticket: bool = True
    """Off by default for the API? No -- on by default, because the safe
    default for a system that acts autonomously is the one that leaves a
    human a work item. A caller batching remediations can turn it off."""

    correlation_id: str | None = Field(default=None, max_length=120)


class RemediateResponse(BaseModel):
    finding_id: uuid.UUID
    proposal_id: uuid.UUID
    outcome: str
    approved: bool
    rounds: int
    llm_calls: int
    tokens_used: int
    cost_usd: float
    latency_ms: float
    llm_model: str | None = None
    draft_pull_request_id: uuid.UUID | None = None
    requires_human_approval: bool
    escalated_reason: str | None = None
    correlation_id: str


# --- Pull requests and the human gate -----------------------------------


class PullRequestResponse(ORMModel):
    pull_request_id: uuid.UUID
    proposal_id: uuid.UUID
    number: int
    title: str
    body: str
    branch: str
    base_branch: str
    target_repo: str
    status: PullRequestStatus
    diff_url: str | None = None
    auto_merge_blocked: bool
    human_approver: str | None = None
    human_approved_at: datetime | None = None
    rejection_reason: str | None = None
    created_at: datetime

    @classmethod
    def from_model(cls, pull_request: Any) -> PullRequestResponse:
        return cls(
            pull_request_id=pull_request.id,
            proposal_id=pull_request.proposal_id,
            number=pull_request.number,
            title=pull_request.title,
            body=pull_request.body,
            branch=pull_request.branch,
            base_branch=pull_request.base_branch,
            target_repo=pull_request.target_repo,
            status=pull_request.status,
            diff_url=pull_request.diff_url,
            # Rendered, not defaulted. This column is the machine-readable form
            # of the project's central guarantee, so a client must never see
            # `False` here because the projection forgot to copy it.
            auto_merge_blocked=pull_request.auto_merge_blocked,
            human_approver=pull_request.human_approver,
            human_approved_at=pull_request.human_approved_at,
            rejection_reason=pull_request.rejection_reason,
            created_at=pull_request.created_at,
        )


class ApprovePullRequestRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
    correlation_id: str | None = Field(default=None, max_length=120)


class RejectPullRequestRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=4000)
    """Required, not optional. A rejection with no explanation is unusable to
    the agent (it cannot learn from it) and useless to the next analyst (they
    cannot tell a bad patch from a bad policy call)."""

    correlation_id: str | None = Field(default=None, max_length=120)

    @field_validator("reason")
    @classmethod
    def _reason_must_not_be_blank(cls, value: str) -> str:
        """Reject a whitespace-only reason at the schema boundary.

        `min_length=1` accepts `"   "`, and the service would then raise
        `ApprovalError` -- which the route maps to **409 Conflict**. A blank
        reason is a malformed *request*, not a conflict with the pull request's
        state, so it belongs here where it is a 422. Getting this classification
        wrong makes a client retry the same impossible request forever.
        """
        if not value.strip():
            raise ValueError("a rejection reason is required and must not be blank")
        return value.strip()


class RecordMergeRequest(BaseModel):
    """Records that a human merged the branch in the git host.

    This does not merge anything. It is how a deployment reports an observed
    external event, and the service refuses it if no human approval was ever
    recorded.
    """

    merged_by: str = Field(min_length=1, max_length=255)


# --- SLA dashboard ------------------------------------------------------


class SeverityBucket(BaseModel):
    severity: Severity
    sla_hours: int
    total_open: int
    on_track: int
    at_risk: int
    breached: int
    met: int
    stopped: int
    not_started: int
    breach_rate: float
    oldest_breach_hours: float


class SlaTotals(BaseModel):
    open: int
    breached: int
    at_risk: int
    breach_rate: float


class SlaDashboardResponse(BaseModel):
    generated_at: datetime
    totals: SlaTotals
    by_severity: list[SeverityBucket]
    remediations: dict[str, Any] = Field(default_factory=dict)
    tickets: dict[str, int] = Field(default_factory=dict)


# --- Audit --------------------------------------------------------------


class AuditEntryResponse(ORMModel):
    audit_id: uuid.UUID
    actor: str
    action: str
    entity_type: str
    entity_id: str | None = None
    correlation_id: str | None = None
    summary: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    @classmethod
    def from_model(cls, entry: Any) -> AuditEntryResponse:
        """Project an `AuditLog` row onto the response.

        Explicit rather than `model_validate`, because two of these fields do
        not match the column names and one has an enum where the schema wants a
        plain string:

          * `AuditLog.id` is the primary key, not `audit_id`.
          * `AuditLog.action` is an `AuditAction` enum, and coercing it here is
            explicit about being a *rendering* rather than something the
            client may send back.
        """
        return cls(
            audit_id=entry.id,
            actor=entry.actor,
            action=entry.action.value,
            entity_type=entry.entity_type,
            entity_id=entry.entity_id,
            correlation_id=entry.correlation_id,
            summary=entry.summary,
            payload=dict(entry.payload),
            created_at=entry.created_at,
        )


class AuditTrailResponse(BaseModel):
    entries: list[AuditEntryResponse]
    total: int


# --- Health -------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    database: str
    scanning_service: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)
