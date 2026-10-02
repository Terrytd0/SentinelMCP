"""The MCP tool surface: security triage, exposed to any MCP client.

This is the piece that makes SentinelMCP a *protocol* server rather than an
API with a nice front end. The four tools below are the roadmap's specified
surface:

    list_findings     triage queue, filtered and sorted
    get_cve_details   advisory lookup for a CVE
    propose_fix       run the agent loop and draft a pull request
    create_ticket     put the result somewhere a human will see it

Design decisions that matter more than the tool bodies:

  * **The tools are thin.** Each one validates its input with a Pydantic
    schema, calls exactly one service method, and returns a Pydantic model.
    All the logic is in `backend/services/`, which is why the HTTP API and the
    MCP server can be correct independently and neither is a special case.

  * **`propose_fix` never merges.** It returns `requires_human_approval: true`
    unconditionally when a draft exists, and the enum of possible outcomes has
    no "merged" member. The tool's contract itself says the machine stops here.

  * **Every call is audited**, with the actor recorded as `mcp:<tool_name>`, so
    the audit log can answer "what did the AI assistant do?" separately from
    "what did the analysts do?".

  * **Errors are returned, not raised.** An MCP client sees a tool result with
    `is_error` set, which is the protocol's way of saying "the call failed"
    without killing the session. A scanner that cannot run is a *result*, not
    a crash.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.ids import new_correlation_id
from backend.core.logging import get_logger
from backend.database.enums import (
    AuditAction,
    Confidence,
    FindingStatus,
    ScannerKind,
    Severity,
    TicketStatus,
)
from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.services.cve import CveNotFoundError, CveService
from backend.services.remediation import RemediationRefusedError, RemediationService
from backend.telemetry import get_telemetry_client
from backend.telemetry.events import EventStatus

logger = get_logger(__name__)

SERVER_NAME = "sentinelmcp"
SERVER_VERSION = "0.1.0"

SERVER_INSTRUCTIONS = """\
SentinelMCP exposes Ironclad Cyber Defense's security-triage backlog.

Typical flow:
  1. `list_findings` to see what is open, most urgent first. Start with
     severity=critical or high.
  2. `get_cve_details` when a finding carries a CVE id, to get the advisory,
     the fixed version, and the upgrade recommendation.
  3. `propose_fix` to have the developer/reviewer agent pair draft a patch.
     This runs an autonomous agent loop and costs tokens. Only do it for a
     finding you have actually looked at.
  4. `create_ticket` so a human picks the work up.

IMPORTANT: `propose_fix` opens a *draft* pull request. It never merges. A human
approver must authorize it before it is mergeable, and a human must perform the
merge in the git host. Do not tell a user that a vulnerability is fixed after
calling `propose_fix` -- it has only been *proposed*.
"""


# --- Tool result models -------------------------------------------------
# Declared as Pydantic models rather than free dicts so the MCP client receives
# a JSON Schema it can validate against, and so a field rename is a type error
# here rather than a silent contract change for every client.


class ListFindingsArgs(BaseModel):
    severity: list[Severity] = Field(
        default_factory=list,
        description="Only these severities. Empty means all.",
    )
    status: list[FindingStatus] = Field(
        default_factory=list,
        description="Only these statuses. Empty means every non-terminal status.",
    )
    scanner: list[ScannerKind] = Field(
        default_factory=list, description="Filter by finding source."
    )
    query: str | None = Field(
        default=None,
        max_length=200,
        description="Substring match over title, description, file path, and rule id.",
    )
    include_closed: bool = Field(
        default=False,
        description="Include terminal states (remediated, accepted risk, false positive).",
    )
    limit: int = Field(default=20, ge=1, le=200, description="Maximum findings to return.")

    @field_validator("severity", "status", "scanner", mode="before")
    @classmethod
    def _none_means_empty(cls, value: object) -> object:
        """Treat an explicit `null` list as an empty one.

        An MCP client that omits an optional argument sends `null`, not "absent"
        -- so a plain `default_factory=list` rejects every call that leaves a
        filter unset, which is the common case. This is the difference between a
        tool that works for a real MCP client and one that only works when
        called from Python; guarded by
        `tests/integration/test_mcp_tools.py::test_an_omitted_optional_filter_is_not_an_error`.
        """
        return [] if value is None else value


class FindingSummary(BaseModel):
    finding_id: str
    title: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    scanner: ScannerKind
    file_path: str | None
    start_line: int | None
    cwe_ids: list[str]
    cve_ids: list[str]
    sla_due_at: str | None
    first_seen_at: str
    auto_remediation_eligible: bool
    remediation_attempts: int


class ListFindingsResult(BaseModel):
    findings: list[FindingSummary]
    returned: int
    """How many are in this response."""
    total_matching: int
    """How many match the filter in total, so a client knows to keep paging."""
    has_more: bool
    next_hint: str
    """Plain-language instruction for the next call, so an agent does not have
    to infer the paging protocol."""


class GetCveDetailsArgs(BaseModel):
    cve_id: str = Field(
        min_length=5,
        max_length=32,
        description="A CVE identifier, e.g. CVE-2023-46695. Case-insensitive.",
    )


class GetCveDetailsResult(BaseModel):
    cve_id: str
    found: bool
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_band: str | None = None
    severity: Severity | None = None
    declared_severity: str | None = None
    severity_mismatch: bool = Field(
        default=False,
        description=(
            "True when the advisory's own severity disagrees with its CVSS band. "
            "Worth surfacing: one of the two is wrong and an analyst should say which."
        ),
    )
    cwe_ids: list[str] = Field(default_factory=list)
    affected_products: list[dict[str, Any]] = Field(default_factory=list)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    matching_findings: list[FindingSummary] = Field(
        default_factory=list,
        description="Findings in this backlog that reference this CVE.",
    )
    note: str | None = None


class ProposeFixArgs(BaseModel):
    finding_id: str = Field(description="The finding to remediate (UUID string).")
    correlation_id: str | None = Field(default=None, max_length=120)
    open_ticket: bool = Field(
        default=True,
        description="Also open a ticket for the human who will review the result.",
    )


class ProposeFixResult(BaseModel):
    finding_id: str
    proposal_id: str
    outcome: str = Field(
        description=(
            "One of: approved (a draft PR was opened), rejected (the reviewer "
            "refused the patch), escalated (the agents could not converge, or "
            "policy refused). Only 'approved' produces a pull request."
        ),
    )
    approved: bool
    draft_pull_request_id: str | None = None
    pull_request_number: int | None = None
    requires_human_approval: bool = Field(
        default=True,
        description=(
            "Always true when a draft was opened. This system cannot merge; a "
            "human approver authorizes the PR and a human performs the merge."
        ),
    )
    rounds: int
    summary: str
    rationale: str | None = None
    patch: str | None = None
    reviewer_comments: list[str] = Field(default_factory=list)
    escalated_reason: str | None = None
    cost: dict[str, Any] = Field(
        default_factory=dict,
        description="LLM calls, tokens, USD, and wall time for this remediation.",
    )
    correlation_id: str


class CreateTicketArgs(BaseModel):
    finding_id: str = Field(description="The finding to open a ticket for (UUID string).")
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(default="", max_length=8000)
    assignee: str | None = Field(default=None, max_length=255)
    priority: Severity | None = Field(
        default=None,
        description="Defaults to the finding's own severity.",
    )


class CreateTicketResult(BaseModel):
    ticket_id: str
    ticket_key: str
    finding_id: str
    title: str
    status: TicketStatus
    priority: Severity
    created_by: str
    message: str


# --- Error envelope -----------------------------------------------------


class ToolError(BaseModel):
    """The shape every failure returns.

    Always a *result*, never an exception. An MCP client that gets an exception
    has to decide whether the session is broken; a client that gets `is_error`
    with a structured body can read the reason and try something else. That
    difference is the difference between a usable tool and an annoying one.
    """

    error: str
    detail: str | None = None
    remedy: str | None = Field(
        default=None, description="What the caller should do next, in one sentence."
    )
    finding_id: str | None = None
    correlation_id: str | None = None


# --- Tool implementations -----------------------------------------------
# These take an explicit session and services rather than reaching for a
# global, so they are callable from a test, from `run_mcp_server.py`, and from
# an HTTP route with the same code path.


class SentinelTools:
    """The four MCP tools, as plain async methods.

    Kept separate from the `MCPServer` wiring in `server.py` so the business
    logic is testable without constructing a protocol server, and so the same
    logic can be exposed over HTTP if that is ever wanted.
    """

    def __init__(self, session: AsyncSession, scanner_backend: Any) -> None:
        self._session = session
        self._scanner_backend = scanner_backend
        self._findings = FindingRepository(session)
        self._remediations = RemediationRepository(session)
        self._tickets = TicketRepository(session)
        self._audit = AuditRepository(session)
        self._cve = CveService()
        self._telemetry = get_telemetry_client()

    async def list_findings(self, args: ListFindingsArgs) -> ListFindingsResult | ToolError:
        """List findings from the triage backlog."""
        correlation_id = new_correlation_id()
        with self._telemetry.measure("mcp.tool.list_findings", correlation_id=correlation_id) as m:
            try:
                result = await self._list_findings(args)
                m.metadata = {
                    "returned": result.returned,
                    "total_matching": result.total_matching,
                }
                await self._audit_tool_call(
                    "list_findings", correlation_id, args.model_dump(mode="json")
                )
                return result
            except Exception as exc:  # noqa: BLE001 - a tool must not kill the MCP session
                return self._fail(
                    "list_findings", exc, correlation_id, remedy="Narrow the filters and try again."
                )

    async def _list_findings(self, args: ListFindingsArgs) -> ListFindingsResult:
        if args.include_closed:
            found = await self._findings.search(
                query=args.query,
                statuses=args.status or None,
                severities=args.severity or None,
                limit=args.limit,
            )
        else:
            found = await self._findings.list_open_with_sla(
                severities=args.severity or None,
                scanner_kinds=args.scanner or None,
                limit=args.limit,
            )
            if args.query:
                needle = args.query.lower()
                found = [
                    f
                    for f in found
                    if needle in f.title.lower()
                    or needle in f.description.lower()
                    or needle in (f.file_path or "").lower()
                    or needle in f.rule_id.lower()
                ]
        found.sort(key=lambda f: (f.severity.rank, f.first_seen_at))

        summaries = [_to_summary(f) for f in found]
        has_more = len(summaries) == args.limit
        return ListFindingsResult(
            findings=summaries,
            returned=len(summaries),
            total_matching=len(summaries),
            has_more=has_more,
            next_hint=(
                f"Ask for the next page with limit={args.limit} and a narrower severity, "
                "or call list_findings with include_closed=true to include fixed findings."
                if has_more
                else "This is the full result set for the filter you supplied."
            ),
        )

    async def get_cve_details(self, args: GetCveDetailsArgs) -> GetCveDetailsResult | ToolError:
        """Look up a CVE advisory and the findings that reference it."""
        correlation_id = new_correlation_id()
        with self._telemetry.measure("mcp.tool.get_cve_details", correlation_id=correlation_id):
            try:
                cve_id = args.cve_id.strip().upper()
                matching = await self._findings.find_by_cve(cve_id)
                await self._audit_tool_call("get_cve_details", correlation_id, {"cve_id": cve_id})

                try:
                    advisory = self._cve.get(cve_id)
                except CveNotFoundError as exc:
                    # A miss is a legitimate answer, not a failure: the CVE is
                    # real, it is just not in the local feed. Returning a
                    # `found: false` result *with* the matching findings is
                    # more useful than an error, because the finding list is
                    # often the part the caller wanted.
                    return GetCveDetailsResult(
                        cve_id=cve_id,
                        found=False,
                        matching_findings=[_to_summary(f) for f in matching],
                        note=(
                            f"{exc} This service reads a local advisory feed rather than "
                            "querying NVD, so a recent or obscure CVE will miss. Check the "
                            "NVD reference URL for the authoritative entry."
                        ),
                    )

                return GetCveDetailsResult(
                    cve_id=cve_id,
                    found=True,
                    title=str(advisory.get("title") or ""),
                    description=str(advisory.get("description") or ""),
                    cvss_score=_as_float(advisory.get("cvss_score")),
                    cvss_band=str(advisory.get("cvss_band") or ""),
                    severity=advisory.get("severity"),
                    declared_severity=str(advisory.get("declared_severity") or ""),
                    severity_mismatch=bool(advisory.get("severity_mismatch")),
                    cwe_ids=[str(c) for c in (advisory.get("cwe_ids") or [])],
                    affected_products=list(advisory.get("affected_products") or []),
                    remediation=str(advisory.get("remediation") or ""),
                    references=[str(r) for r in (advisory.get("references") or [])],
                    matching_findings=[_to_summary(f) for f in matching],
                )
            except Exception as exc:  # noqa: BLE001
                return self._fail("get_cve_details", exc, correlation_id)

    async def propose_fix(self, args: ProposeFixArgs) -> ProposeFixResult | ToolError:
        """Run the agent loop and draft a remediation pull request.

        Costs LLM tokens and starts an autonomous agent. The caller should have
        looked at the finding first; this tool does not know whether they have.
        """
        correlation_id = args.correlation_id or new_correlation_id()
        finding_id = _parse_uuid(args.finding_id)

        with self._telemetry.measure("mcp.tool.propose_fix", correlation_id=correlation_id) as m:
            try:
                if finding_id is None:
                    return ToolError(
                        error="invalid_finding_id",
                        detail=f"{args.finding_id!r} is not a UUID",
                        remedy="Pass the finding_id returned by list_findings.",
                        correlation_id=correlation_id,
                    )

                service = RemediationService(self._session, audit=self._audit)
                outcome = await service.remediate(
                    finding_id,
                    actor="mcp:propose_fix",
                    correlation_id=correlation_id,
                    open_ticket=args.open_ticket,
                )
                result = outcome.result

                number: int | None = None
                if outcome.pull_request_id is not None:
                    pr = await self._remediations.get_pull_request(outcome.pull_request_id)
                    number = pr.number if pr else None

                m.tokens_used = result.tokens_used
                m.cost = result.cost_usd
                m.metadata = {
                    "finding_id": args.finding_id,
                    "outcome": result.outcome,
                    "rounds": result.rounds_completed,
                }

                return ProposeFixResult(
                    finding_id=str(outcome.finding.id),
                    proposal_id=str(outcome.proposal.id),
                    outcome=result.outcome,
                    approved=result.approved,
                    draft_pull_request_id=(
                        str(outcome.pull_request_id) if outcome.pull_request_id else None
                    ),
                    pull_request_number=number,
                    # Unconditionally true. Not a computed value: the absence of
                    # a merge capability is the design, and reporting it as a
                    # flag a client could ignore would weaken the statement.
                    requires_human_approval=True,
                    rounds=result.rounds_completed,
                    summary=result.summary,
                    rationale=result.rationale,
                    patch=result.patch,
                    reviewer_comments=result.all_feedback(),
                    escalated_reason=result.escalated_reason,
                    cost={
                        "llm_calls": result.llm_calls,
                        "tokens_used": result.tokens_used,
                        "cost_usd": result.cost_usd,
                        "latency_ms": round(result.latency_ms, 2),
                        "llm_model": result.llm_model or "deterministic (no LLM calls)",
                    },
                    correlation_id=correlation_id,
                )

            except RemediationRefusedError as exc:
                # A policy refusal is a *successful* call that says no. It
                # returns a structured error with the machine-readable refusal
                # so a client can explain why, rather than a generic failure.
                self._telemetry.emit(
                    "mcp.tool.propose_fix",
                    status=EventStatus.SUCCESS,
                    correlation_id=correlation_id,
                    metadata={"outcome": "policy_refused", "refusal": exc.refusal.value},
                )
                return ToolError(
                    error="policy_refused",
                    detail=exc.reason,
                    remedy=(
                        "This finding is not eligible for auto-remediation. "
                        "Triage it manually, or see backend/policy/rules.py for the rule."
                    ),
                    finding_id=args.finding_id,
                    correlation_id=correlation_id,
                )
            except LookupError as exc:
                return ToolError(
                    error="finding_not_found",
                    detail=str(exc),
                    remedy="Call list_findings to get a valid finding_id.",
                    finding_id=args.finding_id,
                    correlation_id=correlation_id,
                )
            except Exception as exc:  # noqa: BLE001
                return self._fail("propose_fix", exc, correlation_id, finding_id=args.finding_id)

    async def create_ticket(self, args: CreateTicketArgs) -> CreateTicketResult | ToolError:
        """Open a ticket so a human picks the finding up."""
        correlation_id = new_correlation_id()
        finding_id = _parse_uuid(args.finding_id)

        with self._telemetry.measure("mcp.tool.create_ticket", correlation_id=correlation_id):
            try:
                if finding_id is None:
                    return ToolError(
                        error="invalid_finding_id",
                        detail=f"{args.finding_id!r} is not a UUID",
                        remedy="Pass the finding_id returned by list_findings.",
                        correlation_id=correlation_id,
                    )

                finding = await self._findings.get(finding_id)
                if finding is None:
                    return ToolError(
                        error="finding_not_found",
                        detail=f"no finding with id {finding_id}",
                        remedy="Call list_findings to get a valid finding_id.",
                        finding_id=args.finding_id,
                        correlation_id=correlation_id,
                    )

                if finding.status.is_terminal:
                    return ToolError(
                        error="finding_already_terminal",
                        detail=(
                            f"finding status is {finding.status.value!r}; opening a ticket "
                            "for a closed finding creates work that may not be needed"
                        ),
                        remedy="Reopen the finding first if the risk has come back.",
                        finding_id=args.finding_id,
                        correlation_id=correlation_id,
                    )

                ticket = await self._tickets.create_ticket(
                    finding_id=finding_id,
                    title=args.title,
                    description=args.description,
                    priority=args.priority or finding.severity,
                    created_by="mcp:create_ticket",
                    assignee=args.assignee,
                )
                if finding.triaged_at is None:
                    await self._findings.update_status(finding_id, FindingStatus.TRIAGED)

                await self._audit.append(
                    actor="mcp:create_ticket",
                    action=AuditAction.TICKET_CREATED,
                    entity_type="ticket",
                    entity_id=ticket.id,
                    correlation_id=correlation_id,
                    summary=f"opened {ticket.ticket_key}: {args.title}",
                    payload={
                        "finding_id": str(finding_id),
                        "ticket_key": ticket.ticket_key,
                        "priority": ticket.priority.value,
                    },
                )

                return CreateTicketResult(
                    ticket_id=str(ticket.id),
                    ticket_key=ticket.ticket_key,
                    finding_id=str(finding_id),
                    title=ticket.title,
                    status=ticket.status,
                    priority=ticket.priority,
                    created_by=ticket.created_by,
                    message=f"Opened {ticket.ticket_key}. A human analyst will pick this up.",
                )
            except Exception as exc:  # noqa: BLE001
                return self._fail("create_ticket", exc, correlation_id, finding_id=args.finding_id)

    # --- Shared helpers --------------------------------------------------

    async def _audit_tool_call(
        self, tool: str, correlation_id: str, arguments: dict[str, Any]
    ) -> None:
        """Record that an MCP tool was called, and by what.

        Actor is `mcp:<tool>`, which is what makes "separate the AI's actions
        from the analysts' actions" a single `WHERE actor LIKE 'mcp:%'` query
        rather than a schema change.

        Arguments are recorded wholesale. They are validated Pydantic models
        holding ids, enums, and short strings -- no source code and no
        credentials -- so the whole call is reconstructable from the audit log.
        """
        await self._audit.append(
            actor=f"mcp:{tool}",
            action=AuditAction.MCP_TOOL_INVOKED,
            entity_type="mcp_tool",
            entity_id=tool,
            correlation_id=correlation_id,
            summary=f"MCP tool {tool} invoked",
            payload={"arguments": arguments},
        )

    def _fail(
        self,
        tool: str,
        exc: Exception,
        correlation_id: str,
        *,
        finding_id: str | None = None,
        remedy: str | None = None,
    ) -> ToolError:
        """Log a tool failure, emit telemetry, and return a structured error."""
        logger.warning("mcp tool %s failed: %s", tool, type(exc).__name__)
        self._telemetry.emit(
            f"mcp.tool.{tool}",
            status=EventStatus.ERROR,
            correlation_id=correlation_id,
            error_type=type(exc).__name__,
            metadata={"finding_id": finding_id},
        )
        detail = str(exc)
        return ToolError(
            error=type(exc).__name__,
            detail=detail[:1000] or None,
            remedy=remedy,
            finding_id=finding_id,
            correlation_id=correlation_id,
        )


# --- Small helpers ------------------------------------------------------


def _to_summary(finding: Any) -> FindingSummary:
    return FindingSummary(
        finding_id=str(finding.id),
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        status=finding.status,
        scanner=finding.scanner_kind,
        file_path=finding.file_path,
        start_line=finding.start_line,
        cwe_ids=list(finding.cwe_ids),
        cve_ids=list(finding.cve_ids),
        sla_due_at=finding.sla_due_at.isoformat() if finding.sla_due_at else None,
        first_seen_at=finding.first_seen_at.isoformat(),
        auto_remediation_eligible=finding.auto_remediation_eligible,
        remediation_attempts=finding.remediation_attempts,
    )


def _parse_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value).strip())
    except (ValueError, AttributeError, TypeError):
        return None


def _as_float(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
