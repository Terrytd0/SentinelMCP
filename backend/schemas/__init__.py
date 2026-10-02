"""Pydantic request/response and internal data contracts.

Everything that crosses the HTTP or MCP boundary is validated here first, and
ORM models are never exposed directly. `contracts.py` holds the API surface;
`auth.py` holds the auth-specific pieces so `backend/auth/router.py` does not
have to import the whole contract set to serve two routes.
"""

from __future__ import annotations

from backend.schemas.auth import (
    LoginRequest,
    PasswordChangeRequest,
    TokenResponse,
    WhoAmIResponse,
)
from backend.schemas.contracts import (
    AgentRunResponse,
    ApprovePullRequestRequest,
    AuditEntryResponse,
    AuditTrailResponse,
    CreateTicketRequest,
    FindingDetailResponse,
    FindingListResponse,
    FindingResponse,
    FindingStatusUpdateRequest,
    HealthResponse,
    PullRequestResponse,
    RecordMergeRequest,
    RejectPullRequestRequest,
    RemediateRequest,
    RemediateResponse,
    RemediationProposalResponse,
    ScanRequestBody,
    ScanResponseBody,
    SeverityBucket,
    SlaDashboardResponse,
    SlaStateResponse,
    SlaTotals,
    TicketResponse,
)

__all__ = [
    "AgentRunResponse",
    "ApprovePullRequestRequest",
    "AuditEntryResponse",
    "AuditTrailResponse",
    "CreateTicketRequest",
    "FindingDetailResponse",
    "FindingListResponse",
    "FindingResponse",
    "FindingStatusUpdateRequest",
    "HealthResponse",
    "LoginRequest",
    "PasswordChangeRequest",
    "PullRequestResponse",
    "RecordMergeRequest",
    "RejectPullRequestRequest",
    "RemediationProposalResponse",
    "RemediateRequest",
    "RemediateResponse",
    "ScanRequestBody",
    "ScanResponseBody",
    "SeverityBucket",
    "SlaDashboardResponse",
    "SlaStateResponse",
    "SlaTotals",
    "TicketResponse",
    "TokenResponse",
    "WhoAmIResponse",
]
