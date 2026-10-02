"""SQLAlchemy model package.

Importing every model here is load-bearing, not decorative: Alembic's
autogenerate, `Base.metadata.create_all`, and the schema-drift guard in
`tests/integration/test_schema_drift.py` all walk `Base.metadata`, and a
model that was never imported is a table those three will not see.
"""

from __future__ import annotations

from backend.database.base import Base
from backend.database.models.audit_log import AuditLog, User
from backend.database.models.finding import Finding, Ticket
from backend.database.models.remediation import (
    AgentRun,
    PullRequest,
    RemediationProposal,
)

__all__ = [
    "AgentRun",
    "AuditLog",
    "Base",
    "Finding",
    "PullRequest",
    "RemediationProposal",
    "Ticket",
    "User",
]
