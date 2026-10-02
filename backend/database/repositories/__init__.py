"""Repository-pattern data access.

Every SQLAlchemy query in the project lives under this package. Services and
routes depend on these classes; they never import `select` or a model directly.
That is what lets the ORM be replaced, and what makes the unit tests able to
substitute an in-memory repository for a Postgres one without patching
`sqlalchemy` internals.
"""

from __future__ import annotations

from backend.database.repositories.finding import FindingRepository
from backend.database.repositories.remediation import RemediationRepository
from backend.database.repositories.ticket import AuditRepository, TicketRepository
from backend.database.repositories.user import UserRepository

__all__ = [
    "AuditRepository",
    "FindingRepository",
    "RemediationRepository",
    "TicketRepository",
    "UserRepository",
]
