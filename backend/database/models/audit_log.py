"""The append-only audit log, and the operator accounts that act on it.

`audit_logs` is the table that makes the claim "full audit log of every
finding and every agent decision" checkable rather than aspirational. It is
append-only by convention: no repository in this codebase updates or deletes a
row, and `tests/integration/test_pipeline_persistence.py` enforces that
read-and-append is the only surface.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Index, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column

from backend.core.clock import utc_now
from backend.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from backend.database.enums import AuditAction, UserRole
from backend.database.models.finding import _enum


class AuditLog(UUIDPrimaryKeyMixin, Base):
    """One recorded action.

    Deliberately does not use `TimestampMixin`: it has `created_at` only, and
    it is never updated. A table that can be updated is a table nobody trusts
    to answer "did this happen?".
    """

    __tablename__ = "audit_logs"

    actor: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    """A username, or a machine identity for automated actions -- the
    convention is `mcp:<tool_name>` for an MCP tool call and `agent:<role>` for
    an agent turn, so a single query can separate human from machine activity
    without a second column."""

    action: Mapped[AuditAction] = mapped_column(_enum(AuditAction, "audit_action"), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    """`finding`, `ticket`, `remediation_proposal`, `pull_request`."""

    entity_id: Mapped[str | None] = mapped_column(String(64), default=None, index=True)
    """Stringified UUID rather than a foreign key. An audit log with hard FKs
    becomes a cascading-delete liability: deleting a finding would erase the
    record that it existed, which defeats the entire purpose."""

    correlation_id: Mapped[str | None] = mapped_column(String(120), default=None, index=True)
    summary: Mapped[str | None] = mapped_column(Text, default=None)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    """Structured detail. Must never contain a credential, a JWT, or an
    unbounded source file; identifiers and small scalars only."""

    created_at: Mapped[datetime] = mapped_column(
        # Python-side default, not `server_default=func.now()`: an audit row
        # must be timestamped at the moment the action was observed, and an
        # untrusted remote clock on the database host should not be able to
        # make an approval look like it happened before it did.
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
    )

    __table_args__ = (
        Index("ix_audit_logs_entity", "entity_type", "entity_id"),
        Index("ix_audit_logs_created_at", "created_at"),
        Index("ix_audit_logs_action_created", "action", "created_at"),
    )


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """An analyst, approver, or administrator.

    Minimal on purpose -- this project authenticates to demonstrate the
    authorization boundary in front of the human approval gate, not to be an
    identity provider. There is no SSO, no password reset, and no token
    revocation list; those belong to the platform's existing IdP in a real
    deployment.
    """

    __tablename__ = "users"

    username: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole, name="user_role", native_enum=False, length=32, validate_strings=True),
        default=UserRole.ANALYST,
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)


def audit_entity_ref(entity_id: object | None) -> str | None:
    """Normalize an entity id for the audit log's `entity_id` column.

    Accepts anything (`UUID`, `int`, `str`) and returns a string, because the
    column is deliberately a string and every call site would otherwise repeat
    the same `str(...)` cast.
    """
    if entity_id is None:
        return None
    return str(entity_id)
