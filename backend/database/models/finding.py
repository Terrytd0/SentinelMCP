"""The `findings` table -- a security finding and its remediation lifecycle.

One row per distinct finding, keyed by `fingerprint` rather than by scan run.
That is the single most important modelling decision in this file: a scanner
re-run over unchanged code must *update* the existing finding, not create a
second one. Otherwise every scheduled scan inflates the open-finding count,
the SLA dashboard permanently drifts upward, and nobody can answer "how many
real issues do we have?" -- which is the only question the dashboard exists
to answer. See `backend/services/scanning.py::persist_findings`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin
from backend.database.enums import Confidence, FindingStatus, ScannerKind, Severity, TicketStatus

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance for type checkers only
    # `remediation.py` imports `_enum` from here, so a runtime import would be a
    # cycle. `from __future__ import annotations` means these names are only ever
    # needed by a type checker.
    from backend.database.models.remediation import RemediationProposal


def _enum(py_enum: type, name: str) -> SAEnum:
    """Build a SQLAlchemy Enum column type for one of our string enums.

    `native_enum=False` so the column is a VARCHAR + CHECK constraint rather
    than a Postgres `ENUM` type. Postgres enums are painful to evolve --
    adding a value needs `ALTER TYPE` and the reverse ordering is not
    supported at all -- and these lists will grow (a new scanner, a new
    proposal state). A VARCHAR keeps `ALTER TABLE ADD CONSTRAINT` as the only
    migration primitive required, which Alembic generates correctly.
    """
    return SAEnum(py_enum, name=name, native_enum=False, length=32, validate_strings=True)


class Finding(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A single security finding plus everything the SLA engine needs."""

    __tablename__ = "findings"

    # --- Identity -------------------------------------------------------
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    """Content-derived identity. `sha256(scanner_kind | rule_id | normalized location)`,
    truncated to 64 hex chars. Unique -- re-scanning an unchanged finding
    updates this row."""

    rule_id: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # --- Classification -------------------------------------------------
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        _enum(Confidence, "confidence"), default=Confidence.UNSPECIFIED, nullable=False
    )
    scanner_kind: Mapped[ScannerKind] = mapped_column(
        _enum(ScannerKind, "scanner_kind"), default=ScannerKind.UNSPECIFIED, nullable=False
    )

    # --- Location -------------------------------------------------------
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(1000), default=None)
    start_line: Mapped[int | None] = mapped_column(Integer, default=None)
    end_line: Mapped[int | None] = mapped_column(Integer, default=None)
    snippet: Mapped[str | None] = mapped_column(Text, default=None)
    """The offending source lines, verbatim. Stored because the whole point of
    the project is drafting a patch against them later; truncated by the
    scanner, never synthesized."""

    # --- External references --------------------------------------------
    # JSONB, not JSON, and the distinction is load-bearing: Postgres cannot
    # build a GIN index over a `json` column ("data type json has no default
    # operator class for access method gin"), and JSONB additionally gives us the
    # `@>` containment operator that `find_by_cve` queries with. The cost is that
    # JSONB normalizes key order and strips duplicate keys -- irrelevant for a
    # list of CVE strings, and why `raw_payload` below stays `JSON`.
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    """The scanner's own JSON, preserved verbatim so a finding can always be
    explained in the scanner's own terms and re-derived if we get the mapping
    wrong."""

    # --- Lifecycle ------------------------------------------------------
    status: Mapped[FindingStatus] = mapped_column(
        _enum(FindingStatus, "finding_status"),
        default=FindingStatus.OPEN,
        nullable=False,
    )

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    """`first_seen_at` is immutable and starts the SLA clock; `last_seen_at`
    advances on every re-scan. The dashboard reports "new this week" from the
    first and "still open" from the second, and conflating them is how a
    two-year-old finding gets reported as newly discovered."""

    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    """When the finding reached a terminal state. Null while it is still
    actionable, which is what the SLA query filters on."""

    # --- Auto-remediation posture ---------------------------------------
    remediation_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    """How many agent loops have run against this finding. Bounded by
    `remediation_max_rounds` inside the loop; the counter is here so an
    operator can see a finding that has been re-attempted without success."""

    auto_remediation_eligible: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    """Whether policy permits the agent to draft a patch at all. False for
    low-confidence findings and for anything whose file path is outside the
    configured source roots -- the agent is never handed a path it should not
    be able to write a patch for."""

    scan_id: Mapped[uuid.UUID | None] = mapped_column(default=None)
    """The scan that most recently reported this finding. Not a foreign key:
    scan runs are cheap and disposable, findings are the durable record, and a
    hard FK would mean deleting scan history becomes a cascading-delete
    hazard on the table everyone actually queries."""

    # --- Relationships --------------------------------------------------
    tickets: Mapped[list[Ticket]] = relationship(  # noqa: F821
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )
    proposals: Mapped[list[RemediationProposal]] = relationship(  # noqa: F821
        back_populates="finding", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        # The dashboard's main query: open findings, most urgent first.
        Index("ix_findings_status_severity", "status", "severity"),
        # `list_findings` filters on scanner and target within a scan.
        Index("ix_findings_scanner_target", "scanner_kind", "target"),
        # SLA sweep: "everything with a deadline, ordered by deadline".
        Index("ix_findings_sla_due_at", "sla_due_at"),
        Index("ix_findings_cve_ids", "cve_ids", postgresql_using="gin"),
    )


class Ticket(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """A tracked remediation ticket.

    Distinct from a finding: a finding is a scanner's claim, a ticket is the
    human team's unit of work. One finding can have several tickets over its
    life (a re-scan reopening a closed one, a change in scope), which is why
    the relationship is one-to-many rather than a 1:1 `ticket_id` column on
    the finding.
    """

    __tablename__ = "tickets"

    ticket_key: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    """Human-facing identifier, e.g. `SEC-1042`. Assigned by the database
    sequence-like counter in `backend/services/tickets.py`, not by the
    scanner, so the key is stable across re-scans."""

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[TicketStatus] = mapped_column(
        _enum(TicketStatus, "ticket_status"), default=TicketStatus.OPEN, nullable=False
    )
    priority: Mapped[Severity] = mapped_column(
        _enum(Severity, "ticket_priority"), default=Severity.MEDIUM, nullable=False
    )
    assignee: Mapped[str | None] = mapped_column(String(255), default=None)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    """Who or what opened it. `mcp:propose_fix` for an agent-initiated ticket,
    or a username. Recorded so the audit trail distinguishes machine-created
    work from human-created work without needing to join `audit_logs`."""

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    finding: Mapped[Finding] = relationship(back_populates="tickets")  # noqa: F821

    __table_args__ = (Index("ix_tickets_status_priority", "status", "priority"),)
