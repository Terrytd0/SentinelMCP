"""Ticket and audit-log repositories."""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.clock import utc_now
from backend.core.ids import ticket_key
from backend.core.logging import get_logger
from backend.database.enums import AuditAction, Severity, TicketStatus
from backend.database.models.audit_log import AuditLog, audit_entity_ref
from backend.database.models.finding import Ticket

logger = get_logger(__name__)


class TicketRepository:
    """Data access for `tickets`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _next_sequence(self) -> int:
        """Next number in the `SEC-####` sequence.

        Computed as `MAX(numeric suffix) + 1` inside the caller's transaction.
        That is a race between two concurrent `create_ticket` calls, and the
        honest answer is that it is safe *here* because the unique constraint on
        `ticket_key` is the real guard -- a losing insert gets an
        `IntegrityError` and the service retries. A high-traffic deployment
        would want Postgres sequences instead; doing it this way keeps the
        demo running with no extra database object and the constraint still
        guarantees uniqueness.
        """
        result = await self._session.execute(select(func.max(func.substring(Ticket.ticket_key, 5))))
        highest = result.scalar_one_or_none()
        if highest is None:
            return 1001
        try:
            return int(highest) + 1
        except (TypeError, ValueError):  # pragma: no cover - defensive
            return 1001

    async def create_ticket(
        self,
        *,
        finding_id: uuid.UUID,
        title: str,
        description: str = "",
        priority: Severity = Severity.MEDIUM,
        created_by: str,
        assignee: str | None = None,
    ) -> Ticket:
        ticket = Ticket(
            ticket_key=ticket_key(await self._next_sequence()),
            finding_id=finding_id,
            title=title,
            description=description,
            priority=priority,
            status=TicketStatus.OPEN,
            created_by=created_by,
            assignee=assignee,
        )
        self._session.add(ticket)
        await self._session.flush()
        logger.info("created ticket ticket_key=%s finding_id=%s", ticket.ticket_key, finding_id)
        return ticket

    async def get(self, ticket_id: uuid.UUID) -> Ticket | None:
        return await self._session.get(Ticket, ticket_id)

    async def get_by_key(self, key: str) -> Ticket | None:
        result = await self._session.execute(select(Ticket).where(Ticket.ticket_key == key))
        return result.scalar_one_or_none()

    async def list_for_finding(self, finding_id: uuid.UUID) -> list[Ticket]:
        result = await self._session.execute(
            select(Ticket).where(Ticket.finding_id == finding_id).order_by(Ticket.created_at.desc())
        )
        return list(result.scalars().all())

    async def list_tickets(
        self, *, statuses: Sequence[TicketStatus] | None = None, limit: int = 100
    ) -> list[Ticket]:
        statement = select(Ticket)
        if statuses:
            statement = statement.where(Ticket.status.in_(list(statuses)))
        result = await self._session.execute(
            statement.order_by(Ticket.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def set_status(self, ticket_id: uuid.UUID, status: TicketStatus) -> Ticket | None:
        ticket = await self.get(ticket_id)
        if ticket is None:
            return None
        ticket.status = status
        if status in (TicketStatus.RESOLVED, TicketStatus.CLOSED):
            ticket.resolved_at = ticket.resolved_at or utc_now()
        else:
            ticket.resolved_at = None
        await self._session.flush()
        return ticket

    async def counts_by_status(self) -> dict[str, int]:
        result = await self._session.execute(
            select(Ticket.status, func.count()).group_by(Ticket.status)
        )
        return {str(s): c for s, c in result.all()}


class AuditRepository:
    """Append-only access to `audit_logs`.

    There is no `update` and no `delete`. That is the entire design: the
    guarantee "full audit log of every finding and every agent decision" is
    only worth anything if the rows cannot be rewritten after the fact.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        actor: str,
        action: AuditAction,
        entity_type: str,
        entity_id: object | None = None,
        correlation_id: str | None = None,
        summary: str | None = None,
        payload: dict[str, Any] | None = None,
    ) -> AuditLog:
        """Write one audit row.

        Takes `entity_id` as `object` and stringifies it, because callers hold
        UUIDs, ints, and strings interchangeably and every call site would
        otherwise repeat the cast.
        """
        entry = AuditLog(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=audit_entity_ref(entity_id),
            correlation_id=correlation_id,
            summary=summary,
            payload=payload or {},
            created_at=utc_now(),
        )
        self._session.add(entry)
        await self._session.flush()
        logger.debug("audit action=%s entity=%s actor=%s", action.value, entity_type, actor)
        return entry

    async def list_for_entity(
        self, entity_type: str, entity_id: object | None = None, *, limit: int = 200
    ) -> list[AuditLog]:
        """Full history for one entity, oldest first."""
        statement = select(AuditLog).where(AuditLog.entity_type == entity_type)
        resolved = audit_entity_ref(entity_id)
        if resolved is not None:
            statement = statement.where(AuditLog.entity_id == resolved)
        result = await self._session.execute(
            statement.order_by(AuditLog.created_at.asc()).limit(limit)
        )
        return list(result.scalars().all())

    async def list_by_correlation(self, correlation_id: str, *, limit: int = 500) -> list[AuditLog]:
        """Every action taken during one externally-triggered operation.

        This is the query an incident responder runs: one correlation id in,
        the complete chain of what the system did, in order, across findings,
        proposals, pull requests, and MCP tool calls.
        """
        result = await self._session.execute(
            select(AuditLog)
            .where(AuditLog.correlation_id == correlation_id)
            .order_by(AuditLog.created_at.asc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def list_recent(
        self, *, actions: Sequence[AuditAction] | None = None, limit: int = 100
    ) -> list[AuditLog]:
        statement = select(AuditLog)
        if actions:
            statement = statement.where(AuditLog.action.in_(list(actions)))
        result = await self._session.execute(
            statement.order_by(AuditLog.created_at.desc()).limit(limit)
        )
        return list(result.scalars().all())

    async def count_by_action(self) -> dict[str, int]:
        result = await self._session.execute(
            select(AuditLog.action, func.count()).group_by(AuditLog.action)
        )
        return {str(a): c for a, c in result.all()}
