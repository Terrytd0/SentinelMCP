"""Declarative base and reusable column mixins."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from backend.core.clock import utc_now

# Explicit naming convention so Alembic autogenerate produces stable,
# reversible constraint names. Without this, Postgres invents names like
# `findings_pkey_1` for anything created without an explicit name, and the
# downgrade path stops working the moment a table is recreated.
NAMING_CONVENTION: dict[str, str] = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every ORM model.

    All tables share the naming convention above. `metadata` is created
    eagerly rather than per-model so Alembic's autogenerate and the
    `tests/integration/test_schema_drift.py` guard see an identical view
    of the schema.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)

    def __repr__(self) -> str:
        pk = getattr(self, "id", None)
        return f"<{type(self).__name__} id={pk}>"


class UUIDPrimaryKeyMixin:
    """UUID v4 surrogate primary key.

    A UUID rather than a serial integer because these rows are created by
    several independent processes (the gRPC scanner, the MCP server, the API,
    CI) and a shared sequence becomes a contention point they all have to know
    about. The cost is 16 bytes per row, which is irrelevant at the volume a
    single security team produces.
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """`created_at` / `updated_at`, both timezone-aware.

    `server_default=func.now()` rather than a Python-side default: the database
    clock is the authority. A row inserted by a scanner on a machine with a
    skewed clock would otherwise get a `created_at` that disagrees with the
    SLA arithmetic, and SLA breaches are exactly the thing that ends up in a
    dispute with a client.
    """

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


def utc_now_default() -> Any:
    """Python-side UTC default, for the columns that cannot use `func.now()`.

    Used where the value is computed rather than observed (a SLA deadline is
    derived from settings, not from "when the row happened to be written"), so
    a database-side `now()` would be the wrong source of truth.
    """
    return utc_now()
