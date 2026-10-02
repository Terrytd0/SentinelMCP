"""Alembic environment.

Async by default, because the application is async and running migrations on a
second, differently-configured engine is how schema drift starts: a sync
migration engine and an async application engine can disagree about a type, and
only one of them is exercised in production.

`sync_engine` is kept for the two operations that genuinely need a blocking
driver -- `alembic check` and some offline SQL generation -- and it derives its
URL from the same `DATABASE_URL`, so there is exactly one place a DSN is
configured (`backend/config/settings.py`).

Autogenerate targets `Base.metadata`, which is only complete if every model
module has been imported. `backend.database.models` imports all of them, and
this file imports that package specifically so `alembic revision --autogenerate`
sees the same schema the application does.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context
from backend.config.settings import get_settings

# Importing the models package is what populates `Base.metadata`.
from backend.database.models import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
target_metadata = Base.metadata

# Two URLs, one source of truth (`backend.config.settings`).
#
# `database_url`            -> asyncpg. Used for the online run, because the
#                              application is async and running migrations on a
#                              differently-configured engine than production is
#                              how schema drift starts.
# `effective_database_url_sync` -> psycopg2. Used only to render offline SQL,
#                              where no connection is ever made and the driver
#                              is irrelevant -- the dialect is what matters.
#
# Deliberately *not* putting a URL in alembic.ini: a value there could
# disagree with the application's, and that disagreement is invisible until it
# has migrated the wrong database.
config.set_main_option("sqlalchemy.url", settings.database_url)


def run_migrations_offline() -> None:
    """Emit SQL to stdout without connecting.

    Used by `alembic upgrade head --sql` to produce a migration script for a DBA
    to review, which is how a regulated change gets applied by someone who is
    not the person who wrote it.
    """
    context.configure(
        url=settings.effective_database_url_sync,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Run the migrations on an already-established connection."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        # Type and server-default comparison are both on. Without
        # `compare_server_default`, a change to a column default is invisible to
        # autogenerate, and a default is exactly the kind of thing that
        # silently rots.
        compare_type=True,
        compare_server_default=True,
        # SQLite has no ALTER COLUMN; without this a rename looks like a
        # drop+add and autogenerate emits a destructive pair.
        render_as_batch=False,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Connect with the async driver and run the migrations."""
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    """Entry point for an online (connected) migration run."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
