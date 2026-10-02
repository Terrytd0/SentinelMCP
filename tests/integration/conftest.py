"""Shared fixtures for the real-service tests.

Two dependencies are optional at runtime and therefore optional in the test
suite: PostgreSQL and the gRPC scanning service. Each is resolved by a fixture
that *skips* rather than fails when it is unreachable, so a bare `pytest` on a
laptop with nothing running stays green and a run in CI with the full stack
actually exercises the real thing.

The database fixture truncates between tests rather than recreating the schema:
`CREATE TABLE` is slow, and truncation is the only reset that is actually safe
when the schema was created by Alembic rather than by the test. It also means
the tests run against the real migration, not a test-only shortcut schema.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from typing import Any

import pytest
import pytest_asyncio

# A dedicated test database, so a test run can never truncate a developer's
# working data. The name is fixed rather than generated so a crashed run leaves
# an inspectable database rather than an accumulating pile of orphans.
TEST_DATABASE_URL = os.environ.get(
    "SENTINEL_TEST_DATABASE_URL",
    "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test",
)


# Reachability is a property of the *machine*, not of any one test, and a
# container is either up for the whole run or absent for the whole run. Probing
# once and caching keeps ~250 tests from opening a throwaway connection each.
# Without the cache the suite pays a TCP handshake per test for an answer that
# cannot change mid-run.
_REACHABILITY_CACHE: dict[str, bool] = {}


def _skip_if_unreachable(url: str) -> None:
    """Skip the calling test when PostgreSQL is not answering.

    Synchronous, deliberately. It is called from both the async `db_session`
    fixture and the sync `live_database` fixture, and under
    `asyncio_mode = "auto"` the latter runs *inside* a live event loop -- where
    `anyio.run()` raises "Already running asyncio in this thread". A sync probe
    works in both contexts, and the driver is already a hard dependency
    (psycopg2, used by Alembic) so this needs no new import.

    Factored out of `db_session` because a handful of tests need the URL without
    needing a session -- the schema-drift guard shells out to `alembic check`,
    and the constraint probe manages its own engine. Those tests used to take
    the bare `test_database_url` and therefore *failed* with a connection error
    on a machine with no database, breaking the "a bare `pytest` with nothing
    running is green" invariant documented in tests/integration/README.md.
    """
    if url not in _REACHABILITY_CACHE:
        import psycopg2

        try:
            psycopg2.connect(_as_pg_dsn(url), connect_timeout=3).close()
        except Exception:  # noqa: BLE001 - unreachable is the expected answer here
            _REACHABILITY_CACHE[url] = False
        else:
            _REACHABILITY_CACHE[url] = True

    if not _REACHABILITY_CACHE[url]:
        pytest.skip(
            f"PostgreSQL not reachable at {url.split('@')[-1]}. "
            "Start one with `docker compose up -d postgres` and create the "
            "sentinel_test database, or set SENTINEL_TEST_DATABASE_URL."
        )


def _as_pg_dsn(url: str) -> str:
    """A libpq DSN for a SQLAlchemy URL, for the sync psycopg2 probe.

    Strips the `+asyncpg` driver suffix; libpq has never heard of it and the
    connection would fail with a driver error rather than a "server is down"
    error, which is the answer this probe is trying to get.
    """
    return url.replace("postgresql+asyncpg://", "postgresql://", 1).replace("+asyncpg", "")


@pytest.fixture(scope="session")
def test_database_url() -> str:
    """The test database URL.

    Synchronous and session-scoped on purpose: an *async* session-scoped fixture
    would bind to one event loop, while pytest-asyncio gives each test a fresh
    function-scoped one, and the engine created under the first would be unusable
    under the second. Returning a string has no loop attached to it, so the
    reachability probe can run on whichever loop the requesting test is on.
    """
    return TEST_DATABASE_URL


@pytest.fixture
def live_database(test_database_url: str) -> str:
    """The test database URL, having verified PostgreSQL answers.

    For tests that reach the database themselves rather than through
    `db_session`. A plain sync fixture on purpose -- see
    `_skip_if_unreachable` for why it cannot be async.
    """
    _skip_if_unreachable(test_database_url)
    return test_database_url


@pytest_asyncio.fixture
async def db_session(test_database_url: str) -> AsyncIterator[Any]:
    """A session against a clean test database, or skip the test.

    Truncates every table except `alembic_version`, so the schema the tests
    exercise is the one Alembic created. `RESTART IDENTITY` and `CASCADE` are
    both required: without CASCADE a truncate fails on foreign keys, and
    without RESTART IDENTITY sequences keep advancing across tests.
    """
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    _skip_if_unreachable(test_database_url)

    engine = create_async_engine(test_database_url, pool_pre_ping=True)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    async with engine.begin() as connection:
        await connection.execute(
            text(
                "TRUNCATE TABLE agent_runs, pull_requests, remediation_proposals, "
                "tickets, audit_logs, findings, users "
                "RESTART IDENTITY CASCADE"
            )
        )

    session = factory()
    try:
        yield session
    finally:
        await session.close()
        await engine.dispose()


@pytest_asyncio.fixture
async def seeded_session(db_session: Any) -> AsyncIterator[Any]:
    """A session with a scan's findings already persisted.

    Goes through the real `ScanningService` rather than inserting rows, so the
    fixture data satisfies the same invariants as production data -- correct
    fingerprints, SLA deadlines stamped, audit rows written.
    """
    from backend.database.repositories.ticket import AuditRepository
    from backend.mcp_server.server import build_scanner_backend
    from backend.services.scanning import ScanningService

    backend = await build_scanner_backend()
    service = ScanningService(db_session, backend, audit=AuditRepository(db_session))
    await service.run_scan(target="app/", actor="test:seeded_session")
    await db_session.commit()
    yield db_session


@pytest.fixture
def finding_id() -> uuid.UUID:
    """A stable id for a non-existent finding, for 404 paths."""
    return uuid.UUID(int=1)
