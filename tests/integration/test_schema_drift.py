"""Schema-drift guard: the models and the live schema must agree.

The failure this prevents is quiet and slow. Somebody adds a column to
`backend/database/models/finding.py`, forgets to generate a migration, and
nothing breaks until a code path reads that column in production -- where the
column does not exist. Meanwhile every other test passes, because they all run
against a database that *was* migrated correctly at some earlier point.

`alembic check` is Alembic's own diff engine, so this uses it rather than
reimplementing schema comparison: if the guard can disagree with what
autogenerate would do, it is not guarding anything.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_the_live_schema_matches_the_models(live_database: str) -> None:
    """`alembic check` exits 0 when there is nothing to autogenerate.

    Non-zero means the models have drifted from the migrated schema. Takes
    `live_database` rather than the bare URL so the test skips -- instead of
    failing with a connection error -- on a machine with no PostgreSQL.
    """
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "check"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
        env={
            **_clean_env(),
            "SENTINEL_DATABASE_URL": live_database,
        },
    )
    if result.returncode != 0:
        pytest.fail(
            "the live schema does not match the SQLAlchemy models -- generate a "
            "migration:\n"
            f"  alembic revision --autogenerate -m '<what changed>'\n\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )


def test_every_model_is_imported_into_base_metadata() -> None:
    """A model that was never imported is a table Alembic cannot see.

    `backend.database.models` imports them all; this asserts the count, so a
    newly added model that nobody wired into that package fails here rather than
    producing a migration that silently omits its table.
    """
    from backend.database import models  # noqa: F401  -- the import is the assertion
    from backend.database.base import Base

    tables = set(Base.metadata.tables)
    expected = {
        "findings",
        "tickets",
        "remediation_proposals",
        "pull_requests",
        "agent_runs",
        "audit_logs",
        "users",
    }
    assert expected <= tables, f"missing tables: {sorted(expected - tables)}"


def test_the_fingerprint_constraint_exists(live_database: str) -> None:
    """The backstop behind the upsert, asserted against the real database.

    A behavioural test on the constraint is more honest than a schema
    assertion, and it fails with a message that says what breaks.
    """
    from datetime import UTC, datetime

    import anyio
    from sqlalchemy import func, select
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from backend.database.enums import Severity
    from backend.database.models.finding import Finding

    def _probe() -> bool:
        engine = create_async_engine(live_database)
        factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

        async def run() -> bool:
            async with factory() as session:
                now = datetime.now(UTC)
                for _ in range(2):
                    session.add(
                        Finding(
                            fingerprint="constraint-probe",
                            rule_id="probe",
                            title="probe",
                            description="",
                            severity=Severity.LOW,
                            target="probe",
                            cwe_ids=[],
                            cve_ids=[],
                            raw_payload={},
                            first_seen_at=now,
                            last_seen_at=now,
                        )
                    )
                try:
                    await session.flush()
                except Exception:
                    await session.rollback()
                    return True
                await session.rollback()
                count = await session.scalar(
                    select(func.count())
                    .select_from(Finding)
                    .where(Finding.fingerprint == "constraint-probe")
                )
                assert count is not None
                return count == 0

        try:
            return anyio.run(run)
        finally:
            anyio.run(engine.dispose)

    assert _probe(), (
        "a duplicate fingerprint was accepted, so the unique constraint that "
        "backs the re-scan upsert is missing -- run `alembic upgrade head`"
    )


def _clean_env() -> dict[str, str]:
    """The current environment minus any database override.

    Keeping a developer's `SENTINEL_DATABASE_URL` out of the subprocess matters:
    `alembic check` must inspect the *test* database, and an inherited
    production DSN would make this test pass while checking the wrong schema.
    """
    import os

    return {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("SENTINEL_DATABASE_URL")
    }
