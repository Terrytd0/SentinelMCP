"""Async engine and session factory.

Loop-scoped, not process-wide, and that is a hard requirement rather than a
style preference. SQLAlchemy's async engine holds pooled connections that are
bound to whichever event loop first checked them out. This application
legitimately runs two long-lived loops -- FastAPI's request-handling loop, and
the dedicated background loop that `run_sync()` uses to bridge the *synchronous*
scanner and AutoGen code back into async Postgres calls -- so a single
module-level engine shared by both would eventually hand a connection created
on loop A to a caller on loop B. That raises `RuntimeError` at best and, worse,
leaves a poisoned connection in the pool that a later unrelated request draws
and 500s on.

`get_engine()` keys the engine by the running loop for exactly that reason;
`tests/integration/test_cross_loop_session.py` is the regression test.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from backend.config.settings import get_settings
from backend.core.logging import get_logger

logger = get_logger(__name__)

_engines: dict[asyncio.AbstractEventLoop, AsyncEngine] = {}
_session_factories: dict[asyncio.AbstractEventLoop, async_sessionmaker[AsyncSession]] = {}
_lock = asyncio.Lock()


def _loop_key() -> asyncio.AbstractEventLoop:
    """The running loop, which is the natural cache key for an async engine."""
    return asyncio.get_running_loop()


def get_engine() -> AsyncEngine:
    """Return the engine for the currently running loop, creating it once."""
    loop = _loop_key()
    engine = _engines.get(loop)
    if engine is None:
        settings = get_settings()
        engine = create_async_engine(
            settings.database_url,
            echo=settings.db_echo,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_pre_ping=True,
            future=True,
        )
        _engines[loop] = engine
        logger.debug("created async engine for this event loop")
    return engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    """Return the session factory for the currently running loop."""
    loop = _loop_key()
    factory = _session_factories.get(loop)
    if factory is None:
        factory = async_sessionmaker(
            bind=get_engine(),
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        _session_factories[loop] = factory
    return factory


@asynccontextmanager
async def transaction() -> AsyncIterator[AsyncSession]:
    """A session with commit-on-success and rollback-on-error.

    The single place that decides what "the request finished cleanly" means, so
    there is exactly one implementation of the commit for every caller. Three
    call sites used to spell this out separately and drifted:

        `get_session`        documented a commit it did not perform, so every
                             write made through a FastAPI route was discarded
                             when the session closed -- `POST /scans` answered
                             "8 findings created" and left the table empty.
        `session_scope`      got it right, for the one-off scripts.
        `get_db_session`     re-drove `get_session` by hand with `__anext__` and
                             `aclose`, and `aclose` throws `GeneratorExit` at
                             the `yield` -- so the commit that `get_session` did
                             perform was skipped anyway.

    All three now share this. If a fourth caller appears, it wraps this too.

    Note what is *not* handled: `GeneratorExit`. If a consumer abandons the
    generator without resuming it, the `except Exception` below does not match
    (it is a `BaseException`), no commit happens, and closing the session rolls
    the transaction back. That is the correct outcome for an abandoned request.
    """
    factory = get_session_factory()
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency yielding a request-scoped session.

    A thin generator over `transaction`, so it can be used directly as a
    FastAPI dependency. Declared as an `AsyncGenerator` rather than an
    `AsyncIterator` because callers that manage the lifetime themselves (see
    `backend/auth/dependencies.py::get_db_session`) need to be able to close
    it, and a bare `AsyncIterator` has no such method.
    """
    async with transaction() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncGenerator[AsyncSession]:
    """Standalone session context manager for non-request callers.

    The scripts (`seed`, `run_remediation`) and the sync-bridging path in
    `backend/core/asyncio_utils.py` need a session but have no request to hang
    a FastAPI dependency off.
    """
    async with transaction() as session:
        yield session


async def dispose_engines() -> None:
    """Close and forget every engine, on every loop.

    Called from FastAPI's shutdown hook and from the one-off scripts. Without
    it, a script that created an engine leaves an unclosed pool behind and
    emits `Task was destroyed but it is pending` on exit.
    """
    async with _lock:
        for engine in list(_engines.values()):
            await engine.dispose()
        _engines.clear()
        _session_factories.clear()
    logger.debug("disposed all async engines")


def engine_for_url(url: str, **overrides: Any) -> AsyncEngine:
    """Build a standalone engine for a specific URL.

    Used by the integration tests, which need an engine pointed at a scratch
    database rather than the configured one, and by the schema-drift guard.
    Deliberately not cached -- an ad-hoc engine has a caller-defined lifetime.
    """
    return create_async_engine(url, pool_pre_ping=True, future=True, **overrides)
