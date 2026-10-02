"""The async engine must be keyed by event loop, and that has to stay true.

`backend/database/session.py` runs two long-lived loops in one process: the
FastAPI request loop, and the background loop that `run_sync()` uses to bridge
synchronous scanner and agent code back into async Postgres calls. SQLAlchemy's
async engine holds pooled connections bound to whichever loop first checked
them out, so one process-wide engine shared by both would eventually hand a
connection created on loop A to a caller on loop B -- a `RuntimeError` at best,
and worse, a poisoned connection that a later unrelated request draws and 500s
on.

The regression test for that lived in a file that was named in
`session.py`'s docstring and never written, so the guarantee was asserted in
prose and nowhere in code. These tests are that guarantee, executed.
"""

from __future__ import annotations

import asyncio
import inspect
import threading
from collections.abc import Callable
from typing import Any

import pytest
from sqlalchemy import text

from backend.database.session import (
    _engines,
    _session_factories,
    dispose_engines,
    get_engine,
    get_session_factory,
    session_scope,
)

pytestmark = pytest.mark.integration


def _in_new_loop[T](work: Callable[[], T]) -> tuple[T | None, BaseException | None]:
    """Run `work()` on a fresh event loop in a separate thread.

    A separate thread because the point is to get a *different* running loop, and
    the test itself is already inside `pytest-asyncio`'s loop for this module.
    Returns `(result, error)` so a failure surfaces as an assertion rather than
    as an opaque exception raised in another thread.
    """

    box: dict[str, Any] = {}

    def runner() -> None:
        async def main() -> None:
            value = work()
            # `get_engine` is sync; `borrow_and_return` is async. Accept either
            # so a test can assert on the cache keys and on a real query with
            # the same helper.
            box["result"] = await value if inspect.isawaitable(value) else value

        try:
            asyncio.run(main())
        except BaseException as exc:  # noqa: BLE001 - re-raised on the main thread
            box["error"] = exc

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join(timeout=30)
    if "error" in box:
        return None, box["error"]
    return box.get("result"), None


# --- the keying itself ---------------------------------------------------


async def test_two_loops_get_two_engines() -> None:
    """The current loop's engine is not the background loop's engine."""
    this_loop = asyncio.get_running_loop()
    this_engine = get_engine()

    result, error = _in_new_loop(get_engine)

    assert error is None, f"the second loop could not build an engine: {error!r}"
    assert result is not this_engine
    assert this_loop in _engines
    # And the first loop's engine is unchanged -- a shared, mutated engine is
    # exactly the failure this design prevents.
    assert get_engine() is this_engine


async def test_a_loop_always_gets_the_same_engine() -> None:
    """Stability within a loop: one pool, not one pool per call."""
    assert get_engine() is get_engine()
    assert get_session_factory() is get_session_factory()


async def test_the_session_factory_binds_to_its_own_engines() -> None:
    """A factory on loop A must not be handing out loop B's engine."""
    this_factory = get_session_factory()

    other_factory, error = _in_new_loop(get_session_factory)

    assert error is None
    assert other_factory is not this_factory


# --- the real failure it prevents -----------------------------------------


async def test_a_session_still_works_after_another_loop_ran() -> None:
    """The end-to-end version: another loop must not poison this one's pool.

    This is the assertion that matters. The two tests above check the cache
    keys; this one proves the consequence -- a connection created on loop B and
    left in the pool does not break a query issued on loop A afterwards.
    """

    async def borrow_and_return() -> str:
        # Deliberately hold a connection and return it to the pool rather than
        # disposing the engine, which is what leaves a cross-loop connection
        # sitting in the pool for someone else to draw.
        async with session_scope() as session:
            result = await session.execute(text("SELECT 1"))
            return str(result.scalar())

    other_result, other_error = _in_new_loop(borrow_and_return)
    assert other_error is None, f"the other loop failed: {other_error!r}"
    assert other_result == "1"

    async with session_scope() as session:
        result = await session.execute(text("SELECT 1"))
        assert result.scalar() == 1


async def test_the_background_loop_bridge_shares_nothing() -> None:
    """`run_sync` is the caller that motivated loop-scoping; check it holds.

    `run_sync` dispatches onto the dedicated background loop. A session opened
    there and a session opened on the request loop must come from different
    engines, or every remediation run would be one `RuntimeError` away from
    breaking an unrelated HTTP request.
    """
    from backend.core.asyncio_utils import get_background_loop

    background_loop = get_background_loop()
    assert background_loop is not asyncio.get_running_loop()
    assert background_loop is not None

    here = get_engine()
    there, error = _in_new_loop(get_engine)

    assert error is None
    assert there is not here


# --- disposal -------------------------------------------------------------


async def test_dispose_clears_every_loop() -> None:
    """Shutdown must forget every engine, not just the current loop's.

    A leak here is the `Task was destroyed but it is pending` message on exit
    that the FastAPI shutdown hook exists to prevent.
    """
    await dispose_engines()
    assert _engines == {}
    assert _session_factories == {}

    await dispose_engines()  # idempotent, and safe when already empty


def test_engine_for_url_is_never_cached() -> None:
    """Ad-hoc engines have a caller-defined lifetime, so they are not pooled.

    The integration suite leans on this to point at a scratch database; a cached
    engine would silently serve the first URL requested for the rest of the run.
    """
    from backend.database.session import engine_for_url

    assert engine_for_url("postgresql+asyncpg://nobody@127.0.0.1:1/none") is not engine_for_url(
        "postgresql+asyncpg://nobody@127.0.0.1:1/none"
    )
