"""Sync/async bridge.

Scanners and the AutoGen agent loop are synchronous libraries. The HTTP API,
the gRPC server, and the MCP server are asynchronous. Rather than forcing
async wrappers through every scanner and agent call site, the sync work runs in
a worker thread and any async work it needs is driven from a *dedicated*
background loop -- not from the caller's loop, which is blocked waiting on the
thread.

Using a separate loop (instead of `asyncio.run_coroutine_threadsafe` against
the caller's loop) is what makes this safe alongside the loop-scoped engine in
`backend/database/session.py`: the thread gets its own loop, therefore its own
engine, therefore no connection is ever shared across two live loops.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from collections.abc import Coroutine
from typing import Any, TypeVar

from backend.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")

_loop: asyncio.AbstractEventLoop | None = None
_loop_thread: threading.Thread | None = None
_lock = threading.Lock()


def get_background_loop() -> asyncio.AbstractEventLoop:
    """Return the process-wide background loop, starting it on first use.

    A single long-lived loop on a dedicated daemon thread. Daemon so a hung
    loop cannot stop interpreter exit; long-lived so the loop-scoped engine
    keyed to it stays warm instead of being disposed and rebuilt per call.
    """
    global _loop, _loop_thread
    if _loop is not None and not _loop.is_closed():
        return _loop

    with _lock:
        if _loop is not None and not _loop.is_closed():
            return _loop
        new_loop = asyncio.new_event_loop()

        def _run() -> None:
            asyncio.set_event_loop(new_loop)
            new_loop.run_forever()

        thread = threading.Thread(target=_run, name="sentinel-background-loop", daemon=True)
        thread.start()
        _loop, _loop_thread = new_loop, thread
        logger.debug("started background event loop thread=%s", thread.name)
        return new_loop


async def run_sync(func: Any, /, *args: Any, **kwargs: Any) -> T:
    """Run a blocking callable in a thread and await its result.

        summary = await run_sync(scanner.scan, target="app/")

    `functools.partial` is used rather than a lambda so the call site keeps a
    readable repr in tracebacks and profiling output.
    """
    return await asyncio.to_thread(functools.partial(func, *args, **kwargs))


async def run_coroutine_on_background_loop(coro: Coroutine[Any, Any, T]) -> T:  # noqa: UP047
    """Await a coroutine on the background loop from inside a worker thread.

    The counterpart to `run_sync`, for sync code that needs to touch async
    infrastructure (Postgres, a gRPC channel). Marshals onto the background loop rather
    than calling `asyncio.run`, because a fresh loop per call would defeat the
    loop-scoped engine and throw away a connection pool on every remediation.

    Called from a worker thread, never from a thread that already has a
    running loop -- the caller cannot await it in that case, which is the
    correct outcome (that caller should have awaited `run_sync` instead).
    """
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "run_coroutine_on_background_loop() called from a thread with a "
            "running event loop; await run_sync() instead"
        )

    loop = get_background_loop()
    future = asyncio.run_coroutine_threadsafe(coro, loop)
    return await asyncio.wrap_future(future)


def shutdown_background_loop(timeout: float = 5.0) -> None:
    """Stop the background loop and join its thread.

    Safe to call when it was never started. Called from FastAPI's lifespan
    shutdown and at the end of the one-off scripts.
    """
    global _loop, _loop_thread
    with _lock:
        loop, thread = _loop, _loop_thread
        _loop, _loop_thread = None, None
    if loop is None:
        return
    loop.call_soon_threadsafe(loop.stop)
    if thread is not None:
        thread.join(timeout=timeout)
    loop.close()
    logger.debug("stopped background event loop")
