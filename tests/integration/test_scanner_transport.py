"""Transport selection: does the running process actually cross the gRPC boundary?

`build_scanner_backend` has three modes, and this file pins down which one a
given configuration actually produces. The reason these are tests rather than a
comment: this project shipped a `build_scanner_backend` that *always* returned
the in-process client, so every docstring, the compose file, and the proto all
described a gRPC boundary that no production path ever crossed. Nothing failed
-- the whole suite was green -- because a transport decision that silently
degrades looks exactly like a transport decision that works.

So these tests assert on the *class* of the returned backend and on real wire
traffic, not on a mock's call count.

A real `ScannerServer` is bound on an ephemeral port for the reachable cases.
The unreachable case points at a reserved port nothing will be bound to, which
is what a reviewer running bare `uvicorn backend.main:app` actually gets.
"""

from __future__ import annotations

import contextlib
import os
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest

from backend.config.settings import Settings, get_settings
from backend.grpc_service.client import GrpcScannerClient, InProcessScannerClient
from backend.grpc_service.server import ScannerServer
from backend.mcp_server.server import GRPC_PROBE_TIMEOUT_SECONDS, build_scanner_backend
from backend.scanners.registry import ScannerRegistry

pytestmark = pytest.mark.integration

# 127.0.0.1:1 is reserved, so a connect is refused immediately instead of
# hanging on a filtered address.
DEAD_TARGET = "127.0.0.1:1"


@pytest.fixture
async def live_target(registry: ScannerRegistry) -> AsyncIterator[str]:
    """A real scanning service on an ephemeral port, torn down after the test."""
    server = ScannerServer(registry, host="127.0.0.1", port=0)
    await server.start()
    try:
        yield f"127.0.0.1:{server.port}"
    finally:
        await server.stop(grace=0.5)


def _settings_for(transport: str, target: str) -> Settings:
    """Settings with only the transport decision overridden."""
    return get_settings().model_copy(
        update={
            "scanner_transport": transport,
            "grpc_client_target": target,
            "grpc_timeout_seconds": 10.0,
        }
    )


@contextlib.asynccontextmanager
async def _open(settings: Settings) -> AsyncIterator[Any]:
    """Build a backend, hand it to the test, close it afterwards.

    Closing is conditional because only the gRPC client owns a channel; the
    in-process one has nothing to release.
    """
    backend = await build_scanner_backend(settings)
    try:
        yield backend
    finally:
        if hasattr(backend, "close"):
            await backend.close()


# --- transport=in_process -------------------------------------------------


async def test_in_process_never_dials_grpc() -> None:
    """`in_process` must not even attempt a connection.

    The target is dead, so this only proves the mode is chosen by config rather
    than by whether the network happens to cooperate.
    """
    settings = _settings_for("in_process", DEAD_TARGET)
    async with _open(settings) as backend:
        assert isinstance(backend, InProcessScannerClient)
        assert not isinstance(backend, GrpcScannerClient)


async def test_in_process_still_scans(live_target: str) -> None:
    """The fallback is a working scanner, not a stub that raises."""
    settings = _settings_for("in_process", live_target)
    async with _open(settings) as backend:
        result = await backend.scan("app/")
    assert result.findings
    assert result.error is None


# --- transport=grpc ------------------------------------------------------


async def test_grpc_is_selected_without_probing() -> None:
    """`grpc` is a trust-me mode: it must not fall back, even to a dead target.

    If it silently degraded, a deployment configured for a separate scanning
    service would report itself healthy while scanning in-process -- which is
    the precise lie this mode exists to prevent.
    """
    settings = _settings_for("grpc", DEAD_TARGET)
    async with _open(settings) as backend:
        assert isinstance(backend, GrpcScannerClient)


async def test_grpc_does_not_block_at_build_time() -> None:
    """Building a `grpc` backend must not wait on a dead target.

    The FastAPI lifespan calls this before serving anything, so a connect stall
    would present as a hung process rather than as a config error.
    """
    settings = _settings_for("grpc", DEAD_TARGET)
    started = time.monotonic()
    async with _open(settings):
        pass
    assert time.monotonic() - started < 1.0


async def test_grpc_scans_a_real_service(live_target: str) -> None:
    """A real request and a real response, over a real socket."""
    settings = _settings_for("grpc", live_target)
    async with _open(settings) as backend:
        result = await backend.scan("app/", correlation_id="transport-test")
    assert result.findings
    assert result.error is None
    assert result.target == "app/"


# --- transport=auto ------------------------------------------------------


async def test_auto_uses_grpc_when_the_service_is_there(live_target: str) -> None:
    settings = _settings_for("auto", live_target)
    async with _open(settings) as backend:
        assert isinstance(backend, GrpcScannerClient)


async def test_auto_falls_back_when_nothing_is_listening() -> None:
    settings = _settings_for("auto", DEAD_TARGET)
    async with _open(settings) as backend:
        assert isinstance(backend, InProcessScannerClient)


async def test_auto_fallback_is_fast_enough_for_a_stdio_client() -> None:
    """The probe must not use the full scan timeout.

    A stdio MCP host spawns this process and blocks on it, so a fallback that
    took `grpc_timeout_seconds` to notice nothing was listening would present
    to the user as a server that hangs on connect. This is the regression the
    separate `GRPC_PROBE_TIMEOUT_SECONDS` exists to prevent.
    """
    settings = _settings_for("auto", DEAD_TARGET)
    started = time.monotonic()
    async with _open(settings):
        pass
    elapsed = time.monotonic() - started
    assert elapsed < 4.0, f"auto fallback took {elapsed:.1f}s to give up"
    assert GRPC_PROBE_TIMEOUT_SECONDS < 4.0


async def test_auto_falls_back_to_a_working_scanner() -> None:
    """Degrading must degrade to something that works, not to an error."""
    settings = _settings_for("auto", DEAD_TARGET)
    async with _open(settings) as backend:
        result = await backend.scan("app/")
    assert result.findings


# --- configuration surface -----------------------------------------------


def test_the_declared_default_is_auto() -> None:
    """Pinned so a future edit cannot quietly make the wire the default.

    Asserted on the *declared* default rather than the resolved value, because
    `tests/conftest.py` pins `SENTINEL_SCANNER_TRANSPORT=in_process` to keep the
    suite hermetic -- so `get_settings()` here is not "what a deployment gets".

    `auto` is a deliberate compromise: `grpc` would break a bare `uvicorn`, and
    `in_process` would make the gRPC service decorative. If this value changes,
    ADR 003 and the README change with it.
    """
    assert Settings.model_fields["scanner_transport"].default == "auto"


def test_the_test_suite_pins_the_in_process_transport() -> None:
    """The suite must not be decided by whatever happens to be on port 50051.

    This is the bug that produced a confusing failure: a developer with
    `make scanner` running would get a green suite locally and a different one
    in CI, purely from ambient network state.
    """
    assert get_settings().scanner_transport == "in_process"
    assert os.environ["SENTINEL_SCANNER_TRANSPORT"] == "in_process"


def test_an_unknown_transport_is_rejected_at_load() -> None:
    """A typo must fail when settings are loaded, not be treated as `auto`."""
    with pytest.raises(ValueError, match="scanner_transport"):
        Settings(scanner_transport="grpc-ish")  # type: ignore[arg-type]
