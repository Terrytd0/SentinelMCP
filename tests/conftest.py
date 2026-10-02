"""Shared test fixtures.

Two rules this project follows, and the reason for both:

1. **`pytest` with no flags and no services running must pass.** Every unit
   test mocks its database at the repository boundary and its scanner at the
   `ScannerBackend` boundary. A test that needs a real Postgres belongs in
   `tests/integration/` under the `integration` marker, and must skip itself
   rather than fail when the service is not up. That way `pytest` is always a
   safe thing to run, which is the only way it stays run.

2. **The suite never depends on ambient network state.** A test that builds a
   scanner backend must get the same one on a developer laptop, in CI, and on a
   machine that happens to have a scanning service running on port 50051. The
   in-process transport is pinned below for that reason -- see the note there.

3. **No test module basename is reused across directories.** `tests/` has no
   `__init__.py` (pytest does not need them), so two `test_rules.py` files in
   different packages collide under pytest's rootdir-based module naming.
   Every test file name in this suite is unique for that reason.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

# Telemetry must not write files or open sockets during a unit test run. Set
# before any application module is imported, because `get_telemetry_client`
# builds its sink from settings on first use.
os.environ.setdefault("SENTINEL_TELEMETRY_SINK", "null")
os.environ.setdefault("SENTINEL_APP_ENV", "test")

# The default is `auto`, which dials the configured gRPC target and falls back
# to in-process. That is right for a deployment and wrong for a test suite: a
# developer with `make scanner` running in another terminal would have the
# integration tests silently switch transports mid-run and assert against
# whichever scanner answered. `in_process` makes the suite hermetic. The gRPC
# transport is still covered for real, by tests that start their own server on
# an ephemeral port and point a client at it explicitly.
os.environ.setdefault("SENTINEL_SCANNER_TRANSPORT", "in_process")


@pytest.fixture(autouse=True)
def _isolated_settings() -> Iterator[None]:
    """Reset the settings and telemetry singletons around every test.

    Both are process-wide and cached. Without this reset, a test that sets
    `SENTINEL_AUTH_ENABLED=false` would silently change the behaviour of every
    test that runs after it, which is the single most common source of
    "passes alone, fails in the suite".
    """
    from backend.config.settings import reload_settings
    from backend.telemetry import reset_telemetry_client

    reload_settings()
    reset_telemetry_client()
    yield
    reload_settings()
    reset_telemetry_client()


@pytest.fixture
def telemetry() -> Any:
    """A `TelemetryClient` writing to a list, for asserting on events."""
    from backend.telemetry.client import TelemetryClient

    class _RecordingSink:
        def __init__(self) -> None:
            self.events: list[Any] = []

        def write(self, event: Any) -> None:
            self.events.append(event)

    sink = _RecordingSink()
    client = TelemetryClient(service="SentinelMCP-test", sink=sink)
    client._test_sink = sink  # type: ignore[attr-defined]  # noqa: SLF001
    return client


@pytest.fixture
def settings() -> Any:
    from backend.config.settings import get_settings

    return get_settings()


@pytest.fixture
def registry() -> Any:
    """A scanner registry with only the fixture scanner, pointed at real fixtures."""
    from backend.scanners.fixture import FixtureScanner
    from backend.scanners.registry import ScannerRegistry

    return ScannerRegistry([FixtureScanner("data/fixtures")])


@pytest.fixture
def in_process_backend(registry: Any) -> Any:
    from backend.grpc_service.client import InProcessScannerClient

    return InProcessScannerClient(registry)


@pytest.fixture
def deterministic_engine() -> Any:
    from backend.agents.autogen_loop import DeterministicRemediationEngine

    return DeterministicRemediationEngine()
