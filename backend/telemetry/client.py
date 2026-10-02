"""The telemetry client every measured operation in SentinelMCP goes through.

The contract this enforces is the important part: **telemetry can never fail
the operation it is measuring.** A slow log file, a dead collector, a DNS
failure -- none of those may turn a successful scan into an error, or the
monitoring system becomes the outage. So every emit is wrapped, every sink
failure is swallowed after one warning, and a sink that has failed repeatedly
is disabled outright rather than being retried into a hot loop.

Three sinks (`telemetry_sink` in settings):
    "file" -- append JSONL locally. Default, zero dependencies, and the shape
             Aegis will eventually consume off a shared bus.
    "http" -- POST each event to `telemetry_endpoint`.
    "null" -- discard. What tests use.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol

from backend.config.settings import Settings, get_settings
from backend.core.logging import get_logger
from backend.telemetry.events import EventStatus, TelemetryEvent

logger = get_logger(__name__)

# After this many consecutive sink failures, stop trying for this process.
# A permanently dead collector should cost one warning, not a retry storm.
_FAILURE_BUDGET = 5


class TelemetrySink(Protocol):
    """Where events go. Implementations must not raise."""

    def write(self, event: TelemetryEvent) -> None: ...


class NullSink:
    """Discards everything. Used when `telemetry_sink=null` and by tests."""

    def write(self, event: TelemetryEvent) -> None:
        return None


class JsonlFileSink:
    """Appends one JSON object per line to a local file.

    Line-delimited rather than a JSON array so a reader can tail the file while
    it is being written, and so a truncated final line from a hard kill costs
    one event instead of the whole file.

    Serialized under a lock because a gRPC server or the AutoGen loop emits from
    a thread pool, and interleaved partial writes on a shared handle produce
    corrupt lines that are painful to diagnose.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        # Create the parent directory eagerly: a missing directory should fail
        # at startup (loudly, once) rather than silently on the first event.
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(self, event: TelemetryEvent) -> None:
        payload = event.model_dump(mode="json")
        line = json.dumps(payload, separators=(",", ":"), default=str)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class HttpSink:
    """POSTs each event as JSON to a collector endpoint.

    Imports httpx lazily so a deployment using the file sink does not pay for
    an HTTP client it never uses, and so an httpx problem cannot break startup.
    """

    def __init__(self, endpoint: str, timeout_seconds: float = 2.0) -> None:
        self._endpoint = endpoint
        self._timeout = timeout_seconds
        self._client: Any | None = None

    def _get_client(self) -> Any:
        if self._client is None:
            import httpx

            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def write(self, event: TelemetryEvent) -> None:
        self._get_client().post(self._endpoint, json=event.model_dump(mode="json"))


class TelemetryClient:
    """Emits `TelemetryEvent`s to a sink, and never raises.

    Also provides `measure()`, a context manager that times a block, derives
    the status from whether it raised, and attaches token/cost figures. Using
    it consistently is what makes the event stream uniform enough for Aegis to
    actually aggregate it.
    """

    def __init__(
        self,
        service: str | None = None,
        sink: TelemetrySink | None = None,
    ) -> None:
        settings = get_settings()
        self._service = service or settings.telemetry_service
        self._sink: TelemetrySink = sink if sink is not None else _build_sink(settings)
        self._consecutive_failures = 0
        self._disabled = False
        self._lock = threading.Lock()

    @property
    def service(self) -> str:
        return self._service

    def emit(
        self,
        operation: str,
        *,
        latency_ms: float = 0.0,
        tokens_used: int = 0,
        cost: float = 0.0,
        status: EventStatus = EventStatus.SUCCESS,
        correlation_id: str | None = None,
        error_type: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Emit one event. Guaranteed not to raise, ever.

        Callers instrumenting a success path can rely on this never raising;
        that guarantee is what lets it be called from `finally` blocks and
        error handlers without another layer of defensive code.
        """
        if self._disabled:
            return

        event = TelemetryEvent(
            service=self._service,
            operation=operation,
            latency_ms=round(latency_ms, 3),
            tokens_used=tokens_used,
            cost=round(cost, 6),
            status=status,
            correlation_id=correlation_id,
            error_type=error_type,
            metadata=metadata or {},
        )
        self._deliver(event)

    def _deliver(self, event: TelemetryEvent) -> None:
        try:
            self._sink.write(event)
        except Exception as exc:  # noqa: BLE001 -- deliberate: telemetry must never propagate.
            with self._lock:
                self._consecutive_failures += 1
                failures = self._consecutive_failures
                should_disable = failures >= _FAILURE_BUDGET
                if should_disable:
                    self._disabled = True
            # The sink is a side channel; its failure is worth one line, and
            # the *type* only -- an HTTP error body can contain the payload.
            if should_disable:
                logger.warning(
                    "telemetry sink disabled after %d consecutive failures error_type=%s",
                    failures,
                    type(exc).__name__,
                )
            else:
                logger.debug("telemetry sink write failed error_type=%s", type(exc).__name__)
            return

        with self._lock:
            self._consecutive_failures = 0

    @contextmanager
    def measure(
        self,
        operation: str,
        *,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Iterator[_Measurement]:
        """Time a block and emit its event on the way out.

            with telemetry.measure("grpc.scan", correlation_id=cid) as m:
                report = scanner.scan(target)
                m.tokens_used = 0
                m.metadata = {"findings": len(report.findings)}

        Status is derived from the outcome: a raised `TimeoutError` becomes
        `timeout`, anything else becomes `error`, and no exception is
        suppressed -- the block's own error handling still runs, and callers
        see the original traceback.
        """
        measurement = _Measurement(measurement_client=self, metadata=dict(metadata or {}))
        started = time.perf_counter()
        try:
            yield measurement
        except TimeoutError as exc:
            measurement._finish(
                operation,
                time.perf_counter() - started,
                EventStatus.TIMEOUT,
                type(exc).__name__,
                correlation_id,
            )
            raise
        except Exception as exc:
            measurement._finish(
                operation,
                time.perf_counter() - started,
                EventStatus.ERROR,
                type(exc).__name__,
                correlation_id,
            )
            raise
        else:
            measurement._finish(
                operation, time.perf_counter() - started, EventStatus.SUCCESS, None, correlation_id
            )


class _Measurement:
    """Mutable handle yielded by `TelemetryClient.measure()`.

    Callers set `tokens_used`, `cost`, or replace `metadata` inside the block;
    whatever is there at exit is what gets emitted.
    """

    def __init__(self, measurement_client: TelemetryClient, metadata: dict[str, Any]) -> None:
        self._client = measurement_client
        self.tokens_used = 0
        self.cost = 0.0
        self.metadata = metadata

    def _finish(
        self,
        operation: str,
        elapsed_s: float,
        status: EventStatus,
        error_type: str | None,
        correlation_id: str | None,
    ) -> None:
        self._client.emit(
            operation,
            latency_ms=elapsed_s * 1000.0,
            tokens_used=self.tokens_used,
            cost=self.cost,
            status=status,
            correlation_id=correlation_id,
            error_type=error_type,
            metadata=self.metadata,
        )


def _build_sink(settings: Settings) -> TelemetrySink:
    match settings.telemetry_sink:
        case "file":
            return JsonlFileSink(settings.telemetry_file)
        case "http":
            if not settings.telemetry_endpoint:
                logger.warning(
                    "telemetry_sink=http but telemetry_endpoint is empty; discarding events"
                )
                return NullSink()
            return HttpSink(settings.telemetry_endpoint, settings.telemetry_timeout_seconds)
        case "null":
            return NullSink()
        case _:
            # settings.py validates this at construction, so reaching here means
            # a caller built Settings by hand with a mutated value.
            return NullSink()


_default_client: TelemetryClient | None = None
_default_lock = threading.Lock()


def get_telemetry_client() -> TelemetryClient:
    """Return the process-wide telemetry client.

    Lazily built (rather than a module-level instance) so importing this module
    never touches the filesystem, which keeps unit tests free of stray
    `data/telemetry/` directories.
    """
    global _default_client
    if _default_client is None:
        with _default_lock:
            if _default_client is None:
                _default_client = TelemetryClient()
    return _default_client


def reset_telemetry_client() -> None:
    """Drop the cached client so the next call re-reads settings.

    Needed by tests that change `TELEMETRY_*` in the environment, and by
    `backend/telemetry/README.md`'s documented reload path.
    """
    global _default_client
    with _default_lock:
        _default_client = None


# Re-exported so call sites can `from backend.telemetry import TelemetryClient,
# EventStatus` without reaching into the events module for a two-name import.
__all__ = [
    "EventStatus",
    "HttpSink",
    "JsonlFileSink",
    "NullSink",
    "TelemetryClient",
    "TelemetryEvent",
    "TelemetrySink",
    "get_telemetry_client",
    "reset_telemetry_client",
]
