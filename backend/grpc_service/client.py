"""gRPC client for the scanning service, plus the in-process fake.

`ScannerClient` is the async gRPC path. `InProcessScannerClient` implements the
same two methods by calling a `ScannerRegistry` directly, skipping the wire
entirely.

Both exist because the same callers need the service and need it in
different shapes:

    the FastAPI API        -> real gRPC client, so a scan really crosses the
                              boundary (it is a separate process in compose,
                              because scanning is CPU-bound and subprocess-heavy)
    the MCP server         -> real gRPC client, same reason
    the test suite         -> in-process, so 200+ tests need no port, no thread,
                              and no teardown, and run in under a second
    a bare `uvicorn`       -> in-process fallback, so a single command is a
                              working dev setup

`SENTINEL_SCANNER_TRANSPORT` chooses between them; see
`backend/mcp_server/server.py::build_scanner_backend` for the exact rules and
for why "auto" probes with a 2s deadline rather than the 30s scan timeout.

The interface is the point. `backend/services/scanning.py` depends on the
protocol, not on either implementation, which is what makes "run the whole
pipeline without Docker" a property of the design rather than a monkeypatch
in a test file. See `docs/adr/003-grpc-scanning-boundary.md`.
"""

from __future__ import annotations

import abc
from typing import Any

import grpc
from grpc import aio

from backend.core.logging import get_logger
from backend.database.enums import ScannerKind, Severity
from backend.telemetry import get_telemetry_client
from backend.telemetry.events import EventStatus

from .conversion import _PB_SCANNER, _min_severity_to_pb, pb_to_scan_result, scanner_kind_to_pb
from .generated import scanner_pb2, scanner_pb2_grpc

logger = get_logger(__name__)


# Surfaced verbatim by the client so the API layer can pick an HTTP status.
# Mapping gRPC codes to HTTP codes is the API's job, not this module's.
class ScannerServiceError(RuntimeError):
    """The scanning service could not be reached or refused the request."""

    def __init__(self, message: str, code: grpc.StatusCode | None = None) -> None:
        super().__init__(message)
        self.code = code


class ScannerBackend(abc.ABC):
    """The two operations anything scanning-related needs from the service."""

    @abc.abstractmethod
    async def scan(
        self,
        target: str,
        *,
        scanners: list[ScannerKind] | None = None,
        min_severity: Severity | None = None,
        correlation_id: str = "",
    ) -> Any:
        """Run a scan. Returns a `ScanResult`."""

    @abc.abstractmethod
    async def health(self) -> dict[str, Any]:
        """Return `{"healthy": bool, "version": str, "available_scanners": [...]}`.`"""


class GrpcScannerClient(ScannerBackend):
    """Talks to a real `ScannerService` over gRPC.

    The channel is created once and reused: a new channel per call would pay a
    TCP handshake and TLS negotiation on every scan, and would exhaust gRPC's
    connection pool under any concurrency worth having.
    """

    def __init__(self, target: str, timeout_seconds: float = 30.0) -> None:
        self._target = target
        self._timeout = timeout_seconds
        self._channel: aio.Channel | None = None
        self._stub: Any = None
        self._telemetry = get_telemetry_client()

    async def _get_stub(self) -> Any:
        if self._stub is None:
            self._channel = aio.insecure_channel(self._target)
            self._stub = scanner_pb2_grpc.ScannerServiceStub(self._channel)
            logger.debug("opened gRPC channel target=%s", self._target)
        return self._stub

    async def scan(
        self,
        target: str,
        *,
        scanners: list[ScannerKind] | None = None,
        min_severity: Severity | None = None,
        correlation_id: str = "",
    ) -> Any:
        """Call `ScannerService.Scan`, translating gRPC failures to one exception.

        `UNAVAILABLE` and `FAILED_PRECONDITION` both become
        `ScannerServiceError` with the code attached, because at the API layer
        they mean the same thing -- the scan did not happen, and the reason is
        in the message.
        """
        stub = await self._get_stub()
        request = scanner_pb2.ScanRequest(
            target=target,
            scanners=[scanner_kind_to_pb(k) for k in (scanners or [])],
            min_severity=_min_severity_to_pb(min_severity),
            correlation_id=correlation_id,
        )

        try:
            response = await stub.Scan(request, timeout=self._timeout)
        except grpc.RpcError as exc:
            code = exc.code() if callable(getattr(exc, "code", None)) else None
            details = exc.details() if callable(getattr(exc, "details", None)) else str(exc)
            self._telemetry.emit(
                "grpc.scan",
                status=EventStatus.ERROR,
                error_type=type(exc).__name__,
                correlation_id=correlation_id,
                metadata={"target": target, "grpc_code": getattr(code, "name", None)},
            )
            raise ScannerServiceError(f"scanning service error: {details}", code=code) from exc

        return pb_to_scan_result(response)

    async def health(self) -> dict[str, Any]:
        """Call `ScannerService.Health`, degrading to unhealthy on failure.

        A health probe that raises is useless to a readiness check, so transport
        failure is reported as `healthy: False` with the reason, not as an
        exception the caller has to remember to catch.
        """
        stub = await self._get_stub()
        try:
            response = await stub.Health(scanner_pb2.HealthRequest(), timeout=self._timeout)
        except grpc.RpcError as exc:
            code = exc.code() if callable(getattr(exc, "code", None)) else None
            return {
                "healthy": False,
                "version": "unknown",
                "available_scanners": [],
                "fixture_targets": [],
                "error": str(exc),
                "grpc_code": getattr(code, "name", None),
            }

        return {
            "healthy": response.healthy,
            "version": response.version,
            "available_scanners": [
                _PB_SCANNER.get(s, ScannerKind.UNSPECIFIED).value
                for s in response.available_scanners
            ],
            "fixture_targets": list(response.fixture_targets),
        }

    async def close(self) -> None:
        """Close the channel. Safe to call more than once."""
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
            self._stub = None


class InProcessScannerClient(ScannerBackend):
    """Calls a `ScannerRegistry` directly, with no wire in between.

    Emits the same `grpc.scan` telemetry operation as the real client, with
    the `transport: "in_process"` marker, so an in-process run and a networked
    run produce comparable event streams. Deliberately does *not* pretend to
    be gRPC -- if it claimed the same operation name with no marker, a bug that
    only appears over the wire would hide inside normal-looking metrics.
    """

    def __init__(self, registry: Any) -> None:
        self._registry = registry
        self._telemetry = get_telemetry_client()

    async def scan(
        self,
        target: str,
        *,
        scanners: list[ScannerKind] | None = None,
        min_severity: Severity | None = None,
        correlation_id: str = "",
    ) -> Any:
        from backend.core.asyncio_utils import run_sync
        from backend.scanners.base import ScannerUnavailableError, ScanResult

        kinds = scanners or self._registry.available_kinds()
        if not kinds:
            raise ScannerServiceError("no scanners are available")

        findings: list[Any] = []
        errors: list[str] = []
        duration_ms = 0.0

        with self._telemetry.measure(
            "grpc.scan", correlation_id=correlation_id, metadata={"transport": "in_process"}
        ) as measurement:
            for kind in kinds:
                try:
                    scanner = self._registry.get(kind)
                    result: ScanResult = await run_sync(scanner.scan, target)
                except ScannerUnavailableError as exc:
                    raise ScannerServiceError(f"scanning service error: {exc}") from exc

                if min_severity is not None and min_severity is not Severity.UNSPECIFIED:
                    result = result.filtered_by_severity(min_severity)
                findings.extend(result.findings)
                duration_ms += result.duration_ms
                if result.error:
                    errors.append(f"{kind.value}: {result.error}")

            combined = ScanResult(
                scanner_kind=kinds[0],
                target=target,
                findings=findings,
                duration_ms=duration_ms,
                error="; ".join(errors) or None,
            )
            measurement.metadata = {
                "transport": "in_process",
                "target": target,
                "findings": len(findings),
                "scanners": len(kinds),
                "scanner_error": bool(errors),
            }
            return combined

    async def health(self) -> dict[str, Any]:
        """The same shape `GrpcScannerClient.health` returns, computed locally.

        `fixture_targets` is included so the two implementations are
        interchangeable to every caller. When it is not, `GET /scans/targets`
        answers differently depending on which transport the process happens to
        be on -- which is the bug this field was added to the proto to fix.
        """
        from backend.grpc_service.server import _fixture_targets

        available = self._registry.available_kinds()
        return {
            "healthy": bool(available),
            "version": "in-process",
            "available_scanners": [k.value for k in available],
            "fixture_targets": _fixture_targets(self._registry),
        }

    async def close(self) -> None:
        """No channel to close. Present so callers need no isinstance check."""
        return None
