"""The gRPC scanning service.

Implements `sentinel.v1.ScannerService` over a `ScannerRegistry`. It knows
about gRPC and the scanner registry, and nothing else -- no database, no MCP,
no agent loop. That restraint is deliberate: the service is the component most
likely to be scaled independently (scans are CPU-bound, everything else is
I/O-bound), so it must not acquire dependencies that would tie it to the rest
of the system.

Error mapping is the part worth reading carefully. Three distinct failures,
three distinct treatments:

    scanner not registered   -> gRPC FAILED_PRECONDITION
    scanner cannot run       -> gRPC UNAVAILABLE
    scanner ran and failed   -> ScanResponse.error set, RPC succeeds

The third one is the subtle one. Returning an error *field* rather than an
RPC error preserves any findings the scanner produced before failing, and
stops a broken scan from being reported to a dashboard as a clean result.
"""

from __future__ import annotations

import uuid
from typing import Any

import grpc
from grpc import aio

from backend.core.logging import get_logger
from backend.database.enums import ScannerKind, Severity
from backend.scanners.base import ScannerError, ScannerUnavailableError, ScanResult
from backend.scanners.registry import ScannerRegistry
from backend.telemetry import get_telemetry_client

from .conversion import scan_result_to_pb, scanner_kind_to_pb
from .generated import scanner_pb2, scanner_pb2_grpc

logger = get_logger(__name__)

# proto enum int -> our enum, for interpreting ScanRequest.scanners.
_PB_SCANNER_KINDS: dict[int, ScannerKind] = {
    scanner_pb2.SCANNER_KIND_UNSPECIFIED: ScannerKind.UNSPECIFIED,
    scanner_pb2.SCANNER_KIND_FIXTURE: ScannerKind.FIXTURE,
    scanner_pb2.SCANNER_KIND_SEMGREP: ScannerKind.SEMGREP,
    scanner_pb2.SCANNER_KIND_ZAP: ScannerKind.ZAP,
    scanner_pb2.SCANNER_KIND_DEPENDENCY: ScannerKind.DEPENDENCY,
}
_PB_SEVERITIES: dict[int, Severity] = {
    scanner_pb2.SEVERITY_UNSPECIFIED: Severity.UNSPECIFIED,
    scanner_pb2.SEVERITY_CRITICAL: Severity.CRITICAL,
    scanner_pb2.SEVERITY_HIGH: Severity.HIGH,
    scanner_pb2.SEVERITY_MEDIUM: Severity.MEDIUM,
    scanner_pb2.SEVERITY_LOW: Severity.LOW,
    scanner_pb2.SEVERITY_INFO: Severity.INFO,
}


def _fixture_targets(registry: ScannerRegistry) -> list[str]:
    """The fixture scanner's target list, or empty if it is not available.

    A registry holding a fixture scanner that cannot run (missing fixtures
    directory) reports no targets, which is the honest answer -- a target the
    scanner would refuse is worse than no target at all.
    """
    from backend.scanners.fixture import FixtureScanner

    for scanner in registry.all():
        if isinstance(scanner, FixtureScanner) and scanner.available:
            return scanner.available_targets()
    return []


class ScannerServicer(scanner_pb2_grpc.ScannerServiceServicer):
    """`ScannerService` implementation over a scanner registry."""

    def __init__(self, registry: ScannerRegistry, service_name: str = "SentinelMCP") -> None:
        self._registry = registry
        self._service_name = service_name
        self._telemetry = get_telemetry_client()

    async def Scan(  # noqa: N802 - gRPC method names are PascalCase by spec.
        self, request: scanner_pb2.ScanRequest, context: aio.ServicerContext
    ) -> scanner_pb2.ScanResponse:
        """Run the requested scanners over the requested target.

        `request.scanners` is empty when the caller wants the service default.
        A request naming several scanners runs them all and concatenates the
        findings -- the response's `scanner_kind` is then the first one, which
        is why callers that care should send one scanner per request.
        """
        scan_id = uuid.uuid4().hex
        correlation_id = request.correlation_id or scan_id

        with self._telemetry.measure("grpc.scan", correlation_id=correlation_id) as measurement:
            try:
                response = await self._scan(request, scan_id, correlation_id)
            except ScannerUnavailableError as exc:
                # "We could not look." Surfaces as a status code so no client
                # can mistake it for a clean scan.
                measurement.metadata = {
                    "scan_id": scan_id,
                    "target": request.target,
                    "outcome": "unavailable",
                }
                await context.abort(grpc.StatusCode.UNAVAILABLE, str(exc))

            except ScannerError as exc:
                measurement.metadata = {
                    "scan_id": scan_id,
                    "target": request.target,
                    "outcome": "scanner_error",
                }
                await context.abort(grpc.StatusCode.FAILED_PRECONDITION, str(exc))

            except ValueError as exc:
                measurement.metadata = {
                    "scan_id": scan_id,
                    "target": request.target,
                    "outcome": "bad_request",
                }
                await context.abort(grpc.StatusCode.INVALID_ARGUMENT, str(exc))

            measurement.metadata = {
                "scan_id": scan_id,
                "target": request.target,
                "findings": len(response.findings),
                "critical": response.counts.critical,
                "high": response.counts.high,
                "scanners": len(request.scanners) or 1,
                "scanner_error": bool(response.error),
            }
            return response

    async def _scan(
        self, request: scanner_pb2.ScanRequest, scan_id: str, correlation_id: str
    ) -> scanner_pb2.ScanResponse:
        """Fan the request out across the requested scanners."""
        target = request.target.strip()
        if not target:
            raise ValueError("ScanRequest.target must not be empty")

        kinds = self._resolve_kinds(request)
        minimum = _PB_SEVERITIES.get(request.min_severity, Severity.UNSPECIFIED)
        if minimum == Severity.UNSPECIFIED:
            minimum = Severity.INFO  # no filter requested: keep everything

        logger.info(
            "scan requested scan_id=%s target=%s scanners=%d min_severity=%s",
            scan_id,
            target,
            len(kinds),
            minimum.value,
        )

        first: scanner_pb2.ScanResponse | None = None
        findings: list[Any] = []
        errors: list[str] = []

        for kind in kinds:
            scanner = self._registry.get(kind)  # raises -> aborts the RPC
            result: ScanResult = await self._run_scanner(scanner, target, minimum)
            response = scan_result_to_pb(result, scan_id=scan_id, correlation_id=correlation_id)
            findings.extend(response.findings)
            if result.error:
                errors.append(f"{kind.value}: {result.error}")
            first = first or response

        assert first is not None  # kinds is never empty: _resolve_kinds guarantees it
        combined = scanner_pb2.ScanResponse(
            scan_id=scan_id,
            scanner_kind=first.scanner_kind,
            target=target,
            findings=findings,
            counts=scanner_pb2.SeverityCounts(
                critical=sum(1 for f in findings if f.severity == scanner_pb2.SEVERITY_CRITICAL),
                high=sum(1 for f in findings if f.severity == scanner_pb2.SEVERITY_HIGH),
                medium=sum(1 for f in findings if f.severity == scanner_pb2.SEVERITY_MEDIUM),
                low=sum(1 for f in findings if f.severity == scanner_pb2.SEVERITY_LOW),
                info=sum(1 for f in findings if f.severity == scanner_pb2.SEVERITY_INFO),
                total=len(findings),
            ),
            started_at=first.started_at,
            duration_ms=int(first.duration_ms),
            correlation_id=correlation_id,
            error="; ".join(errors),
        )
        return combined

    async def _run_scanner(self, scanner: Any, target: str, minimum: Severity) -> ScanResult:
        """Run one scanner off the event loop.

        Scanners are synchronous by contract (they shell out to subprocesses),
        so running one inline would block the gRPC server's event loop for the
        whole scan and stall every other in-flight request.
        """
        from backend.core.asyncio_utils import run_sync

        result: ScanResult = await run_sync(scanner.scan, target)
        if minimum != Severity.INFO:
            result = result.filtered_by_severity(minimum)
        return result

    def _resolve_kinds(self, request: scanner_pb2.ScanRequest) -> list[ScannerKind]:
        """Decide which scanners this request means.

        Falls back to the service's available set when the request is
        unspecified -- but only to *available* ones, so a default request can
        never land on a scanner whose binary is missing.
        """
        if not request.scanners:
            available = self._registry.available_kinds()
            if not available:
                raise ScannerUnavailableError(
                    "no scanners are available on this service; check its health endpoint"
                )
            return available

        kinds: list[ScannerKind] = []
        for raw in request.scanners:
            kind = _PB_SCANNER_KINDS.get(raw)
            if kind is None or kind == ScannerKind.UNSPECIFIED:
                raise ValueError(f"unrecognized scanner value {raw} in ScanRequest.scanners")
            kinds.append(kind)
        return kinds

    async def Health(  # noqa: N802
        self, request: scanner_pb2.HealthRequest, context: aio.ServicerContext
    ) -> scanner_pb2.HealthResponse:
        """Report liveness and -- the useful part -- real capability.

        `available_scanners` is the field that lets a client avoid requesting a
        scan it knows will fail. A health check that only says "the process is
        up" would tell a client nothing about whether it can actually do the
        job it is calling for.

        `fixture_targets` rides along for the same reason: `GET /scans/targets`
        used to reach into the client's private `_registry` attribute, so over
        a real gRPC connection it returned nothing. See the field's comment in
        the proto.
        """
        available = self._registry.available_kinds()
        return scanner_pb2.HealthResponse(
            healthy=bool(available),
            version=self._service_name,
            available_scanners=[scanner_kind_to_pb(k) for k in available],
            fixture_targets=list(_fixture_targets(self._registry)),
        )


class ScannerServer:
    """Owns the gRPC server lifecycle."""

    def __init__(
        self,
        registry: ScannerRegistry,
        host: str = "0.0.0.0",
        port: int = 50051,
        service_name: str = "SentinelMCP",
        max_concurrent_rpcs: int | None = None,
    ) -> None:
        self._registry = registry
        self._host = host
        self._port = port
        self._servicer = ScannerServicer(registry, service_name=service_name)
        # Scans run on asyncio's own thread pool (see `_run_scanner`), so
        # there is no separate gRPC thread pool to size. `maximum_concurrent_rpcs`
        # is the right lever instead: it caps how many scans are in flight, which
        # is what actually needs bounding -- each one holds a subprocess and a
        # database connection. Unset means unbounded, which is correct for a
        # single-user local run and something a deployment should set.
        self._server = aio.server(
            options=[
                ("grpc.max_send_message_length", 16 * 1024 * 1024),
                ("grpc.max_receive_message_length", 16 * 1024 * 1024),
            ],
            maximum_concurrent_rpcs=max_concurrent_rpcs,
        )
        scanner_pb2_grpc.add_ScannerServiceServicer_to_server(self._servicer, self._server)
        self._bound_port: int | None = None

    @property
    def port(self) -> int:
        """The bound port.

        Differs from the requested port when port 0 was requested, which is how
        `tests/integration/test_grpc_scanning.py` gets a free port without racing
        another test for a fixed one.
        """
        return self._bound_port if self._bound_port is not None else self._port

    async def start(self) -> int:
        """Bind and start serving. Returns the bound port."""
        self._bound_port = self._server.add_insecure_port(f"{self._host}:{self._port}")
        if self._bound_port == 0:
            raise RuntimeError(f"could not bind gRPC scanning service to {self._host}:{self._port}")
        await self._server.start()
        logger.info("gRPC scanning service listening on %s:%s", self._host, self._bound_port)
        return self._bound_port

    async def stop(self, grace: float = 5.0) -> None:
        """Stop serving, letting in-flight scans finish within `grace` seconds."""
        if self._server is not None:
            await self._server.stop(grace)
            logger.info("gRPC scanning service stopped")
