"""The gRPC scanning service, over a real socket.

Not mocked. A `ScannerServer` is started on a real ephemeral port and driven by
the real generated stub, because the things this boundary is supposed to
guarantee -- a typed schema, a correct status code, an error that cannot be
mistaken for an empty result -- only exist once the wire is involved. A mocked
gRPC test would assert that the mock was called.

The only concession to speed is `port=0`, which binds an ephemeral port, so the
suite needs no fixed port and cannot collide with a real service or another run.
"""

from __future__ import annotations

from typing import Any

import grpc
import pytest
from grpc import aio

from backend.database.enums import ScannerKind, Severity
from backend.grpc_service.client import GrpcScannerClient, ScannerServiceError
from backend.grpc_service.conversion import (
    from_timestamp,
    pb_to_raw_finding,
    raw_finding_to_pb,
    scan_result_to_pb,
    to_timestamp,
)
from backend.grpc_service.generated import scanner_pb2
from backend.grpc_service.server import ScannerServer
from backend.scanners.base import (
    RawFinding,
    Scanner,
    ScannerUnavailableError,
    ScanResult,
)
from backend.scanners.registry import ScannerRegistry

# Marked so `make test-integration` actually selects it. It needs no database
# -- only a real socket -- which used to be the reason it carried no marker, and
# the effect was that 20 tests of the project's headline boundary were silently
# skipped by the command documented as running the integration suite.
pytestmark = pytest.mark.integration


class _UnavailableScanner(Scanner):
    kind = ScannerKind.SEMGREP
    available = False
    unavailable_reason = "semgrep binary not found"

    def scan(self, target: str) -> ScanResult:
        raise ScannerUnavailableError(self.unavailable_reason)


@pytest.fixture
async def running_service(registry: ScannerRegistry) -> Any:
    """A real gRPC server on an ephemeral port, torn down after the test."""
    server = ScannerServer(registry, host="127.0.0.1", port=0)
    await server.start()
    try:
        yield server
    finally:
        await server.stop(grace=0.5)


@pytest.fixture
async def client(running_service: ScannerServer) -> Any:
    grpc_client = GrpcScannerClient(f"127.0.0.1:{running_service.port}", timeout_seconds=10)
    try:
        yield grpc_client
    finally:
        await grpc_client.close()


# --- Health -------------------------------------------------------------


async def test_health_reports_real_capability(client: GrpcScannerClient) -> None:
    """Not "is the process up" -- *which scanners can actually run*.

    A health check that only says the process is alive tells a client nothing
    about whether it can do the job it is about to ask for.
    """
    health = await client.health()
    assert health["healthy"] is True
    assert health["available_scanners"] == ["fixture"]


async def test_health_reports_the_fixture_targets(client: GrpcScannerClient) -> None:
    """Capability a client needs has to be on the wire, not behind a private attr.

    `GET /scans/targets` used to read `scanner_backend._registry`, which only
    exists on the in-process client, so over a real connection it answered
    `[]` -- a discovery endpoint that worked in development and returned
    nothing in the deployment it exists for.
    """
    health = await client.health()
    assert health["fixture_targets"] == ["app/", "services/payments/"]


async def test_health_fixture_targets_survive_the_wire(client: GrpcScannerClient) -> None:
    """And the field is genuinely in the protobuf, not synthesised client-side."""
    from backend.grpc_service.generated import scanner_pb2

    assert set(scanner_pb2.HealthResponse.DESCRIPTOR.fields_by_name) >= {
        "healthy",
        "version",
        "available_scanners",
        "fixture_targets",
    }


async def test_health_of_a_service_with_no_fixture_scanner() -> None:
    """No fixture scanner, no targets -- reported honestly as empty.

    Advertising a target the service would refuse is worse than advertising
    none, so this must not fall back to a default list.
    """
    registry = ScannerRegistry([_UnavailableScanner()])
    server = ScannerServer(registry, host="127.0.0.1", port=0)
    await server.start()
    try:
        grpc_client = GrpcScannerClient(f"127.0.0.1:{server.port}", timeout_seconds=10)
        health = await grpc_client.health()
        assert health["healthy"] is False
        assert health["available_scanners"] == []
        assert health["fixture_targets"] == []
        await grpc_client.close()
    finally:
        await server.stop(grace=0.5)


# --- Scanning -----------------------------------------------------------


async def test_a_scan_returns_typed_findings_with_a_histogram(client: GrpcScannerClient) -> None:
    result = await client.scan("app/", correlation_id="corr-1")

    assert len(result.findings) == 8
    counts = result.counts_by_severity()
    assert counts[Severity.CRITICAL] == 2
    assert counts[Severity.HIGH] == 3
    assert sum(counts.values()) == 8

    first = result.findings[0]
    assert first.rule_id
    assert first.severity is Severity.CRITICAL
    assert first.file_path
    assert first.cwe_ids == ["CWE-95"]


async def test_severity_filtering_is_applied_server_side(client: GrpcScannerClient) -> None:
    """A client asking for "high and critical only" should not pay to serialize
    five hundred low findings and then throw them away."""
    result = await client.scan("app/", min_severity=Severity.HIGH)
    assert {f.severity.rank for f in result.findings} <= {0, 1}
    assert len(result.findings) == 5


async def test_a_clean_scan_is_not_an_error(client: GrpcScannerClient) -> None:
    """ "This target has no known findings" is a true answer, and must not look
    like a failure."""
    result = await client.scan("does/not/exist/")
    assert result.findings == []
    assert result.error is None


async def test_an_unavailable_scanner_is_refused_not_reported_as_clean(
    client: GrpcScannerClient,
) -> None:
    """ "We could not look" must not be reported as "we found nothing".

    This is the single most important behaviour in the whole scanning layer, and
    it holds whether the scanner was never registered or is registered but
    cannot run -- both must surface as a gRPC error, never as an empty
    `ScanResponse`.
    """
    with pytest.raises(ScannerServiceError) as exc:
        await client.scan("app/", scanners=[ScannerKind.SEMGREP])
    assert exc.value.code in (
        grpc.StatusCode.UNAVAILABLE,  # registered, but cannot run here
        grpc.StatusCode.FAILED_PRECONDITION,  # not registered at all
    )
    assert str(exc.value), "the refusal must say why"


async def test_a_registered_but_unavailable_scanner_reports_unavailable() -> None:
    """The stronger case: the scanner exists, and the service says exactly
    which thing is missing so an operator can fix it."""
    server = ScannerServer(ScannerRegistry([_UnavailableScanner()]), host="127.0.0.1", port=0)
    await server.start()
    try:
        grpc_client = GrpcScannerClient(f"127.0.0.1:{server.port}", timeout_seconds=10)
        with pytest.raises(ScannerServiceError) as exc:
            await grpc_client.scan("app/", scanners=[ScannerKind.SEMGREP])
        assert exc.value.code is grpc.StatusCode.UNAVAILABLE
        assert "semgrep binary not found" in str(exc.value)
        await grpc_client.close()
    finally:
        await server.stop(grace=0.5)


async def test_an_empty_target_is_a_bad_request(client: GrpcScannerClient) -> None:
    with pytest.raises(ScannerServiceError) as exc:
        await client.scan("")
    assert exc.value.code is grpc.StatusCode.INVALID_ARGUMENT


async def test_an_unrecognised_scanner_value_is_rejected() -> None:
    """An enum value outside the known set, straight down the wire."""
    server = ScannerServer(ScannerRegistry([]), host="127.0.0.1", port=0)
    await server.start()
    try:
        async with aio.insecure_channel(f"127.0.0.1:{server.port}") as channel:
            stub = scanner_pb2_grpc_stub(channel)
            with pytest.raises(grpc.RpcError) as exc:
                await stub.Scan(scanner_pb2.ScanRequest(target="app/", scanners=[9999]), timeout=10)
            assert exc.value.code() is grpc.StatusCode.INVALID_ARGUMENT
    finally:
        await server.stop(grace=0.5)


async def test_a_caller_can_explicitly_select_a_scanner(client: GrpcScannerClient) -> None:
    result = await client.scan("app/", scanners=[ScannerKind.FIXTURE])
    assert len(result.findings) == 8


async def test_scanning_two_targets_is_supported(client: GrpcScannerClient) -> None:
    first = await client.scan("app/")
    second = await client.scan("services/payments/")
    assert len(first.findings) == 8
    assert len(second.findings) == 5


async def test_the_correlation_id_is_echoed_back(registry: ScannerRegistry) -> None:
    """Lets an operator tie a scan to the job that requested it."""
    server = ScannerServer(registry, host="127.0.0.1", port=0)
    await server.start()
    try:
        async with aio.insecure_channel(f"127.0.0.1:{server.port}") as channel:
            stub = scanner_pb2_grpc_stub(channel)
            response = await stub.Scan(
                scanner_pb2.ScanRequest(target="app/", correlation_id="trace-me-123"),
                timeout=10,
            )
            assert response.correlation_id == "trace-me-123"
            assert response.scan_id
            assert response.duration_ms >= 0
    finally:
        await server.stop(grace=0.5)


async def test_an_unreachable_service_reports_a_clean_error() -> None:
    """Port 1 is not listening, so this exercises the transport-failure path."""
    grpc_client = GrpcScannerClient("127.0.0.1:1", timeout_seconds=2.0)
    try:
        with pytest.raises(ScannerServiceError):
            await grpc_client.scan("app/")
        health = await grpc_client.health()
        assert health["healthy"] is False
        assert health["error"]
    finally:
        await grpc_client.close()


# --- Protobuf conversion ------------------------------------------------


def test_every_severity_survives_the_wire() -> None:
    for severity in Severity:
        message = raw_finding_to_pb(
            RawFinding(rule_id="r", title="t", description="d", severity=severity),
            scanner_kind=ScannerKind.FIXTURE,
            target="app/",
        )
        assert pb_to_raw_finding(message).severity is severity


def test_every_scanner_kind_survives_the_wire() -> None:
    for kind in ScannerKind:
        message = raw_finding_to_pb(
            RawFinding(rule_id="r", title="t", description="d", severity=Severity.HIGH),
            scanner_kind=kind,
            target="app/",
        )
        assert message.scanner_kind is not None


def test_the_fingerprint_is_computed_on_the_wire() -> None:
    """Identity is computed at the wire boundary, so a scanner reporting the
    same location twice gets the same fingerprint and the re-scan upsert
    deduplicates it.

    The fingerprint deliberately *includes* the scanner kind: two scanners
    reporting the same flaw are two findings, so it is possible to answer
    "what does one scanner catch that the other misses?".
    """
    from backend.core.ids import compute_fingerprint

    finding = RawFinding(
        rule_id="r",
        title="t",
        description="d",
        severity=Severity.HIGH,
        file_path="app/x.py",
    )
    from_fixture = raw_finding_to_pb(finding, scanner_kind=ScannerKind.FIXTURE, target="app/")
    again = raw_finding_to_pb(finding, scanner_kind=ScannerKind.FIXTURE, target="app/")
    from_semgrep = raw_finding_to_pb(finding, scanner_kind=ScannerKind.SEMGREP, target="app/")

    assert from_fixture.fingerprint == again.fingerprint
    assert from_fixture.fingerprint == compute_fingerprint(
        scanner_kind="fixture", rule_id="r", file_path="app/x.py", target="app/", title="t"
    )
    assert from_semgrep.fingerprint != from_fixture.fingerprint


def test_a_partial_scan_preserves_the_error_and_the_findings() -> None:
    """A scanner that found three things and then died has still told you
    something, and the client should be able to use it."""
    result = ScanResult(
        scanner_kind=ScannerKind.FIXTURE,
        target="app/",
        findings=[
            RawFinding(rule_id="a", title="a", description="", severity=Severity.HIGH),
            RawFinding(rule_id="b", title="b", description="", severity=Severity.LOW),
        ],
        error="ran out of memory on file 41",
    )
    message = scan_result_to_pb(result, scan_id="s1")
    assert message.error
    assert len(message.findings) == 2
    assert message.counts.total == 2

    round_tripped = pb_to_raw_finding(message.findings[0])
    assert round_tripped.rule_id == "a"


def test_an_empty_error_field_means_no_error() -> None:
    """proto3 has no null, so "" is the absent marker. Conflating it with a real
    message would make every clean scan look partial."""
    message = scan_result_to_pb(
        ScanResult(scanner_kind=ScannerKind.FIXTURE, target="app/"), scan_id="s1"
    )
    assert message.error == ""


def test_timestamps_round_trip() -> None:
    from backend.core.clock import utc_now

    now = utc_now()
    restored = from_timestamp(to_timestamp(now))
    assert abs((now - restored).total_seconds()) < 0.001


def test_a_missing_timestamp_defaults_to_now() -> None:
    """A zero-valued Timestamp is proto3's "absent"; defaulting rather than
    returning epoch-0 keeps SLA arithmetic sane."""
    from backend.core.clock import utc_now

    restored = from_timestamp(scanner_pb2.Finding().detected_at)
    assert abs((utc_now() - restored).total_seconds()) < 5


def scanner_pb2_grpc_stub(channel: aio.Channel) -> Any:
    """The generated stub, imported lazily to keep the import list tidy."""
    from backend.grpc_service.generated import scanner_pb2_grpc

    return scanner_pb2_grpc.ScannerServiceStub(channel)
