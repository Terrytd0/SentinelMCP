"""The telemetry client and its cross-project event contract.

The capstone roadmap asks for a standardized event shape from day one so that
Sprint 11's Aegis can consume events from seven repositories without writing
seven adapters. That only works if the six core fields cannot be renamed -- so
the contract itself is asserted here, in the one repository where a rename would
be caught before it propagated to the other six.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.telemetry.client import (
    JsonlFileSink,
    NullSink,
    TelemetryClient,
)
from backend.telemetry.events import EventStatus, TelemetryEvent

CORE_CONTRACT_FIELDS = {"service", "timestamp", "latency_ms", "tokens_used", "cost", "status"}


class _ExplodingSink:
    def write(self, event: TelemetryEvent) -> None:
        raise RuntimeError("the collector is down")


# --- The contract -------------------------------------------------------


def test_the_six_core_fields_are_present_and_correctly_named() -> None:
    event = TelemetryEvent(service="SentinelMCP", operation="grpc.scan")
    payload = event.model_dump(mode="json")
    assert CORE_CONTRACT_FIELDS <= set(payload)


def test_every_core_field_is_always_present_in_the_serialised_event() -> None:
    """The guarantee that actually matters.

    Core fields have defaults -- a non-LLM operation genuinely reports zero
    tokens -- so they cannot be *required constructor arguments*. What must
    hold is that they are always present in the payload, because a downstream
    aggregator reading `event["cost"]` must never hit a KeyError.
    """
    empty = TelemetryEvent(service="SentinelMCP").model_dump(mode="json")
    assert CORE_CONTRACT_FIELDS <= set(empty)

    populated = TelemetryEvent(
        service="SentinelMCP", latency_ms=1.0, tokens_used=1, cost=0.1
    ).model_dump(mode="json")
    assert CORE_CONTRACT_FIELDS <= set(populated)

    # And the defaults are the documented ones, not `None`.
    assert empty["tokens_used"] == 0
    assert empty["cost"] == 0.0
    assert empty["status"] == "success"


def test_an_unknown_field_is_rejected() -> None:
    """The event is a wire format. Silently accepting extras would let one
    project invent a field name that another has to guess at."""
    with pytest.raises(ValueError):
        TelemetryEvent(service="SentinelMCP", opreation="typo")  # type: ignore[call-arg]


def test_the_example_from_the_brief_round_trips() -> None:
    """The exact shape from `SUGGESTION FOR EACH PROJECT.txt`."""
    event = TelemetryEvent(
        service="SupportOps",
        latency_ms=185,
        tokens_used=1248,
        cost=0.0042,
        status=EventStatus.SUCCESS,
    )
    payload = event.model_dump(mode="json")
    assert payload["service"] == "SupportOps"
    assert payload["latency_ms"] == 185
    assert payload["tokens_used"] == 1248
    assert payload["cost"] == 0.0042
    assert payload["status"] == "success"


def test_non_llm_operations_report_zero_not_null() -> None:
    """A Postgres-only operation genuinely costs zero tokens. `None` would
    force every aggregator to handle a null that means the same as 0."""
    event = TelemetryEvent(service="SentinelMCP")
    assert event.tokens_used == 0
    assert event.cost == 0.0


def test_the_status_enum_covers_the_outcomes_an_sla_needs() -> None:
    """`timeout` is separate from `error` on purpose: a run that exhausted its
    budget is a capacity problem, not a defect."""
    values = {s.value for s in EventStatus}
    assert {"success", "error", "timeout"} <= values


# --- Sinks --------------------------------------------------------------


def test_the_jsonl_sink_writes_one_object_per_line(tmp_path: Path) -> None:
    sink = JsonlFileSink(tmp_path / "events.jsonl")
    sink.write(TelemetryEvent(service="SentinelMCP", operation="a"))
    sink.write(TelemetryEvent(service="SentinelMCP", operation="b"))

    lines = sink.path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert [json.loads(line)["operation"] for line in lines] == ["a", "b"]


def test_the_jsonl_sink_creates_its_parent_directory(tmp_path: Path) -> None:
    """Fail at construction rather than silently on the first event."""
    sink = JsonlFileSink(tmp_path / "deep" / "nested" / "events.jsonl")
    assert sink.path.parent.is_dir()


def test_the_jsonl_sink_appends_rather_than_truncates(tmp_path: Path) -> None:
    """A restarted process must not erase the fleet's event history."""
    path = tmp_path / "events.jsonl"
    JsonlFileSink(path).write(TelemetryEvent(service="SentinelMCP", operation="first"))
    JsonlFileSink(path).write(TelemetryEvent(service="SentinelMCP", operation="second"))
    assert len(path.read_text(encoding="utf-8").strip().splitlines()) == 2


def test_the_null_sink_discards_silently() -> None:
    NullSink().write(TelemetryEvent(service="SentinelMCP"))


# --- Failure isolation --------------------------------------------------


def test_a_broken_sink_never_propagates() -> None:
    """The core promise: telemetry can never fail the operation it measures.

    A slow log file or a dead collector must not turn a successful scan into an
    error, or the monitoring system becomes the outage.
    """
    client = TelemetryClient(service="SentinelMCP", sink=_ExplodingSink())
    client.emit("grpc.scan")  # must not raise


def test_measure_still_raises_the_original_error() -> None:
    """Failure isolation applies to the *sink*, not to the operation.

    A block that fails must still fail, with its own traceback -- swallowing it
    would be a different and much worse bug.
    """
    client = TelemetryClient(service="SentinelMCP", sink=_ExplodingSink())

    def _divide_by_zero() -> float:
        return 1 / 0

    with pytest.raises(ZeroDivisionError):
        with client.measure("scan.run"):
            _divide_by_zero()


def test_measure_reports_the_right_status_per_outcome() -> None:
    recorded: list[TelemetryEvent] = []

    class _Sink:
        def write(self, event: TelemetryEvent) -> None:
            recorded.append(event)

    client = TelemetryClient(service="SentinelMCP", sink=_Sink())

    with client.measure("ok"):
        pass
    with pytest.raises(ValueError):
        with client.measure("bad"):
            raise ValueError("nope")
    with pytest.raises(TimeoutError):
        with client.measure("slow"):
            raise TimeoutError("took too long")

    assert [e.status for e in recorded] == [
        EventStatus.SUCCESS,
        EventStatus.ERROR,
        EventStatus.TIMEOUT,
    ]
    assert recorded[1].error_type == "ValueError"
    assert recorded[2].error_type == "TimeoutError"


def test_a_repeatedly_failing_sink_is_disabled() -> None:
    """A permanently dead collector costs one warning, not a retry storm."""
    client = TelemetryClient(service="SentinelMCP", sink=_ExplodingSink())
    for _ in range(20):
        client.emit("grpc.scan")
    assert client._disabled is True  # noqa: SLF001


def test_measure_times_the_block() -> None:
    recorded: list[TelemetryEvent] = []

    class _Sink:
        def write(self, event: TelemetryEvent) -> None:
            recorded.append(event)

    client = TelemetryClient(service="SentinelMCP", sink=_Sink())
    with client.measure("timed") as measurement:
        measurement.tokens_used = 42
        measurement.cost = 0.5
        measurement.metadata = {"findings": 3}

    assert recorded[0].latency_ms >= 0
    assert recorded[0].tokens_used == 42
    assert recorded[0].cost == 0.5
    assert recorded[0].metadata == {"findings": 3}


def test_the_event_carries_a_timestamp_and_correlation_id() -> None:
    recorded: list[TelemetryEvent] = []

    class _Sink:
        def write(self, event: TelemetryEvent) -> None:
            recorded.append(event)

    client = TelemetryClient(service="SentinelMCP", sink=_Sink())
    client.emit("mcp.tool.list_findings", correlation_id="abc123")

    assert recorded[0].correlation_id == "abc123"
    assert recorded[0].timestamp is not None
    assert recorded[0].service == "SentinelMCP"
