"""Standardized telemetry, using the cross-fleet contract Aegis will consume.

The event schema lives in `events.py`; the sinks and the emit path live in
`client.py`. Both are imported here so call sites can do
`from backend.telemetry import get_telemetry_client, EventStatus` without
knowing the internal layout.

Read `backend/telemetry/README.md` before adding a new emission point: the
six core fields are frozen across the whole portfolio and a rename is a
breaking change for Sprint 11's Aegis ingest.
"""

from __future__ import annotations

from backend.telemetry.client import (
    HttpSink,
    JsonlFileSink,
    NullSink,
    TelemetryClient,
    TelemetrySink,
    get_telemetry_client,
    reset_telemetry_client,
)
from backend.telemetry.events import EventStatus, TelemetryEvent

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
