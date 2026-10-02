"""The telemetry event contract shared with the Aegis fleet (Sprint 11).

This module is deliberately the *first* thing in the project rather than an
instrumentation pass bolted on at the end. Aegis is an LLMOps control plane
that has to consume events from seven separate repositories; if each project
invents its own shape, Aegis ends up writing seven bespoke adapters. So the
six core fields below are frozen and identical across every project in the
fleet, and the extras are additive.

Core contract (do not rename these six -- every project emits them):

    {
      "service":    "SentinelMCP",   # fleet tenant name
      "timestamp":  "2026-09-27T10:11:12.131415+00:00",
      "latency_ms": 185,             # wall time of the measured operation
      "tokens_used": 1248,           # LLM tokens, 0 for non-LLM operations
      "cost":       0.0042,          # USD, 0.0 for non-LLM operations
      "status":     "success"        # success | error
    }

Additive fields (`operation`, `correlation_id`, `error_type`, `metadata`) are
allowed to grow, because Aegis can ignore what it does not understand. A
*removed or renamed* core field is a breaking change that would force Aegis to
version per-project ingestion.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from backend.core.clock import utc_now


class EventStatus(StrEnum):
    """Terminal state of a measured operation.

    `success` and `error` are the only two values an SLA or availability
    metric can be built on. `timeout` is separated from `error` because an
    operation that ran out of budget is a capacity problem, not a defect, and
    conflating them sends the on-call to the wrong dashboard.
    """

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class TelemetryEvent(BaseModel):
    """One standardized measurement of one operation.

    `tokens_used` and `cost` default to 0 rather than being optional: a
    Postgres-only operation genuinely costs zero tokens, and making them
    `None` would force every downstream aggregator to handle a null that
    means the same thing as 0.
    """

    # --- Fleet contract: identical across every project. Do not rename. ---
    service: str
    timestamp: datetime = Field(default_factory=utc_now)
    latency_ms: float = 0.0
    tokens_used: int = 0
    cost: float = 0.0
    status: EventStatus = EventStatus.SUCCESS

    # --- Additive context. ---
    operation: str = "unknown"
    """What was measured, e.g. "grpc.scan", "mcp.tool.list_findings", "remediation.loop"."""

    correlation_id: str | None = None
    """Ties an event back to the request, scan, or agent run that produced it."""

    error_type: str | None = None
    """Exception class name when `status != success`. Never the message -- it
    may embed a source snippet or a credential."""

    metadata: dict[str, Any] = Field(default_factory=dict)
    """Small, flat, low-cardinality extras (counts, severities, round numbers).
    Never put source code, prompts, or unbounded lists in here: this payload
    ships to a fleet-wide aggregator and is the most likely thing to blow up
    its index size."""

    model_config = {"extra": "forbid"}
