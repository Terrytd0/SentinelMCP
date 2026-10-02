# Telemetry

The event contract this project emits, and why six of its fields are frozen.

Read this before adding a new emission point.

## Why a contract at all

Sprint 11 of the roadmap is **Aegis**: a control plane that has to consume events
from seven separate repositories. For that to work without seven adapters, the
core event shape has to be identical everywhere and must not drift.

That is only achievable if the shape is *asserted*, so it is:
`tests/unit/telemetry/test_telemetry_contract.py` fails if a core field is
renamed, removed, or made optional. That test is the only thing standing between
a well-meaning refactor and seven broken adapters in a future sprint.

## The event

```python
class TelemetryEvent(BaseModel):
    model_config = {"extra": "forbid"}

    # --- frozen cross-fleet core. Do not rename, reorder, or make optional. ---
    service: str  # which service emitted it; the Aegis tenant key
    timestamp: datetime  # UTC, defaults to now
    latency_ms: float  # wall time of the measured operation
    tokens_used: int  # 0 for anything that is not an LLM call
    cost: float  # USD; 0.0 for anything that is not an LLM call
    status: EventStatus  # SUCCESS | ERROR | TIMEOUT | CANCELLED

    # --- additive. Safe to extend. ---
    operation: str = "unknown"
    correlation_id: str | None = None
    error_type: str | None = None
    metadata: dict = {}
```

`EventStatus` separates `TIMEOUT` from `ERROR` on purpose: a timeout is a
capacity problem — raise the budget, add capacity — while an error is a defect.
Collapsing them means the capacity signal is lost in the error signal.

`extra: forbid` means an unknown field is a hard failure, not a silently dropped
value. A typo in a metadata key is caught at the emit site rather than
discovered in Aegis three sprints later.

## Three rules for the fields you are adding

**`error_type` is the exception *class name*, never the message.** Exception
messages in this codebase carry file paths, snippets, and occasionally
configuration. `type(exc).__name__` is safe to ship; `str(exc)` is not.

**`metadata` is small, flat, and low-cardinality.** No source code, no
unbounded lists, no per-item dictionaries that change shape with the size of the
input. A `metadata` value that is a list of N user-facing strings is a
denial-of-service vector on the ingest side, in a later sprint, written by
someone who did not remember this paragraph.

**Identifiers, never content.** `finding_id`, `scan_id`, `correlation_id` —
those go in metadata. Snippets and patches do not go anywhere.

## Operations emitted

| operation | emitted by | notes |
|---|---|---|
| `grpc.scan` | both `ScannerBackend` implementations | the in-process one tags `metadata.transport = "in_process"` so the two are comparable and neither pretends to be the other |
| `scan.run` | `ScanningService` | new vs. refreshed finding counts |
| `mcp.tool.<tool>` | `SentinelTools` | one per tool call, on success and on error |
| `remediation.loop` | `RemediationService` | carries `tokens_used` and `cost` from the loop |
| `remediation.outcome` | `RemediationService` | the terminal verdict, `SUCCESS` even for a refusal |

That last one is deliberate: a policy refusal is a *successful* refusal. Marking
it `ERROR` would make the refusal rate look like a failure rate.

## Sinks

`SENTINEL_TELEMETRY_SINK` — `file` (default), `http`, or `null`. Validated at
construction; an unknown value is a startup error rather than a silent discard.

- `file` — JSONL, one object per line, appended under a lock, parent directory
  created eagerly. `data/telemetry/events.jsonl`.
- `http` — POSTs `event.model_dump(mode="json")` with a 2s timeout. If
  `SENTINEL_TELEMETRY_ENDPOINT` is empty this becomes a `NullSink` with a
  warning, because an HTTP sink with no URL should not look configured.
- `null` — discards. What the test suite uses.

## Telemetry must never break the operation it measures

This is the rule the module is built around:

- **A sink that throws is caught and counted.** After
  `_FAILURE_BUDGET = 5` consecutive failures the sink is disabled with one
  warning. A telemetry backend having a bad day must not become an outage cause.
- **`measure()` never suppresses the original exception.** It records the status,
  re-raises, and lets the caller handle it. A context manager that swallowed
  exceptions would be a much worse bug than a missing metric.
- **Rounding is deliberate** — `latency_ms` to 3 decimals, `cost` to 6. Keeps
  the JSONL stable so it diffs cleanly and does not accumulate float noise.

```python
with telemetry.measure("remediation.loop", correlation_id=cid) as m:
    m.tokens_used = result.tokens_used  # read at exit, not at emit time
    m.cost = result.cost_usd
    result = await run_sync(loop.run, ...)
```

`measure()` yields a mutable `_Measurement`; `tokens_used`, `cost`, and
`metadata` are read **at exit**, so a block can fill them in as it learns
something.

## Reloading the sink

`get_telemetry_client()` is a lazily built, double-checked singleton, so merely
importing the module never touches the filesystem or the network.

To change the sink at runtime, both cached singletons must be reset — settings
first, then telemetry:

```python
from backend.config.settings import reload_settings
from backend.telemetry import reset_telemetry_client

import os

os.environ["SENTINEL_TELEMETRY_SINK"] = "null"
reload_settings()
reset_telemetry_client()
# the next get_telemetry_client() rebuilds from the reloaded settings
```

The order matters and is not obvious: `reset_telemetry_client()` alone drops the
client but `get_settings()` is still cached, so the sink is rebuilt from the old
settings and the change appears to do nothing. `tests/conftest.py` does both,
before and after every test, in an autouse fixture.

## What this module is not

It is not a metrics backend, not OpenTelemetry, and not a tracing library. It is
the smallest thing that can emit a stable cross-fleet event shape from a
synchronous codebase that runs blocking scanners and `asyncio.run` bridges,
without ever being able to fail the operation it measures.
