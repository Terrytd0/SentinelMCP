# 003 — A typed gRPC boundary for scanning

**Status:** accepted

## Context

Scanning and serving are different jobs with opposite resource profiles.

- **Serving** is I/O-bound: HTTP in, a few queries, a JSON response. It must stay
  responsive while everything else is busy, because the triage queue is what a
  human looks at during an incident.
- **Scanning** is CPU-bound and subprocess-heavy. Semgrep is a separate binary
  that can run for minutes. ZAP will start a JVM.

Run both in one process and one long Semgrep scan makes `/health` time out. The
health check is what an orchestrator and an operator both rely on, so this is not
a theoretical concern — it is the health check lying about whether the service
can serve.

The obvious answer is two processes and a network boundary. That raises the
question this record answers: **what goes on that boundary, and how do the
callers stay testable?**

There is a second constraint. The test suite has ~300 tests. If "two processes
and a network boundary" means "every test needs a subprocess and a port", nobody
runs the suite, and a suite nobody runs protects nothing. So the boundary has to
be real *and* bypassable.

## Decision

**A protobuf-typed gRPC service, with an ABC (`ScannerBackend`) that both a real
gRPC client and an in-process implementation satisfy.**

### The contract

`proto/sentinel/v1/scanner.proto`, package `sentinel.v1`, two unary RPCs:

- `Scan(ScanRequest) → ScanResponse` — typed `Finding` with fingerprint, rule
  id, severity, confidence, scanner kind, target, file path, line range,
  snippet, CWE ids, CVE ids, and a `detected_at` timestamp.
- `Health(HealthRequest) → HealthResponse` — `healthy`, `version`,
  `available_scanners`, and `fixture_targets`.

Enum values are **explicitly numbered with gaps** (`CRITICAL = 10`, not `1`).
Renumbering a protobuf enum is a wire-breaking change for any client built
against the old schema; the gaps make that mistake visible in review.

No TLS. The channel is `aio.insecure_channel` because the compose network is
the trust boundary here. In a deployment that crosses a host boundary this
becomes a credential and a certificate, and it should be the first thing changed
— noted in `server.py` rather than left for someone to assume.

### Status-code mapping, and the one that matters

| condition | gRPC code | why |
|---|---|---|
| scanner not installed / not registered | `UNAVAILABLE` | retryable, someone else's problem |
| scanner ran and failed | `FAILED_PRECONDITION` | fix the configuration, don't retry |
| bad request (empty target, unknown enum) | `INVALID_ARGUMENT` | the caller's mistake |
| **scanner ran and produced findings *and* an error** | **success, with `ScanResponse.error` set** | the findings are real; dropping them loses security data |

That last row is the design decision worth defending. A partial scan is not a
failure — it is a scan that found things and then hit a problem. The findings are
persisted, the error is carried alongside them, the API raises
`PartialScanError` with the recovered findings attached, and the response says
`partial: true`. The alternative — treating any error as total failure and
discarding — silently loses findings during exactly the incident where they
matter most.

The general principle: **an error must never be representable as an empty
success.** A scanner that is not installed must not look like a scanner that
found nothing. `UNAVAILABLE` exists so that "I could not check" and "there is
nothing here" are different answers.

### Two implementations, one interface

```python
class ScannerBackend(abc.ABC):
    async def scan(
        self, target, *, scanners=None, min_severity=None, correlation_id=""
    ) -> ScanResult: ...
    async def health(self) -> dict[str, Any]: ...
```

`backend/services/scanning.py` depends on the ABC, not on either implementation.
That is what makes "run the whole pipeline with no Docker" a property of the
design rather than a monkeypatch in a test file.

`SENTINEL_SCANNER_TRANSPORT` selects: `grpc` (dial it, fail loudly if absent),
`in_process` (skip the wire), or `auto` (probe, fall back). Details below.

### Two things this boundary got wrong first

Both were found by the end-to-end smoke test, and both are the kind of mistake
this record should prevent repeating.

**The boundary was decorative.** `build_scanner_backend()` returned
`InProcessScannerClient` unconditionally. Five docstrings, the compose file's
`SENTINEL_GRPC_CLIENT_TARGET`, and the proto all described a gRPC boundary that
no production path crossed — and the entire test suite was green, because a
transport decision that silently degrades looks exactly like one that works.
`tests/integration/test_scanner_transport.py` now asserts which implementation
each mode produces against a real server on an ephemeral port, and
`scripts/smoke_e2e.py` runs the pipeline with `SENTINEL_SCANNER_TRANSPORT=grpc`
so a regression fails loudly rather than quietly proving nothing.

**A capability lived behind a private attribute.** `GET /scans/targets` read
`scanner_backend._registry` to list the fixture scanner's targets. That
attribute only exists on the in-process client, so over a real connection the
endpoint returned an empty list — a discovery endpoint that worked in development
and returned nothing in the deployment it exists for. The fix was not to special-
case it: `fixture_targets` is now a field on `HealthResponse`. **A capability a
client needs belongs on the wire, not behind a private attribute of one
implementation.** This is the specific mistake to not repeat.

### Why `auto` is the default, and its cost

`auto` exists so that `uvicorn backend.main:app` is a working dev setup with one
command, while `docker compose up` — which runs a real `scanner` service —
genuinely crosses the wire. It is a compromise, and compromises in the request
path are the kind that rot.

The mitigation is that the fallback is **logged at WARNING with the gRPC status
code**, so "which transport am I actually on?" is answerable from the logs and
from `GET /health` rather than requiring a guess. And the probe uses its own
2-second deadline (`GRPC_PROBE_TIMEOUT_SECONDS`), separate from the 30-second
scan timeout: a stdio MCP host spawns this process and blocks on it, so a
fallback that waited the full scan timeout to notice nothing was listening would
present to the user as a hung server. Refusing to connect is fast; scanning is
allowed to be slow. `tests/integration/test_scanner_transport.py` asserts the
fallback completes in under four seconds for exactly this reason.

A deployment that must not degrade sets `SENTINEL_SCANNER_TRANSPORT=grpc`, and
a dead target becomes a startup failure.

## Consequences

**Good.** A real typed schema rather than JSON over HTTP: the compiler and
`protoc` catch drift, and `conversion.py` degrades an unrecognised enum to
`UNSPECIFIED` rather than raising, so an old client talking to a new server
finds out through a data value instead of a stack trace. The fingerprint is
computed on the **wire** side, so it is computed once and cannot differ between
the server's copy and the client's. Tests get a real socket for the 22 tests
that need one, with `port=0` so there is no fixed port to collide, and no socket
for the ~280 that do not.

**Inconvenient.** Two things to keep honest. Generated code is committed and must
be regenerated with `make proto` when the `.proto` changes — and it is excluded
from ruff and mypy, so nothing will complain if you forget; the test that
imports it will. And a protobuf field added to a deployed service is a
compatibility question; `fixture_targets = 4` is additive and safe, but renumbering
anything is not.

**The awkward one:** `ScannerKind.ZAP` and `ScannerKind.DEPENDENCY` exist in the
enums and the proto with no implementation. They are declared so the schema can
carry them when a DAST scanner is wired up, and an unknown kind is rejected at
the boundary rather than guessed at. A reader could reasonably think the DAST
half of the roadmap's stretch goal is done. It is not — the fixture scanner and
the Semgrep adapter are what exist, and Semgrep is real (fixed argv, `subprocess`
with a timeout, absolute paths resolved to repo-relative so fingerprints are
machine-independent), it just is not in the container image, and
`data/samples/vulnerable_app/` is the real target it is pointed at.

## Alternatives considered

**In-process function calls only, no gRPC.** The simplest design and the one that
was accidentally shipped. It cannot work: scanning has to be separable from
serving, and a boundary you cannot put in a separate process is not a boundary.

**REST/JSON between the services.** Would have worked, and is a defensible
choice. Rejected because the finding schema has ~16 fields with three enums and
nested arrays, all of which drift silently in JSON, and because gRPC's typed
errors are the mechanism that keeps "scanner unavailable" from being
indistinguishable from "no findings". The cost is generated code and a
regeneration step.

**A message queue (Kafka/RabbitMQ) instead of a request/response boundary.**
Rejected for now, on a real technical point rather than taste: a scan is
request/response. The caller needs the findings in this request to answer an
HTTP call, so a queue buys asynchrony nobody asked for and adds a delivery
guarantee to reason about. Sprint 7's FlowMesh is where a queue is the right
answer, because orders genuinely decouple. Note the ordering in the roadmap:
Kafka arrives in Sprint 7, after the gRPC boundary in Sprint 6 — and if the
evidence from this project says anything, it is that a boundary you cannot test
is a boundary you do not have.

**Tight one-to-one gRPC streaming for progress.** Rejected: this is a bounded
batch job, not a stream. A long scan belongs behind a job-and-poll API where the
result is a resource, not behind a streaming RPC that holds a connection open
and gives the caller no way to walk away.
