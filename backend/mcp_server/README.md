# The MCP server

Four tools, exposed to any MCP client. This is the agent-facing surface; the
FastAPI app is the human-facing one. They sit on the same services, so neither is
a special case and neither can drift from the other's behaviour.

## Run it

```bash
# stdio — what Claude Desktop and most MCP hosts speak
python -m backend.scripts.run_mcp_server

# streamable-http — a network-reachable server, for a deployment that wants one
python -m backend.scripts.run_mcp_server --transport streamable-http --port 8080
```

Claude Desktop config:

```jsonc
{
  "mcpServers": {
    "sentinel": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/SentinelMCP",
               "python", "-m", "backend.scripts.run_mcp_server"],
      "env": {
        "SENTINEL_DATABASE_URL": "postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel",
        "SENTINEL_SCANNER_TRANSPORT": "in_process"
      }
    }
  }
}
```

`in_process` because a stdio server is a *subprocess the client spawned* — there
is no second process to dial. See
[ADR 003](../../docs/adr/003-grpc-scanning-boundary.md).

## The rule: return, don't raise

**A tool never raises for a business outcome.** Every failure comes back as
structured content the model can read and reason about, in a `ToolError`
envelope:

```json
{
  "error": "policy_refused",
  "detail": "file path is outside the permitted source roots ['app/', 'src/']",
  "remedy": "…",
  "finding_id": "…",
  "correlation_id": "…"
}
```

This is the single most important design decision in this package, and it is not
a style preference:

An agent that gets an *exception* for an unremarkable outcome learns to retry.
It tries a different phrasing. It tries a third time. Eventually something
retries in a way that succeeds at doing the wrong thing. An agent that gets a
*result* — `"found": false`, `"outcome": "policy_refused"` — learns to move on.

So `get_cve_details` for a CVE that is not in the feed returns
`{"found": false, ...}`, not an error. `propose_fix` for a finding the policy
refuses returns `{"outcome": "policy_refused", "refusal": "path_outside_source_roots"}`,
not an exception. A refusal is a successful refusal, and the audit trail records
it as one.

Two validation layers, and they are not the same thing:

1. **The SDK** checks arity and types before a tool body runs.
2. **`SentinelTools._validate()`** checks semantics — a malformed UUID, a
   finding in a terminal state — and returns `error: "invalid_arguments"`.

Explicit `null` for an optional list is normalised to `[]`, because MCP clients
send `null` rather than omitting an argument, and a filter that silently becomes
`None` is a filter that silently does nothing.

## The four tools

There are exactly four, and a test asserts the count. Adding a fifth is a
deliberate act, not a drive-by.

### `list_findings`

The triage queue.

| arg | type | notes |
|---|---|---|
| `severity` | `list[Severity]` | only these; empty means all |
| `status` | `list[FindingStatus]` | only these; empty means every non-terminal status |
| `scanner` | `list[ScannerKind]` | filter by source |
| `query` | `str` ≤200 | substring over title, description, file path, rule id |
| `include_closed` | `bool` = `false` | include remediated / accepted-risk / false-positive |
| `limit` | `int` = 20, 1–200 | |

Returns `{findings, returned, total_matching, has_more, next_hint}`. Sorted
**most urgent first** — by time remaining against the SLA, not by severity. A
critical with three days left beats a high with twenty minutes left.

`total_matching` and `next_hint` are there so an agent can tell "that is
everything" from "that is the first twenty" without guessing from the array
length.

No `snippet` in a list response. It is the most sensitive field in the system,
and shipping it in a list puts it in every browser cache and proxy log on the
path. `get_finding` (via the HTTP detail endpoint) is where source code lives.

### `get_cve_details`

Local advisory lookup for one CVE. Case-insensitive. Returns the advisory plus a
`cvss_band`, a `severity_mismatch` flag when the feed's declared severity
disagrees with its CVSS score, and `matching_findings` linking back to the
backlog.

An unknown CVE is a **result**, not an error:

```json
{ "found": false, "cve_id": "CVE-9999-0000",
  "available_count": 3, "known_examples": ["CVE-2024-22195", "…"] }
```

It is a *local* feed rather than a live NVD call for a confidentiality reason,
not an offline one: an analyst triaging a leak report for a customer of a
managed security provider should not be telling a third party which CVEs that
customer is worried about, at what volume, at what hours. See
`backend/services/cve.py`.

### `propose_fix`

The one that matters. Runs the policy gate and then the agent loop.

| arg | type | notes |
|---|---|---|
| `finding_id` | `str` (UUID) | |
| `correlation_id` | `str?` ≤120 | |
| `open_ticket` | `bool` = `true` | also open a ticket for the reviewer |

Returns `outcome` (`approved` / `rejected` / `escalated` / `policy_refused`),
`requires_human_approval` — **hardcoded `true`, not computed** — the cost
accounting, the reviewer's comments, and the patch.

`requires_human_approval` is a constant because it is not a runtime fact. It is
the guarantee, and the field exists so a model reading this response cannot come
away thinking a successful remediation is finished. It is a
[truthful constant, not a bug](
../../docs/adr/001-safety-rails-and-human-approval.md).

Cost reporting is honest per engine: with the AutoGen engine it is real tokens
and a real dollar figure; with the deterministic engine `llm_model` is `null` and
the cost is genuinely `0.0`. Recording a made-up model name would be worse than
recording nothing.

Every call is audited with actor `mcp:propose_fix` and the arguments recorded
wholesale.

### `create_ticket`

Opens a human work item and moves the finding to `TRIAGED`. `priority` defaults
to the finding's own severity. Rejects an unknown finding, a malformed UUID, and
a finding in a terminal state.

## Both SDK majors

The SDK renamed `FastMCP` to `MCPServer` in v2, and this project supports both
with a fifteen-line shim — because `semgrep` pins `mcp<2` and pinning either way
makes the scanner and the MCP surface mutually exclusive. The version in use is
logged at startup and reported on `GET /health/policy`, so a deployment always
knows which branch it took. Full reasoning in
[ADR 004](../../docs/adr/004-mcp-sdk-major-version.md).

## stdout is the protocol channel

On stdio, **stdout carries the JSON-RPC stream**. A single stray `print` or
INFO log line corrupts it and the client disconnects with an unhelpful parse
error on *its* side, with nothing useful in this process's logs.

`run_mcp_server.py` calls `configure_logging()` first and then refuses to start
if stdout is already dirty (`_assert_clean_stdout`), which catches the common
cause — a library that logs at import time — and reports it where the operator
is looking.

The honest caveat: `backend/core/logging.py` writes every log line to stdout, so
a runtime INFO line still lands on the wire. Routing logs to stderr is the real
fix and is not done here. This is recorded in
[architecture.md §11](../../docs/architecture.md).

## There is no authentication on this server

No token check, no role check, no transport-level auth, anywhere in
`backend/mcp_server/`. `SENTINEL_AUTH_ENABLED` is consulted only by the HTTP
layer.

That is defensible on stdio — the transport is a pipe the client process
created, so there is no network peer to authenticate — and **not** defensible on
`streamable-http`, where the server is reachable by anything that can open a
socket. That is why the streamable-http service sits behind a compose profile
that is off by default:

```bash
docker compose --profile mcp-http up -d mcp
```

Put auth in front of it before exposing it.

## Session model

One database session per MCP *connection*, not per tool call, opened by
`mcp_session()` and closed on disconnect. Opening a session is a pool checkout,
and an agent making four related calls should not pay for four of them. The
engine is loop-scoped and the MCP server owns its loop for the connection's
lifetime, so a single session is safe.

## Testing

`tests/integration/test_mcp_tools.py` (37 tests) drives all four tools through a
real `MCPServer` rather than calling `SentinelTools` directly — so the
registration, the input schemas, the structured output, and protocol-level
rejection of a bad arity or an unknown tool name are all covered. Calling the
methods directly would have verified the business logic and proved nothing about
the protocol surface.

The split is deliberate and is why the code is split the same way: tool bodies
are one-liners that validate and delegate to `SentinelTools`, which is plain
async Python a test can call without constructing a protocol server.

## Adding a tool

1. Add a `*Args` and a `*Result` pydantic model in `tools.py`. The result model
   must name **both** outcomes it can produce — an agent cannot reason about a
   result schema that does not say what the unhappy path looks like.
2. Implement the method on `SentinelTools`. Return, do not raise. Catch broadly,
   audit, and return a `ToolError`.
3. Register it in `build_mcp_server` (`server.py`).
4. Update the count assertion in `tests/integration/test_mcp_tools.py`.
5. Add an actionable `description` — it is the only thing the model reads before
   deciding to call the tool. A test asserts every tool has one.
