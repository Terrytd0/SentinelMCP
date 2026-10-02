# SentinelMCP — Architecture

Sprint 6 of the AI Engineering capstone roadmap. Cybersecurity domain, client
Ironclad Cyber Defense.

This document explains *why the system is shaped this way*. What each endpoint
does is in the OpenAPI schema at `/docs`; what each table holds is in
`backend/database/models/`. What follows is the reasoning that the code cannot
state for itself, plus the three bugs this project found in itself, because a
document that only describes the happy path is a brochure.

---

## 1. The problem

A managed security provider's analysts get hundreds of SAST/DAST/dependency
findings a week and spend most of their time on manual triage rather than
remediation. The two things that are actually expensive:

1. **Deciding what matters** — a hundred findings a week is the same as none.
2. **Turning a finding into a change** — knowing what to fix and writing the
   fix are different skills, and most of the queue is people who have the first
   and not the second.

So the system does two things: it orders the queue by *time remaining* rather
than by severity, and it drafts the change. Everything else in here exists to
make the second one safe enough to let a machine attempt.

---

## 2. The shape

```
                        ┌──────────────────────────────────────┐
   Claude Desktop ──────▶  MCP server  (stdio / streamable-http) │
   or any MCP client     │  list_findings                       │
                         │  get_cve_details                     │
                         │  propose_fix                         │
                         │  create_ticket                       │
                         └───────────────┬──────────────────────┘
                                         │
   human analyst ───────▶  FastAPI  /docs                        │
                         │  scans · findings · remediations      │
                         │  pull-requests · sla · audit          │
                         └───────────────┬──────────────────────┘
                                         │  ScannerBackend
                                         │  (gRPC, or in-process)
                                         ▼
                         ┌──────────────────────────────────────┐
                         │  gRPC ScannerService  :50051         │
                         │  Scan(target) → typed findings       │
                         │  Health()    → real capability        │
                         └───────────────┬──────────────────────┘
                                         ▼
                         FixtureScanner  ·  SemgrepScanner
                                         │
                                         ▼
                              PostgreSQL  (system of record)
```

Three processes, one database. The split exists because **scanning is CPU-bound
and subprocess-heavy** (Semgrep shells out) while the API is I/O-bound. Sharing
a process means one slow scan makes `/health` time out and takes the triage queue
down with it.

### Why the gRPC boundary is real, and how to tell

`SENTINEL_SCANNER_TRANSPORT` decides which implementation of `ScannerBackend`
a process gets. See [ADR 003](adr/003-grpc-scanning-boundary.md).

| value | behaviour | who uses it |
|---|---|---|
| `grpc` | dial the service; a dead target is a **startup failure** | `docker compose up`, the smoke test |
| `in_process` | call the registry directly, no wire | the test suite |
| `auto` *(default)* | dial it, fall back to in-process if the health probe finds nothing | a bare `uvicorn` |

`auto` is a compromise, and a compromise worth being suspicious of: a transport
decision that silently degrades looks exactly like one that works. This project
shipped a version of `build_scanner_backend` that *always* returned the
in-process client, so the proto, the compose file, and every docstring described
a gRPC boundary that no production path ever crossed. The entire suite was
green. `GET /scans/targets` had reached into the client's private `_registry`
attribute, so over a real connection it returned an empty list — a discovery
endpoint that worked in development and returned nothing in the deployment it
exists for.

Both are now asserted rather than described:
`tests/integration/test_scanner_transport.py` checks which implementation each
mode produces against a real server on an ephemeral port, and
`scripts/smoke_e2e.py` runs the whole pipeline across two real OS processes with
`SENTINEL_SCANNER_TRANSPORT=grpc`, so a regression there fails loudly instead of
quietly proving nothing.

---

## 3. Data model

Seven tables. The reasoning that matters:

**A finding is identified by a fingerprint, not by an id.** `compute_fingerprint`
is a SHA-256 over `(scanner_kind, rule_id, normalised file path, target)`. It
deliberately excludes the snippet, the line numbers, the description, and the
severity. A finding is a *kind of problem at a place*, not an instance of
observed text — so when a scanner's output shifts by two lines or rewords its
description, the same finding updates instead of arriving as a new one, and the
SLA clock does not restart. Line number is not identity.

**Enums are `VARCHAR + CHECK`, not PostgreSQL `ENUM`s.** Adding a value to a
native enum in PostgreSQL is a schema migration that takes an ACCESS EXCLUSIVE
lock. `native_enum=False, length=32, validate_strings=True` costs a little space
and buys an enum value as a one-line change. (`class X(str, Enum)` rather than
`enum.StrEnum` is deliberate — SQLAlchemy stores the *value*, and a `StrEnum`
member is a `str` subclass, which makes the stored-vs-loaded type ambiguous.)

**`audit_logs` has no `updated_at` and is append-only.** It is an event log, and
an event log with a mutable timestamp is a contradiction. Nothing in the
application updates an audit row, and `tests/integration/test_pipeline_persistence.py`
asserts that.

**`pull_requests.auto_merge_blocked` defaults to `True` at the column level.**
Not just in code. The database itself would have to be altered to store a
pull request that is not blocked. §4 is the rest of the story.

**`findings.scan_id` has no foreign key.** A scan is not a row; it is a
correlation id, and findings outlive the scan that created them. `first_seen_at`
is the real provenance.

### The two loops in one process

`backend/database/session.py` keys the async engine by running event loop, and
that is a hard requirement rather than a style preference. SQLAlchemy's async
engine holds pooled connections bound to whichever loop first checked them out.
This process runs two long-lived loops — the FastAPI request loop, and the
background loop `run_sync()` uses to bridge synchronous scanner and agent code
back into async Postgres — so a single shared engine would eventually hand a
connection created on loop A to a caller on loop B. At best a `RuntimeError`;
at worst a poisoned connection in the pool that an unrelated request draws and
500s on. `tests/integration/test_cross_loop_session.py` asserts it.

---

## 4. The guarantee: the system cannot merge its own code

This is the project's thesis, so it is enforced five times over rather than once.

1. **No merge code exists.** `publisher.merge_pull_request()` is a function whose
   entire body raises. It is kept as a named function so the interface still
   answers "can this merge?" with a clear no, rather than by omission.
2. **The column default is `True`.** `auto_merge_blocked` is `Boolean, default=True`
   in the schema *and* hardcoded `True` at the insert. The guarantee does not
   depend on a caller remembering.
3. **`SENTINEL_ALLOW_AUTO_MERGE` is read only to raise.** If it is set, startup
   raises `MergePolicyViolation` and the process refuses to serve. There is no
   code path that reads the flag to enable anything — passing `False` does not
   unlock a thing, it only avoids raising.
4. **A test AST-walks the source.** `tests/unit/policy/test_safety_rails.py`
   parses every module under `backend/` and asserts that no assignment anywhere
   sets `auto_merge_blocked` to anything but the literal `True`, and that
   **exactly one** function in the codebase writes
   `PullRequestStatus.MERGED` — `ApprovalService.record_external_merge`, which
   records an observation made by a human and contacts no git host. It also
   walks `app.routes` and asserts no path ends in `/merge` or `/automerge`.
   Check 2 catches a bad insertion; check 4 catches a *new* insertion.
5. **The smoke test proves it end to end.** `scripts/smoke_e2e.py` scans, drafts
   a PR, confirms an analyst gets 403, confirms an approver succeeds, and then
   asserts the status is not `MERGED` and the block is still set.

### The sequence

```
finding (OPEN, eligible)
  → policy gate          evaluate_auto_remediation(), re-evaluated fresh
  → proposal row         created BEFORE any code is generated
  → attempt counter      incremented
  → agent loop           developer ⇄ reviewer, bounded by rounds and calls
  → transcript           every turn written to agent_runs
  → draft pull request   ONLY if the loop approved; auto_merge_blocked = True
  → human approves       APPROVER or ADMIN only; a second approval is refused
  → human merges         in the git host, by hand
  → record_external_merge()   records the observation; finding → REMEDIATED
```

Two orderings here are load-bearing. The proposal row is created *before* the
loop runs, so an interrupted run leaves a record rather than nothing. And the
pull request is drafted *only on approval* — a rejected or escalated loop leaves
no artifact for a human to mistake for work in progress.

Approval moves the finding to `IN_PROGRESS`, **not** `REMEDIATED`. A draft that
a human approved is not a fix that a human merged, and the code that records a
merge is the only code that may claim the finding is done.

### Why the block is written twice

`ApprovalService.approve()` writes two audit rows: `pull_request.approved` from
the approver, and `pull_request.auto_merge_blocked` from `system:policy`. The
second one exists so that if somebody later edits that column directly, the
discrepancy is *detectable* — the approval is on record with no matching block.
One row would have been tidier and would have proved nothing.

---

## 5. The agent loop

Two engines, one protocol, and the service layer cannot tell which ran.

```
                     ┌─────────────────────────────┐
   RemediationEngine │  develop(snippet, feedback) │
   (Protocol)        │  review(patch)              │
                     └─────────────────────────────┘
                        ▲                        ▲
       DeterministicRemediationEngine    AutogenRemediationEngine
       (default, rule-based)             (opt-in, LLM)
```

`run_remediation_loop` drives the protocol: up to `max_rounds` (default 3) of
develop/review, up to `max_llm_calls` (default 8), with two terminations that
matter — the developer may `ESCALATE` (which stops *before* the reviewer is
called, because there is nothing to review), and reaching the round limit
escalates to a human rather than burning tokens on an argument two agents cannot
settle.

`LoopBudgetExhausted` is a distinct exception from an escalation on purpose: one
is an operational capacity signal that should alert, the other is a normal
outcome that should appear in a dashboard.

### The deterministic engine is the default, and that is the interesting choice

It is not a stub and not a placeholder. It is a rule-based developer with seven
rewrites (eval→`ast.literal_eval`, SQL f-string→bound parameter, `shell=True`→
argv list, disabled TLS verification, hardcoded secret→environment,
`math.random`→`secrets`, proxy-auth-on-redirect), and a reviewer that runs three
real checks on the produced patch:

1. the vulnerable construct is gone from the added lines,
2. `.py` output actually parses (retrying inside an indented body, so a statement
   fragment is accepted),
3. removed lines appear in the snippet, and more than 20 added lines is refused
   as oversized.

It escalates on a vulnerability class it has no rewrite for, rather than
guessing. It is the test oracle for the loop's control flow, it costs nothing,
it needs no network, and it makes the whole remediation path runnable in CI. The
AutoGen engine is the same protocol with a model behind it.

Each rewrite documents its own limits and a test asserts they are documented —
because a fix that half-solves a problem is the most dangerous output an agent
can produce. The `eval` rewrite does not add `import ast`; the SQL rewrite
produces the parameterised statement but not the bind call. The limits are in
the code, in the PR body, and in the tests.

### Why the two roles never talk

`autogen_engine.py` runs each role as its own single-agent
`RoundRobinGroupChat([agent], MaxMessageTermination(2))`, not as a two-agent
team. A reviewer that has read the developer's justification anchors on it, and
the entire value of the review step is that it does not. The
critique/revise cycle that genuinely needs both roles lives one level up, in
`run_remediation_loop`, which drives them a turn at a time.

Why AutoGen over LangGraph and CrewAI, in full, is [ADR 002](adr/002-autogen-vs-langgraph-crewai.md).

---

## 6. Policy

`evaluate_auto_remediation()` is ordered cheapest-check-first, and the order is
also the explanation order — a refusal reports the *first* reason that applied.
Seven checks, all conjunctive:

| # | refusal | why |
|---|---|---|
| 1 | `STATUS_NOT_ACTIONABLE` | already closed; nothing to remediate |
| 2 | `SEVERITY_NOT_ACTIONABLE` | INFO/UNSPECIFIED is never auto-drafted |
| 3 | `CONFIDENCE_TOO_LOW` | below MEDIUM; a guess is not a patch |
| 4 | `NO_SOURCE_LOCATION` | no file to patch |
| 5 | `PATH_OUTSIDE_SOURCE_ROOTS` | **the important one** — see below |
| 6 | `NO_SNIPPET` | no source to reason about |
| 7 | `ATTEMPT_BUDGET_EXHAUSTED` | 3 attempts; a 4th means escalate to a human |

What is deliberately *not* checked: whether the finding is interesting. Policy
gates safety, not priority. Deciding that a CRITICAL outranks a MEDIUM is the
queue's job, and mixing the two would mean loosening safety to reprioritise work.

### The path check is not a `startswith`

`_path_within_roots()` resolves *both* sides to absolute `PurePosixPath`s with
`..` collapsed before comparing. A path that starts inside an allowed root can
still escape it — `app/../../etc/passwd` — and a string-prefix check would wave
it through. Backslashes are normalised, so a finding reported by a Windows
scanner is checked the same way. A root that resolves to fewer than two path
parts (like `/`) is skipped rather than treated as match-everything.

Two related things were wrong and are now tested
(`tests/unit/policy/test_source_roots_setting.py`):

- `SENTINEL_REMEDIATION_SOURCE_ROOTS` was declared, documented, and read by
  **nothing**; the policy module silently fell back to a hardcoded tuple with
  the same values. Identical behaviour, so nothing failed — and the
  configurability was fictional. An agent that can patch
  `infra/terraform/prod/` can break production, so the allow-list has to be
  operator-configurable, not a constant buried in a rule module.
- The fallback was written `source_roots or DEFAULT_SOURCE_ROOTS`, which treats
  an operator who deliberately set an *empty* list as one who did not set it —
  and hands them the defaults. It now fails closed, and there is a test named
  for exactly that.

### The policy is re-evaluated, not remembered

`RemediationService._assert_allowed()` calls `evaluate_auto_remediation()` fresh
rather than trusting the `auto_remediation_eligible` flag stored at scan time.
Between the scan and the remediation the finding may have been triaged, closed,
or retried past the attempt budget. The stored flag is a fast filter written
once; the service-layer call is the gate. Re-checking is one cheap function call
and it closes the window in which a stale flag would let the agent act.

---

## 7. Ordering the queue: SLA state, not severity

`evaluate_sla()` produces one of `not_started` / `on_track` / `at_risk` /
`breached` / `met` / `stopped`, from the severity's deadline and the finding's
timestamps. `GET /findings/at-risk` sorts by **hours remaining**, not severity:

> A critical with three days left is more urgent today than a high with twenty
> minutes left, and the person triaging the list needs them ordered by how much
> time is actually left.

Two details that are easy to get wrong and are tested:

- A finding closed *after* its deadline reports `breached=True` with elapsed
  measured to the close, not to now. Measuring to now would say a ticket closed
  six months late was breached by six months of an SLA that stopped applying the
  moment it closed.
- `UNSPECIFIED` severity gets `sla_low_hours` — the most generous — so a brand
  new scanner does not manufacture a wall of phantom breaches on its first run.

---

## 8. The MCP surface

Four tools. Exactly four; a test asserts the count, so adding a fifth is a
deliberate act.

| tool | returns instead of raising on |
|---|---|
| `list_findings` | — (filters, pagination, `has_more` + `next_hint`) |
| `get_cve_details` | an unknown CVE is a *result* with `found: false`, not an error |
| `propose_fix` | a policy refusal is `outcome: "policy_refused"` with the machine-readable reason |
| `create_ticket` | an unknown finding, a malformed UUID, a terminal finding |

`get_cve_details` treating "not in the feed" as a result is the one that
matters. An agent that gets an exception for an unremarkable lookup learns to
retry; an agent that gets `found: false` learns to move on. And a *local* feed
rather than a live NVD call is a confidentiality decision, not an offline one:
an analyst triaging a leak report for a customer of a managed security provider
should not be telling a third party which CVEs that customer is worried about,
at what volume, at what hours. See `backend/services/cve.py`.

Errors are always returned, never raised, in a `ToolError` envelope carrying
`error`, `detail`, `remedy`, `finding_id`, and `correlation_id`. Every call is
audited with actor `mcp:<tool>`.

### The MCP server has no authentication

This is a real property of the code, not an oversight to be discovered later:
there is no token check, no role check, and no transport-level auth anywhere in
`backend/mcp_server/`. `SENTINEL_AUTH_ENABLED` is consulted only by the HTTP
layer. It is defensible — the stdio transport is a pipe the client process
created, so a network peer cannot reach it — and it must be stated plainly
rather than left for a reader to assume otherwise. The streamable-http
transport is *not* defensible without auth in front of it, which is why it is
behind a compose profile that is off by default.

### stdout is the protocol channel

On stdio, a single stray `print` or INFO log line corrupts the JSON-RPC stream
and the client disconnects with an unhelpful parse error. `run_mcp_server.py`
calls `configure_logging()` first and then refuses to start if stdout is already
dirty (`_assert_clean_stdout`). See §11 for the tension this creates.

---

## 9. Telemetry: a contract for Sprint 11

The roadmap's capstone is Aegis, a control plane that has to consume events from
seven repositories without writing seven adapters. That only works if the core
event fields cannot be renamed, so the schema is frozen and asserted.

Six core fields, deliberately named for the cross-fleet contract:
`service`, `timestamp`, `latency_ms`, `tokens_used`, `cost`, `status`.
Everything else (`operation`, `correlation_id`, `error_type`, `metadata`) is
additive. `error_type` is the exception *class name* and never the message,
because exception messages carry source code, credentials, and customer data.
`metadata` is documented as small, flat, and low-cardinality for the same reason.

`TelemetryClient` cannot fail the operation it measures: every emit is wrapped,
a sink that throws is caught and counted, and after 5 consecutive failures the
sink is disabled with one warning. `measure()` never suppresses the original
exception — it records the status and re-raises. Details in
[`backend/telemetry/README.md`](../backend/telemetry/README.md).

---

## 10. Auth

JWT, HS256, with an explicit `algorithms=[settings.jwt_algorithm]` allowlist and
`options={"require": ["exp", "sub"]}` on decode. The allowlist is the anti-`alg:none`
measure; a decoder that trusts the token's own header is a well-known and
still-exploited bug class.

Three roles: `ANALYST`, `APPROVER`, `ADMIN`; only the latter two may approve a
remediation. Two details worth stating:

- An **unrecognised `role` claim in a validly-signed token is a 401**, not a
  silent downgrade to `ANALYST`. A token you cannot interpret is not a token you
  should guess about.
- With auth disabled the principal is `ANONYMOUS`, which is deliberately granted
  **only ANALYST rights** — so running with `SENTINEL_AUTH_ENABLED=false` can
  never hand out the power to approve a code change.

**Not everything is behind auth.** 28 of the 36 endpoints declare no principal
dependency: the read endpoints (findings, SLA, audit, CVE, health) are open by
design so an operator can look at the queue without a login. The write endpoints
and the three approval endpoints are not. This is a property of the code as
written, stated here so nobody has to infer it.

---

## 11. Known tensions, stated rather than hidden

**stdout on stdio vs. logging to stdout.** `run_mcp_server.py` documents that
stdout *is* the protocol channel, and `backend/core/logging.py` writes every log
line to stdout. `_assert_clean_stdout()` catches writes that happened before
logging was configured; a runtime INFO line still lands on the wire. The
mitigation in place is that the MCP entry point logs at INFO deliberately and
keeps its own noise low, and that the guard catches the common cause (a library
logging at import time). The real fix is routing logs to stderr, and it is not
done here.

**The MCP server owns a session per connection, not per call.** An agent making
four related tool calls does not pay for four pool checkouts. The engine is
loop-scoped and the MCP server owns its loop for the connection's lifetime, so
this is safe — but it does mean one slow tool call holds the session for the
whole connection.

**`ProposalStatus` has no `MERGED` member, on purpose.** Merging is a
`PullRequest` state, recorded by a human action. Putting `MERGED` on the
proposal would imply the agent could reach it, and the AST test in §4 asserts
the single writer rather than trusting the enum's shape.

**Semgrep is not in the container image.** The scanner degrades to fixture-only
and says so on `/health` and `/scans/targets`, and a scan that explicitly names
an unavailable scanner returns gRPC `UNAVAILABLE` → HTTP 502 rather than an
empty clean result. An empty result would be the worst possible answer: it reads
as "no vulnerabilities found".

**`data/samples/vulnerable_app/` is deliberately vulnerable code.** It is
excluded from ruff, from mypy, and from import, and exists only as a real
Semgrep target. Do not "fix" it.

---

## 12. What the tests are actually for

414 tests. The interesting part is not the count, it is what each group is
*unable* to check.

| group | count | what only it can prove |
|---|---|---|
| `tests/unit/policy/test_safety_rails.py` | 21 | the AST assertions in §4 — that no *new* code can set the block or write `MERGED` |
| `tests/integration/test_db_session_dependency.py` | 8 | the real session dependency, which every other test overrides |
| `tests/integration/test_scanner_transport.py` | 12 | which `ScannerBackend` implementation each mode actually produces |
| `tests/integration/test_grpc_scanning.py` | 22 | typed schema, status codes, and that an error cannot be mistaken for an empty result — over a real socket |
| `tests/integration/test_mcp_tools.py` | 37 | the four tools through a real `MCPServer`, including protocol-level rejection |
| `tests/integration/test_pipeline_persistence.py` | 20 | that the audit log is append-only and a duplicate fingerprint is rejected by the database |
| `tests/integration/test_schema_drift.py` | 3 | `alembic check` — live schema vs. models |
| `scripts/smoke_e2e.py` | 21 | the whole pipeline across two OS processes, a real socket, and a real database |

The rule the suite follows: **if a test overrides a dependency, some other test
has to run the real one.** Otherwise the override is not a test double, it is a
hole. That rule exists because of the two worst bugs in this project, both
found by the smoke test and both invisible to a green suite:

### The two bugs the smoke test found

**`get_session()` never committed.** Its docstring promised "commits on clean
exit, rolls back on any exception" and the body rolled back but did not commit.
Closing the session therefore discarded everything a route had written:
`POST /scans` answered `{"new_findings": 8, ...}` and left the `findings` table
empty. Every write endpoint in the HTTP API — scans, tickets, status changes,
remediation, approval — was a no-op that reported success.

**`get_db_session()` tore its generator down with `asend(None)`.** Resuming an
async generator that has already yielded once makes it run to completion and
raise `StopAsyncIteration`, which PEP 479 converts into
`RuntimeError: async generator raised StopAsyncIteration` on the way out of a
coroutine. It sat in a `finally`, so it replaced the response of *every
authenticated request* with a 500.

Both were invisible because every route test overrides `get_db_session` with a
session the test manages itself, so neither function was executed by a single
test. The naive fix for the second — swapping `asend(None)` for `aclose()` —
removes the 500 and introduces a quieter bug, because `aclose` throws
`GeneratorExit` at the `yield` and the commit never runs. The actual fix was to
stop hand-driving a generator: `backend/database/session.py` now owns one
`transaction()` context manager, and `get_session`, `session_scope`, and
`get_db_session` are all thin wrappers over it, so there is exactly one
implementation of "the request finished cleanly".

Neither bug would have been found by a test suite that only asserted on return
values. Both were found by starting two processes and looking.

### The three test groups are not interchangeable

| group | what only it can prove |
|---|---|
| unit + mocks | the logic, fast and hermetic; nothing about the real dependency |
| integration, real service | that the real dependency behaves; the only way to catch a session bug |
| the evidence harness, by execution | that the *output* does what it claims; nothing else can |

A green suite said the SQL rewrite produced a parameterised statement. It was
true, and the statement silently returned the wrong rows. The suite was answering
a question nobody had asked.

---

## 13. The reviewer's rejection rate, and what it is for

Running the deterministic reviewer over the real fix commits of 19 GitHub Security
Advisories, **9 of 30 real, merged, human-reviewed security fixes would be
rejected** given the one line a scanner reports. **8 of 30** given the enclosing
block the loop is now shown. Full numbers in [evidence.md](evidence.md).

| check | objections | what it asserts |
|---|---|---|
| `scoped` | 8 | at least one removed line is in the reported snippet |
| `size` | 3 | a single-finding patch adds at most 20 lines |

Before the parse check was restricted to like-for-like replacements this was 18 of
30, and that check accounted for 15 of the 18 — it was simply wrong on multi-line
diffs. Fixing a bug improved the number, which is why the remainder deserves
arguing about rather than celebrating.

**The residual 8 are not a context problem.** A ±10 line window takes the rate to
3 of 30, because it sweeps in the neighbouring lines a typical small fix touches
and so satisfies the check by accident. An enclosing block satisfies it by being
the right context. The 8 that survive are fixes that also edit something far away
— an import, a declaration, a type — which no snippet anchored on one line can
reach and which the 120-line ceiling exists to stop us reaching by showing the
whole file.

So what remains is a design argument, and there are two defensible answers:

**The reviewer is a gate.** Then the scope check is right, and a patch that also
edits an import 400 lines from the finding *should* get a second look. The
argument for it: the reviewer is handed a snippet and a diff and never reads the
file, so "the patch touches code I was not shown" is a genuinely correct
observation, and a human behind the gate costs a minute rather than a release.

**The reviewer is a second opinion.** Then its error rate on our own output is the
only number that matters — which is 0 measured rejections and 5 approvals on
Tier 1's six cases, one of which was a SQL rewrite that had, until that run, been
silently returning the wrong rows. The argument for it: a check with 8 false
rejections in 30 is a check a human learns to skim.

What is clearly wrong either way is the measurement, not the gate. **This corpus is
all good patches.** The number that would settle the question is how often the
reviewer rejects a patch that is *wrong* — and that needs a corpus of bad patches
labelled by a human, which does not exist. Every number in this section is a
half-measure, and the missing half is the only one that would justify the gate.

---

## 14. Where to read next

- [Evidence](evidence.md) - the three tiers, what they found, and the known gaps
- [ADRs](adr/README.md) - the four decisions, with the alternatives rejected
- [The MCP contract](../backend/mcp_server/README.md) - tool schemas and the
  "return, don't raise" rule
- [Telemetry contract](../backend/telemetry/README.md) - the frozen event shape
- [Integration tests](../tests/integration/README.md) - how to run them, and
  what they skip
- [Regenerating the gRPC stubs](../backend/grpc_service/generated/README.md) -
  `make proto`
