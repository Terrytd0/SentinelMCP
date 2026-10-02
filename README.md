# SentinelMCP

**Sprint 6 · Cybersecurity · Client: Ironclad Cyber Defense**

A production-style **MCP server** exposing security-triage tools to any MCP
client, paired with an **AutoGen developer/reviewer agent loop** that drafts
human-approved remediation pull requests — and an **AutoGen-free deterministic
engine** so the whole path is testable with no API key.

The system scans a codebase, persists findings against severity-based SLAs, and
attempts to fix them. It can propose, review, and draft. **It cannot merge.**
That is enforced five ways, one of which is a test that AST-walks the codebase
to prove no new code can add a merge path.

```
Claude Desktop ──▶  MCP server ─┐
                                ├──▶  gRPC ScannerService ──▶  Semgrep / fixtures
human analyst ───▶  FastAPI ────┘                                  │
                                                                   ▼
                                                          PostgreSQL
```

---

## What this cannot do — read this first

The remediation engine is **six regex rules over a single line of source.** That
is the whole of it, and these are the measured numbers on real code.

| | measured |
|---|---|
| Real vulnerable files where a rule could act at all | **3 of 30** (10%) |
| Patches that stopped a real exploit, of those proposed | **5 of 5** |
| Rewrites that need a human step before the code will run | 2 of 6 |
| Fixture CWE classes with no rewrite, which escalate to a human | **7 of 13** |
| Real merged fixes our reviewer would reject | 9 of 30 — **8 of 30** with the enclosing block the loop is now shown |

All of this is measured, not asserted, by three tiers of evidence against real
exploits, an independent static analyser, and 19 published CVEs. Full write-up,
including the eight defects the harness found in the engine and in itself:
**[docs/evidence.md](docs/evidence.md)**.

**So the honest pitch is triage, not autonomous remediation.** The queue ordering,
the SLA clock, the policy gates and the audit trail work on any finding a scanner
produces. The *drafting* is narrow: mechanical, high-confidence, single-line
fixes, with everything else escalated to a human. That is a real product — a
managed security provider's volume problem is triage, and an agent that drafts the
10% it can do correctly while escalating the rest beats an agent that guesses at
the 90% it cannot.

The number that is **not** a limitation: the merge block is real. A test
AST-walks `backend/` to prove no future commit can add a code path that merges.
That is the part of this project I would defend without qualification.

---

## Why this exists

A managed security provider's analysts get hundreds of SAST/DAST/dependency
findings a week and spend most of their time triaging rather than remediating.
The two expensive things are deciding what matters, and turning a finding into a
change — most of the queue can do the first and not the second.

So: order the queue by **time remaining** rather than severity, and let a machine
attempt the change on the narrow class where a mechanical fix is unambiguous. The
second one is only safe with a hard human gate, which is the part this project is
actually about.

## Resume line

> Built a production-style MCP server exposing security-triage tools to any MCP
> client, paired with an AutoGen developer/reviewer agent loop that drafts
> human-approved remediation pull requests — with a three-tier evidence harness
> that found eight defects in the engine, including one asserted as correct by a
> green test.

---

## What it does

| | |
|---|---|
| **4 MCP tools** | `list_findings`, `get_cve_details`, `propose_fix`, `create_ticket` — over stdio (what Claude Desktop launches) or streamable-http |
| **36 HTTP endpoints** | scans, findings, remediation, pull requests, SLA dashboard, tickets, CVE lookup, read-only audit |
| **gRPC scanning service** | protobuf-typed `Scan` and `Health`; the fingerprint is computed on the wire side |
| **2 agent engines** | AutoGen (opt-in, LLM) and a deterministic 6-rewrite one (default) behind one protocol |
| **7 policy gates** | severity, confidence, status, path allow-list, snippet, attempt budget — re-evaluated fresh, never trusted from a stored flag |
| **16 audit actions** | every finding, every agent turn, every human decision |
| **3 evidence tiers** | patch correctness measured by execution, by an independent static analyser, and against 19 real CVEs |
| **414 tests** | ruff + mypy + pytest, all green; 159 of them against real Postgres, real sockets, and real upstream commits |

## Try it

```bash
git clone <this repo> && cd SentinelMCP
cp .env.example .env

# Option A: everything in Docker (a real gRPC boundary)
docker compose up -d --build
docker compose exec api python -m backend.scripts.seed
open http://localhost:8000/docs

# Option B: no Docker beyond Postgres
docker compose up -d postgres
pip install -e ".[dev]"
alembic upgrade head
make seed
make api          # http://localhost:8000/docs
```

Then, to see the whole thing work end to end across two real processes:

```bash
python scripts/smoke_e2e.py
```

```
  [PASS] the API reports itself healthy
  [PASS] and that the scanning service behind it is reachable
  [PASS] auto-merge is blocked and human approval is required
  [PASS] fixture targets are discoverable over gRPC
  [PASS] the scan succeeded                          new=8 total=8
  [PASS] findings were persisted
  [PASS] the outcome is a legitimate agent result     outcome=approved rounds=1
  [PASS] the draft is blocked from auto-merge         status=draft auto_merge_blocked=True
  [PASS] an ANALYST cannot approve                   HTTP 403
  [PASS] an APPROVER can approve
  [PASS] and approving it STILL does not merge it    status=open blocked=True
  [PASS] the auto-merge block was recorded by the policy engine, not the approver
SMOKE PASSED -- 21 checks
```

Note what this does and does not show. It scans `data/fixtures/`, which is
hand-written to match the rule table, so "the outcome is a legitimate agent
result" means the *plumbing* works end to end — not that the fix is correct. On
real code the engine engages on 10% of vulnerable files. [`make evidence`](#is-the-patch-actually-a-fix)
is the version that measures the fix.

### Connect it to Claude Desktop

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

`in_process` because a stdio server is a subprocess the client spawned — there is
no second process to dial. See [ADR 003](docs/adr/003-grpc-scanning-boundary.md).

---

## The guarantee

**The system cannot merge its own code.** Not "it doesn't by default" —
enforced, redundantly, because a guarantee that depends on nobody ever finding
the exception is a convention, not a guarantee.

1. **No merge code exists.** `publisher.merge_pull_request()` exists and its body
   raises.
2. **The column default is `True`.** `auto_merge_blocked` is `Boolean,
   default=True` in the schema *and* hardcoded at every insert. The database would
   have to be altered to store an unblocked pull request.
3. **`SENTINEL_ALLOW_AUTO_MERGE` is read only to raise.** Set it and the process
   refuses to start. It is a tripwire, not a switch.
4. **A test AST-walks the source.** No assignment anywhere sets
   `auto_merge_blocked` to anything but `True`; exactly one function writes
   `PullRequestStatus.MERGED`; no route path ends in `/merge`. Check 4 catches a
   *new* merge path, which the other three would not.
5. **The smoke test proves it** on two real processes: blocked → analyst 403 →
   approver OK → still not merged.

Full reasoning, including the alternatives that were refused:
[ADR 001](docs/adr/001-safety-rails-and-human-approval.md).

This is the load-bearing claim, and it is the one thing here I would defend without
qualification. The remediation engine is narrow and I have said so; this is not
narrow and it is not a matter of degree.

---

## Is the patch actually a fix?

The system can prove it cannot merge its own code. Nothing in it could say whether
a drafted patch *works* — until this.

```bash
make evidence        # three tiers, six real advisories
make evidence-all    # all nineteen
```

| tier | question | whose answer | needs a network |
|---|---|---|---|
| 1 execution | does the patch stop a real exploit? | ours, by running it | no |
| 2 static | does an independent detector stop reporting it? | Semgrep's | first run only |
| 3 corpus | what happens on real CVEs and real upstream fixes? | upstream's | yes |

Tier 1 writes a real vulnerable module, runs a real attack against it, applies the
agent's patch, and runs the attack again. Tier 2 asks Semgrep whether the finding is
still reported. Tier 3 fetches the real fix commit for 19 GitHub Security
Advisories and compares.

There is deliberately **no pass rate**: every denominator available is flattering by
construction. The report leads with what each tier could not check, and the counts
of patches that are incomplete, that regress the function, and that no tier covers.

**What it found.** Eight findings — seven code defects and one measurement defect.
Four of the code defects were invisible to a 300-test suite, and one of those was
being actively asserted as correct by a green test:

- The SQL rewrite emitted a statement that psycopg2 rejects and **sqlite3 executes
  while silently returning the wrong rows** — a `LIKE` wildcard colliding with the
  `%s` placeholder. The existing test asserted the text contained `%s`; the broken
  form does too.
- The reviewer requested changes on a correct one-line signature change, because it
  reconstructed the patched source from the diff's added lines and got a block header
  with no body. Fixing that was not enough: the same check was also rejecting any
  diff that was not a like-for-like line replacement, which was 15 of 18 rejections
  on real upstream fixes.
- Two rules emitted **Python into Go files**, and the test for one of them asserted
  that was correct, on a `.go` path.
- `eval(` matched the *declaration* of a method named `eval`; `task_keyprefix` was
  treated as a secret.
- Two bugs in the harness itself, found by its own mutation control.
- And a measurement defect: the reviewer-rejection rate was two-thirds an artifact
  of feeding the reviewer a one-line snippet and judging 67-line fixes against it.

All fixed, all pinned by regression tests. The unflattering numbers are still
reported, and one of them turned out to be the harness's fault rather than the
engine's:

- **The rule table engages on 3 of 30 real vulnerable files (10%)** — an *upper*
  bound, since the candidate line is found by matching the table's own patterns.
  A six-regex table is the wrong shape for most real vulnerabilities, and no amount
  of work changes that without a different product.
- **9 of 30 real, merged, human-reviewed fixes would be rejected by our own
  reviewer** — 8 of 30 once the loop is shown the finding's enclosing block
  instead of the single line a scanner reports. A ±10 line window takes it to 3
  of 30, and is *not* what is shipped: it satisfies the check by sweeping in
  neighbouring lines by accident rather than by being the right context. The
  residual is fixes that also edit an import far from the finding, which the
  reviewer is arguably right to flag.

Full write-up, including why a bad `--config` URL exiting 0 makes a static-analysis
gate silently meaningless, and why one of these numbers was a measurement artifact
before it was a product finding: **[docs/evidence.md](docs/evidence.md)**.

---

## Architecture

Three processes, one database.

```
                    ┌──────────────────────────────────┐
 Claude Desktop ───▶│  MCP server  (stdio / http)      │
 or any MCP client  │  4 tools · errors returned,       │
                    │  never raised                    │
                    └────────────────┬─────────────────┘
                                     │
 human analyst ────▶┌────────────────┴─────────────────┐
                    │  FastAPI                          │
                    │  32 endpoints · JWT · 3 roles      │
                    └────────────────┬─────────────────┘
                                     │  ScannerBackend (ABC)
                                     ▼
                    ┌──────────────────────────────────┐
                    │  gRPC ScannerService  :50051      │
                    │  Scan() → typed findings          │
                    │  Health() → real capability       │
                    └────────────────┬─────────────────┘
                                     ▼
                    FixtureScanner · SemgrepScanner → PostgreSQL
```

**Why the boundary is real.** Scanning is CPU-bound and shells out to Semgrep;
serving is I/O-bound and must stay responsive during an incident. In one
process, one slow scan makes `/health` time out, and a health check that lies is
worse than no health check.

`SENTINEL_SCANNER_TRANSPORT` picks the implementation — `grpc`, `in_process`, or
`auto` (default: probe with a 2s deadline, fall back with a WARNING). Both
implementations satisfy the same ABC, so `ScanningService` depends on the
interface and the test suite needs no socket for 280+ of its 414 tests.

**Full walkthrough:** [docs/architecture.md](docs/architecture.md).

### The data model, briefly

- A **finding is identified by a fingerprint**, a SHA-256 over
  `(scanner, rule_id, normalised path, target)`. It deliberately excludes the
  snippet and line numbers, so a scanner whose output shifts by two lines
  *updates* the finding instead of arriving as a new one — and the SLA clock
  does not restart. Line number is not identity.
- **Enums are `VARCHAR + CHECK`, not PostgreSQL `ENUM`s.** Adding a value to a
  native enum takes an `ACCESS EXCLUSIVE` lock; here it is a one-line change.
- **`audit_logs` has no `updated_at`** and nothing updates it. An event log with
  a mutable timestamp is a contradiction.
- **The engine is keyed by event loop.** This process runs two long-lived loops,
  and SQLAlchemy's async pool holds connections bound to whichever loop first
  checked them out.

### The agent loop

```
for round in range(3):                          # and at most 8 LLM calls
    patch   = developer.propose(snippet, feedback)   # may ESCALATE
    verdict = reviewer.critique(patch)               # APPROVE / REQUEST_CHANGES / REJECT
    if approved: return patch
return escalate_to_human()
```

Two engines implement one protocol, so the service cannot tell which ran and the
audit trail is identical:

- **Deterministic (default).** Six regex rules, applied to the one line the
  scanner reported (`eval` → `ast.literal_eval`, SQL f-string → bound parameter,
  `shell=True` → argv, disabled TLS verification, hardcoded secret → env,
  proxy-auth-on-redirect), and a reviewer that checks the patch *parses*, that the
  vulnerable construct is gone, and that it is not oversized. It escalates on a
  class it has no rewrite for, on a language its replacement does not compile in,
  and on a finding with no snippet — rather than guessing. Free, no network,
  deterministic — so it is the test oracle for the loop's control flow, and it makes
  the whole remediation path runnable in CI. **This is the 10% in the table at the
  top**, and the reason is structural: a real vulnerability is usually not one line.
- **AutoGen (opt-in).** Same protocol, LLM behind it, with per-call token and
  cost attribution. The two roles run as **separate single-agent chats**, never
  one team: a reviewer that has read the developer's justification anchors on it,
  and not anchoring is the entire value of the review step.

Each rewrite documents its own limits, and a test asserts they are documented —
a fix that half-solves a problem is the most dangerous thing an agent can output.
And because documentation is not evidence, [the three evidence tiers](#is-the-patch-actually-a-fix)
*measure* those limits by execution. That harness removed a seventh rewrite
(`math.random` → `secrets`): its pattern was Go's and its replacement was Python's,
and no regex can bridge the two.

---

## Design decisions

| ADR | decision | the short version |
|---|---|---|
| [001](docs/adr/001-safety-rails-and-human-approval.md) | Humans merge, always | five enforcement mechanisms; the AST test is the one that catches a *new* merge path |
| [002](docs/adr/002-autogen-vs-langgraph-crewai.md) | AutoGen, not LangGraph or CrewAI | the reviewer must not be anchored; AutoGen makes separate agents and model clients the default. LangGraph is a state graph and this is a counter |
| [003](docs/adr/003-grpc-scanning-boundary.md) | Typed gRPC boundary | scanning is subprocess-heavy and must be separable; and an error must never be representable as an empty success |
| [004](docs/adr/004-mcp-sdk-major-version.md) | Support both `mcp` majors | `semgrep` pins `mcp<2`; pinning either way makes the scanner and the MCP surface mutually exclusive. Verified: 10 identical checks pass on **both** v1 (local) and v2 (container) |

### Both SDK majors, actually verified

`scripts/verify_mcp_sdk.py` runs the same ten assertions against whichever
`mcp` major is installed. The two environments genuinely differ, and that falls
out of the dependency graph rather than being arranged:

| environment | `mcp` resolves | why |
|---|---|---|
| local venv | **v1** | something in the tree pins `mcp<2` |
| runtime image | **v2** | the image deliberately does not install `semgrep` |

```bash
make verify-mcp                                     # whichever you have
docker run --rm sentinelmcp:ci python scripts/verify_mcp_sdk.py   # the other one
```

CI runs both (`mcp-sdk` and `docker` jobs), so a change that works on only one
major fails CI rather than a reviewer's environment.

---

## Verification

```bash
make check          # format-check, lint, typecheck, test  (what CI runs)
make test           # pytest; integration tests skip themselves
make test-integration
python scripts/smoke_e2e.py
make evidence       # measured patch correctness -- see docs/evidence.md
```

| gate | tool | result |
|---|---|---|
| format | `ruff format --check` | 126 files |
| lint | `ruff check` | clean |
| types | `mypy` (`disallow_untyped_defs`) | 114 files, clean |
| tests | `pytest` | **414 passed** |
| integration | `pytest -m integration` | **159 passed** against real Postgres, real sockets, and real upstream commits |
| end to end | `scripts/smoke_e2e.py` | **21 checks** across 2 processes |
| evidence | `scripts/evidence_report.py --all` | 3 tiers, 19 real advisories, 0 failures |

CI (`.github/workflows/ci.yml`) runs the same six gates plus a container build,
a real `/health/policy` check on the running image, and **tier 1 of the evidence
harness**. Only tier 1: tiers 2 and 3 need semgrep.dev and seven upstream clones,
so a network blip would train contributors to re-run red builds. Tier 1 needs no
network, no database and no key, runs in about two seconds, and is what notices
when a rewrite stops working.

### The suite's actual shape

| group | count | what only it can prove |
|---|---|---|
| `tests/unit/policy/test_safety_rails.py` | 21 | the AST assertions — no *new* code can set the block or write `MERGED` |
| `tests/integration/test_db_session_dependency.py` | 8 | the real session dependency, which every other test overrides |
| `tests/integration/test_mcp_tools.py` | 37 | the four tools through a real `MCPServer` |
| `tests/integration/test_grpc_scanning.py` | 22 | typed schema and status codes over a real socket |
| `tests/integration/test_pipeline_persistence.py` | 20 | append-only audit log; a duplicate fingerprint rejected *by the database* |
| `tests/integration/test_scanner_transport.py` | 12 | which backend implementation each mode actually produces |
| `tests/unit/agents/test_deterministic_agents.py` | 26 | each rewrite's diff, and that it documents its own limits |
| `tests/unit/policy/test_source_roots_setting.py` | 16 | that the path allow-list is operator-configurable, traversal-safe, and fails closed |
| `tests/unit/telemetry/test_telemetry_contract.py` | 16 | the frozen cross-fleet event shape Sprint 11 depends on |

---

## Two bugs this project found in itself — and eight the evidence harness found

Included because a portfolio that only shows the happy path is a brochure, and
because these are exactly the kind of defect a green suite hides.

These two were found by `scripts/smoke_e2e.py`, starting two processes and looking.

**`get_session()` never committed.** Its docstring promised "commits on clean
exit, rolls back on any exception"; the body rolled back and did not commit.
Closing the session therefore discarded everything a route had written:
`POST /scans` answered `{"new_findings": 8, ...}` and left the `findings` table
empty. Every write endpoint in the HTTP API was a no-op reporting success.

**`get_db_session()` tore its generator down with `asend(None)`.** Resuming an
async generator that has already yielded once makes it run to completion and
raise `StopAsyncIteration`, which PEP 479 turns into `RuntimeError` on the way
out of a coroutine. It sat in a `finally`, so it replaced the response of *every
authenticated request* with a 500.

Both were invisible to a fully green suite, because every route test overrides
`get_db_session` with a session it manages itself — so neither function was
executed by a single test.

The naive fix for the second — swapping `asend(None)` for `aclose()` — removes
the 500 and introduces a quieter bug, because `aclose` throws `GeneratorExit` at
the `yield` and the commit never runs. The real fix was to stop hand-driving a
generator: `backend/database/session.py` now owns a single `transaction()`
context manager, and `get_session`, `session_scope`, and `get_db_session` are
all thin wrappers over it.

The rule that came out of it, now written into the test suite:

> **If a test overrides a dependency, some other test has to run the real one.
> Otherwise the override is not a test double, it is a hole.**

### The eight the evidence harness found later

`make evidence` was written *because* of the two above, on the reasoning that if
starting two processes found two session bugs, asserting on diff strings would
find more. It found eight: a SQL rewrite that **silently returned the wrong rows**,
two rules that emitted **Python into Go files** — one of which a green test was
asserting was correct, on a `.go` path — a reviewer that rejected correct patches
for two separate reasons, `eval(` matching the *declaration* of a method named
`eval`, `task_keyprefix` treated as a secret, two bugs in the harness itself, and
one number that turned out to be an artifact of the harness rather than a fact
about the engine.

The rule that came out of *that*, also written into the suite:

> **A verification harness that cannot fail is worse than none.** The exploit must
> land on the unpatched code first, the mutation control must prove it can tell a
> fix from a no-op, and a rule set that reports nothing must be reported as
> vacuous rather than as a clean scan.

Full account, with before-and-after numbers:
[docs/evidence.md](docs/evidence.md).

---

## Layout

```
backend/
  agents/        the developer/reviewer pair: autogen_engine, deterministic, and the loop
  api/           FastAPI routers, dependencies, correlation-id middleware
  auth/          JWT, Argon2 hashing, roles, the session dependency
  config/        pydantic-settings; every env var with its default
  core/          clock, ids and fingerprints, logging, asyncio bridging
  database/      models, repositories, enums, the loop-scoped engine
  evidence/      3 tiers of measured patch-correctness evidence; no runtime path
  grpc_service/  the ScannerService server, the two client backends, conversion
  mcp_server/    the 4 MCP tools and their registration
  policy/        the 7 remediation gates and the SLA state machine
  scanners/      base interface, registry, fixture and Semgrep adapters, snippet enrichment
  services/      scanning, remediation, approvals, publisher, sla, cve
  telemetry/     the frozen event contract
proto/           sentinel/v1/scanner.proto
alembic/         one initial migration, verified by `alembic check` in tests
data/evidence/   the checked-in advisory manifest; the git cache is gitignored
docs/            architecture.md + evidence.md + 4 ADRs
scripts/         smoke_e2e.py, evidence_report.py
tests/           unit + integration, 414 tests
```

---

## Configuration

Every variable is documented in `.env.example` with its default and why it
exists. The ones that change behaviour:

| variable | default | effect |
|---|---|---|
| `SENTINEL_ALLOW_AUTO_MERGE` | `false` | **Set it and startup raises.** A tripwire, not a switch. |
| `SENTINEL_SCANNER_TRANSPORT` | `auto` | `grpc` \| `in_process` \| `auto`. `grpc` makes a dead target a startup failure. |
| `SENTINEL_AUTOGEN_ENABLED` | `false` | `true` + `SENTINEL_LLM_API_KEY` switches to the LLM engine. |
| `SENTINEL_REMEDIATION_SOURCE_ROOTS` | `["app/","src/","services/","lib/","config/"]` | the only paths the agent may draft patches under. Empty list fails **closed**. |
| `SENTINEL_REMEDIATION_SNIPPET_MAX_LINES` | `120` | ceiling on how much source the loop is shown, around the finding. `0` disables the ceiling. |
| `SENTINEL_ENABLED_SCANNERS` | `["fixture"]` | add `"semgrep"` for real SAST |
| `SENTINEL_APP_ENV` | `development` | `production` makes startup refuse a default JWT secret |
| `SENTINEL_TELEMETRY_SINK` | `file` | `file` \| `http` \| `null` |

Note list-valued settings need JSON, not comma-separated: `fixture,semgrep` is
an error at import.

## Known limits

Stated here rather than left to be discovered. The first is the one that matters
most, and it is measured rather than estimated.

- **The remediation engine covers about 10% of real vulnerabilities.** Six regex
  rules over one line of source, against 30 real vulnerable files pulled from 19
  published CVEs: a rule could act on 3. A real vulnerability is usually not one
  line, so this is a shape problem and more rules would not fix it. Seven of the
  thirteen CWE classes in `data/fixtures/` have no rewrite and escalate to a
  human, which is the intended behaviour. Measured, with the reasoning and the two
  attempts to improve it: [docs/evidence.md](docs/evidence.md).
- **The reviewer is starved of context** — was. It was handed the one line the
  scanner reported, so it rejected any fix touching neighbouring lines. The loop
  is now shown the finding's enclosing block, bounded by
  `SENTINEL_REMEDIATION_SNIPPET_MAX_LINES`, and the strategy used is recorded in
  the audit row. See `backend/scanners/snippet.py`; the residual rate and what it
  actually means are in [docs/evidence.md](docs/evidence.md).
- **CWE-295 has no verification.** The TLS rewrite is Go-only, there is no Go
  toolchain here, and no Semgrep rule was found that fires on
  `InsecureSkipVerify: true`. Tier 1 and Tier 2 independently record it as
  unverified rather than passing.
- **CWE-338 has no rewrite.** The rule that used to claim it emitted a Python name
  into a Go file, and `math/rand.Int` and `crypto/rand.Int` have incompatible
  signatures, so it was removed rather than patched.
- **Semgrep is not in the container image** and the Dockerfile does not install
  it, deliberately — it is a heavy dependency and the fixture scanner keeps the
  demo deterministic. Point it at `data/samples/vulnerable_app/` and it works;
  the scanner adapter is real (fixed argv, `subprocess` with a timeout, absolute
  paths resolved to repo-relative so fingerprints are machine-independent).
- **`ScannerKind.ZAP` and `DEPENDENCY` are declared but unimplemented.** The
  schema can carry them; no adapter exists.
- **The MCP server has no authentication.** No token check, no role check, no
  transport-level auth. Defensible on stdio (a pipe the client created, so no
  network peer can reach it), *not* defensible on streamable-http, which is
  therefore behind a compose profile that is off by default.
- **28 of the 36 HTTP endpoints are unauthenticated** — the read paths, by
  design. The write paths and all three approval endpoints are not.
- **The publisher is simulated.** It never contacts a git host: no token, no
  remote, no HTTP. A portfolio project must not be able to push to a real
  repository by accident.
- **stdout is the MCP protocol channel**, and `backend/core/logging.py` writes
  logs to stdout. There is a startup guard against a dirty stdout, but a runtime
  INFO line still lands on the wire. Routing logs to stderr is the real fix and
  is not done.
- **`data/samples/vulnerable_app/` is deliberately vulnerable.** Excluded from
  ruff, from mypy, and from import. Do not "fix" it.

More, including the unresolved tensions:
[docs/architecture.md §11](docs/architecture.md).

---

## Sprint coverage

Roadmap technologies for Sprint 6: **MCP**, **AutoGen**, **gRPC**, and
**SAST/DAST** (stretch).

- MCP — the whole `mcp_server/` package, both transports, both SDK majors
- AutoGen — `agents/autogen_engine.py`, three packages not the meta-package
- gRPC — `proto/`, the server, two client backends, 22 tests over a real socket
- SAST — a real Semgrep adapter. DAST (ZAP) is a schema placeholder only.

**Deliberately not built here:** Redis. An earlier revision of this project
declared a Redis service, a `SENTINEL_REDIS_URL`, a
`SENTINEL_SCAN_CACHE_TTL_SECONDS`, and a `fakeredis` dev dependency "for rate
limiting and a scan-result cache" — and implemented none of it. Redis is not in
this sprint's scope; the roadmap builds it properly in Sprint 4 and reuses it in
Sprints 7 and 10. A cache that is declared but absent is worse than no cache,
because a reader assumes it is protecting something. It has been removed, and
`docker-compose.yml` says why.

---

## Development

```bash
make install      # uv sync --extra dev + pre-commit install
make help         # all targets
make proto        # regenerate gRPC stubs after editing the .proto
make check        # the full quality gate
make evidence     # the patch-correctness harness -- see docs/evidence.md
```

`make` targets are Unix-only (Git Bash / WSL / macOS / Linux). On plain Windows
PowerShell, run the underlying commands — `.venv\Scripts\python -m ruff check .`,
`-m mypy .`, `-m pytest`.

Pre-commit runs the same three tools as CI: `ruff-format`, `ruff`, `mypy`. Not
pytest, because it needs a database for the integration half and is too slow for
a commit hook.

## Further reading

- [docs/evidence.md](docs/evidence.md) — **start here if you only read one thing.**
  What the three tiers measured, the eight defects they found, and the limits the
  engine does not cover
- [docs/evidence-results.md](docs/evidence-results.md) — the generated snapshot of
  `make evidence-all`, so the numbers can be checked without running anything
- [docs/architecture.md](docs/architecture.md) — why it is shaped this way, the
  known tensions, and what each test group is able to prove
- [docs/adr/](docs/adr/README.md) — four decisions with the rejected alternatives
- [backend/telemetry/README.md](backend/telemetry/README.md) — the frozen event
  contract for Sprint 11's Aegis
- [tests/integration/README.md](tests/integration/README.md) — how to run them,
  and the rule about overrides
- [backend/grpc_service/generated/README.md](backend/grpc_service/generated/README.md) —
  `make proto`

MIT licensed.
