# CLAUDE.md

Orientation for an AI assistant (or a new contributor) working in this
repository. The README explains what the system does; this explains how the code
is arranged and which rules are load-bearing rather than incidental.

Read `docs/architecture.md` and `docs/adr/README.md` before changing anything
structural. The ADRs record rejected alternatives, so you do not have to
re-derive them — and re-proposing one is how they get undone.

## The one rule

**The system cannot merge its own code.**

Not "it does not by default." There is no code path, no flag, and no setting that
enables a merge. If a change makes merging possible, that change is the bug.

`tests/unit/policy/test_safety_rails.py` enforces this by AST-walking every
module under `backend/`. Before you touch anything in `policy/`, `services/
approvals.py`, `services/publisher.py`, or the pull-request repository, read that
test — it is the specification, and it will fail in a way that tells you
exactly which rule you broke.

## Layout, and the direction dependencies point

```
api/  ──▶  services/  ──▶  repositories/  ──▶  models/
  │            │                                   
  └──▶ auth/  ┌──┴──┐                         
              │     │                          
         agents/  scanners/                  
              │     │                          
        policy/  grpc_service/                 
              │     │                          
              └─ telemetry/                     
```

Dependencies point downward only. `services/` never imports `api/`.
`repositories/` never imports `services/`. If you find yourself wanting to, the
thing that is in the wrong layer is usually the thing to move.

Cross-cutting, importable from anywhere: `policy/` (safety gates), `telemetry/`
(the event contract), `core/` (clock, ids, logging), `evidence/` (measured
patch-correctness evidence; **not** in the request path — nothing imports it, and
it is the one package allowed to reach sideways into both `agents/` and
`scanners/`, because verifying a patch means running it through both and a
verification component in the request path that reaches sideways would be a real
layering violation).

## The load-bearing invariants

These are not style. Breaking one produces a bug that the test suite may or may
not catch, and several of them did.

**1. The database session commits exactly once, in one place.**
`backend/database/session.py` owns a `transaction()` context manager.
`get_session`, `session_scope`, and `auth/dependencies.py::get_db_session` are
all thin wrappers over it. Do not add a fourth caller that opens a session and
manages the commit itself.

This module has contained two severe bugs, both invisible to a green suite:
`get_session` not committing at all (every API write silently rolled back), and
`get_db_session` driving a generator with `asend(None)` (every authenticated
request 500'd). `tests/integration/test_db_session_dependency.py` is the only
test that runs the real dependency, because every other test overrides it.

**2. The engine is keyed by event loop.**
`get_engine()` caches by `asyncio.get_running_loop()`. This process runs two
long-lived loops (FastAPI's, and the background loop `run_sync` uses). A
process-wide engine eventually hands a connection created on one loop to a caller
on the other.

**3. `auto_merge_blocked` is only ever `True`.**
Column default `True`, hardcoded `True` at every insert, and the AST test asserts
no assignment anywhere sets it otherwise.

**4. Exactly one function writes `PullRequestStatus.MERGED`.**
`ApprovalService.record_external_merge`. It records a human's action and contacts
no git host. The AST test asserts there is no second writer.

**5. The engine cache is keyed by content, not identity.**
`compute_fingerprint` excludes the snippet, line numbers, description, and
severity. A finding is a *kind of problem at a place*. If you "improve" the
fingerprint to include the line number, every re-scan creates new findings and
restarts every SLA clock.

**6. `PolicyError` / policy gates are re-evaluated, never trusted from a flag.**
`RemediationService._assert_allowed` calls `evaluate_auto_remediation()` fresh
rather than reading `findings.auto_remediation_eligible`. The stored flag was
written at scan time; the finding may have been closed or retried since.

**7. Path checks resolve, they do not `startswith`.**
`_path_within_roots` resolves both sides to absolute posix paths with `..`
collapsed. `app/../../etc/passwd` starts inside an allowed root and escapes it.
An empty `source_roots` fails **closed**.

**8. Generated code is never edited.**
`backend/grpc_service/generated/` is `protoc` output, excluded from ruff and
mypy. Change the `.proto` and run `make proto`. Nothing will warn you if the
committed output is stale — the suite fails on an import error instead.

**9. Telemetry cannot fail the operation it measures.**
Every emit is wrapped; a failing sink is counted and disabled after 5
consecutive failures. `measure()` records status and re-raises — it never
suppresses. The six core event fields are frozen for Sprint 11's Aegis; see
`backend/telemetry/README.md` before adding a field.

**10. A rewrite declares the language its *replacement* is valid in, and the
gate fails closed.** `Rewrite.languages` is not the language the pattern matches —
that asymmetry was the bug. `move-secret-to-environment` matched Go's `const Key =
"..."` and emitted `os.environ[...]`, which does not compile, and the test for it
*asserted that was correct* on a `.go` path. An unrecognised extension matches
nothing. Found by `backend/evidence/tier2.py`.

**11. Documented limits are measured, not asserted.** The old suite asserted that
each rewrite's `description` was non-empty, which is documentation checking
dressed as correctness checking. `backend/evidence/` now applies each rewrite to a
real vulnerable module, runs a real exploit against it, and re-checks with an
independent analyser. When you add a rewrite, add a case to
`backend/evidence/execution.py` or it is not covered — and the report will say so.

**12. The reviewer's parse check only runs on like-for-like replacements.** It
reconstructs the patched source from the diff's added lines, which is only the
patched file when one line became one line. Running it on a multi-line diff made it
object to 15 of 18 real upstream fixes, for reasons about the diff's shape rather
than the patch's correctness. Found by `backend/evidence/tier3.py`.

**13. The loop is shown a block, not the scanner's line.** A scanner reports one
line; the reviewer judges a multi-line patch. `backend/scanners/snippet.py`
widens it to the finding's enclosing indented block, bounded by
`SENTINEL_REMEDIATION_SNIPPET_MAX_LINES`, and records which strategy it used on
the audit row. It does **not** widen `findings.snippet` -- a finding records what
the detector found, and the report must not overstate its precision. The residual
rejection rate is not a context problem and is not worth optimising away; see
[docs/evidence.md](docs/evidence.md).

## Commands

```bash
make check              # format-check + lint + typecheck + test  (what CI runs)
make test               # pytest; integration tests skip themselves
make test-integration   # needs postgres, see tests/integration/README.md
make smoke              # two real processes, 21 checks
make verify-mcp         # the MCP surface under whichever SDK major is installed
make evidence           # 3 tiers of measured patch correctness, ~15s
make evidence-all       # the same, all 19 real advisories
make proto              # regenerate gRPC stubs
python scripts/smoke_e2e.py
python scripts/verify_mcp_sdk.py
python scripts/evidence_report.py
```

CI runs `make check`, the container and MCP jobs, and **tier 1 of the evidence
harness only**. Tiers 2 and 3 are excluded on purpose: they need semgrep.dev and
seven upstream clones, so a network blip would train contributors to re-run red
builds. Tier 1 needs no network, no database and no key, and runs in about two
seconds. If you change a rewrite, that job is what notices.

`make` is Unix-only. On plain Windows PowerShell use the venv directly:
`.venv\Scripts\python -m ruff check .`, `-m mypy .`, `-m pytest`.

## Testing rules

**Rule 1 — a bare `pytest` with nothing running must pass, and must be safe to
run.** Integration tests skip themselves when a service is unreachable. Never
make a test fail because Postgres is down.

**Rule 2 — if a test overrides a dependency, some other test has to run the real
one.** Otherwise the override is not a test double, it is a hole. This rule
exists because two severe bugs shipped behind a fully green suite.

**Rule 3 — no test module basename is reused across directories.** There are no
`__init__.py` files under `tests/`, so pytest's rootdir-based module naming
collides.

**Rule 4 — the suite is hermetic.** `tests/conftest.py` pins
`SENTINEL_SCANNER_TRANSPORT=in_process`. Do not let a test's result depend on
whether something happens to be listening on port 50051.

**Rule 5 — prefer a real socket to a mock for the gRPC boundary.** Bind `port=0`.
A mocked gRPC test asserts that the mock was called.

**Rule 6 — a verification harness that cannot fail is worse than none.** Any test
that measures the system has to be able to report red. Three mechanisms in
`backend/evidence/` exist only for that: the exploit must land on the *unpatched*
code first, the mutation control re-applies every diff in reverse and requires the
exploit to come back, and a Tier 2 rule set that fires on nothing is `vacuous` and
exits non-zero. `semgrep --config <not-a-rule> --json` exits 0 and reports zero
findings, which is indistinguishable from a clean scan — four of eleven guessed
rule ids behaved that way while this was being built.

## When you add a feature

- **A new MCP tool** — add it to `backend/mcp_server/tools.py`, register it in
  `server.py`, and return errors as a `ToolError` rather than raising. Return
  "not found" as a *result*, not an exception: an agent that gets an exception
  for an unremarkable lookup learns to retry, and one that gets a result learns
  to move on. Every error should carry a `remedy`. Update the count assertion in
  `tests/integration/test_mcp_tools.py` — there are exactly four on purpose — and
  add the tool to `scripts/verify_mcp_sdk.py` if it has a data-backed call.
- **Anything touching the MCP surface** — run `make verify-mcp` locally *and*
  the same script inside the image. The local venv is on SDK v1 and the image is
  on v2, so one of the two is always testing the branch you are not looking at.
  CI runs both. See `backend/mcp_server/README.md`.
- **A new policy gate** — add it to `evaluate_auto_remediation` in
  `policy/rules.py`, in cheapest-check-first order (the order is also the
  explanation order a refusal reports), add a `AutoRemediationRefusal` member,
  and cover it in `test_safety_rails.py`. Policy gates safety, never priority.
- **A new scanner** — subclass `Scanner`, implement `kind` / `available` /
  `unavailable_reason` / `scan(target)`, register in `_FACTORIES`. `scan()`
  returns rather than raises for "found nothing", and raises
  `ScannerUnavailableError` when it cannot run. That distinction is the whole
  point: an unavailable scanner must never look like a clean scan.
- **A new telemetry field** — additive fields are safe, core fields are frozen.
  Read `backend/telemetry/README.md` first. `error_type` is a class name, never a
  message.
- **A new rewrite** — add it to `_REWRITES` with `languages` naming where its
  *replacement* compiles, then add a case to `backend/evidence/execution.py` that
  applies it to a real vulnerable module and runs a real exploit against both
  versions. The `description` must state the limits and the harness must *measure*
  them; a rewrite with no evidence case shows up in the report as uncovered, which
  is the correct outcome. Do not add a rule whose fix is "and a human finishes
  the job" unless the fix is a single, mechanical, well-defined step — that was
  how `math-rand-to-crypto-rand` ended up emitting a Python name into a Go file.
- **A new table** — add the model, then a migration. `alembic check` runs in CI
  and will fail on drift. The initial migration's `downgrade()` is explicit;
  keep it that way.

## Things that will look wrong but are not

- **`data/samples/vulnerable_app/` is deliberately vulnerable.** Excluded from
  ruff, mypy, and import. It is a real Semgrep target. Do not fix it.
- **The `publisher` never contacts a git host.** No token, no remote, no HTTP.
  Simulated on purpose: a portfolio project must not be able to push to a real
  repository by accident.
- **`ProposalStatus` has no `MERGED`.** Merging is a `PullRequest` state, and
  putting it on the proposal would imply the agent can reach it.
- **The Alembic migration file is excluded from ruff** (`alembic/versions`).
- **stdout is the MCP stdio protocol channel.** `run_mcp_server.py` configures
  logging first and refuses to start on a dirty stdout. See
  `docs/architecture.md` §11 for the unresolved part of this.
- **The AutoGen engine's module docstring describes two single-agent chats, not
  a team.** It originally described a `RoundRobinGroupChat` of both agents with a
  custom `TerminationCondition`, which was never what the code did. The roles are
  kept separate *on purpose* so the reviewer is not anchored on the developer's
  reasoning.

## Two dead things that were removed, and why

If you are tempted to add them back, the reasoning is recorded:

**Redis** — was declared as a compose service, a `SENTINEL_REDIS_URL`, a
`SENTINEL_SCAN_CACHE_TTL_SECONDS`, and a `fakeredis` dev dependency, all
"for rate limiting and a scan-result cache", and implemented none of it. Redis is
not in this sprint's scope; the roadmap builds it in Sprint 4 and reuses it in
Sprints 7 and 10. A cache that is declared but absent is worse than no cache.

**`SENTINEL_REMEDIATION_SOURCE_ROOTS` was read by nothing** and silently fell
back to a hardcoded tuple with identical values, so nothing failed and the
configurability was fictional. It is now threaded through both call sites.

**`math-rand-to-crypto-rand`** — the rule was removed, not patched. Its pattern
was Go's `rand.Intn(` and its replacement was Python's `secrets.randbelow(`, so it
emitted a Python name into a Go file, and Tier 2's independent scan is what found
it. It could not be repaired because `math/rand.Int(n) int` and
`crypto/rand.Int(rand.Reader, n) (*big.Int, error)` have incompatible signatures.
CWE-338 now escalates to a human. Adding it back is the mistake.

## Where the interesting arguments are

- `docs/adr/001-safety-rails-and-human-approval.md` — the human gate, and the
  auto-merge threshold that was refused
- `docs/adr/002-autogen-vs-langgraph-crewai.md` — why the reviewer is a separate
  agent, and when LangGraph would be the right answer
- `docs/adr/003-grpc-scanning-boundary.md` — the status-code mapping, and two
  ways the boundary was wrong first
- `docs/evidence.md` — what the three evidence tiers found, including the seven
  defects and the two bugs the harness found in itself
- `docs/architecture.md` §12 — the two session bugs, and what each test group is
  uniquely able to prove
- `docs/architecture.md` §13 — the reviewer's rejection rate on real fixes, and
  the unresolved argument about what it is for
