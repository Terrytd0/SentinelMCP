# Integration tests

These tests use real infrastructure: a live PostgreSQL, and real gRPC sockets on
ephemeral ports. They are marked `integration` and they **skip themselves** when
the service they need is not reachable.

That is the whole design, and it is worth stating up front:

> **`pytest` with no flags and no services running must pass, and must be a safe
> thing to run.**

That is the only reason a suite stays run, and therefore the only reason it
protects anything. A test that fails because Postgres is not up is a test people
learn to ignore with `-k`, and then they are ignoring the assertions too.

```bash
pytest                        # everything; integration tests skip themselves
pytest -m "not integration"   # unit tests only, no services needed
pytest -m integration         # only the tests that need something real
```

## What "real" means here, per file

| file | needs | what a fake could not prove |
|---|---|---|
| `test_api_and_approval.py` (38) | PostgreSQL | the HTTP surface, the auth dependency, and the human approval gate end to end |
| `test_mcp_tools.py` (37) | PostgreSQL | the four tools through a real `MCPServer`, including protocol-level rejection |
| `test_grpc_scanning.py` (22) | a socket | the typed schema, the status codes, and that an error cannot be mistaken for an empty result |
| `test_pipeline_persistence.py` (20) | PostgreSQL | that the audit log is append-only and a duplicate fingerprint is rejected *by the database* |
| `test_scanner_transport.py` (12) | a socket | which `ScannerBackend` implementation each transport mode actually produces |
| `test_cross_loop_session.py` (7) | PostgreSQL | that two event loops do not share an engine's connection pool |
| `test_db_session_dependency.py` (8) | PostgreSQL | that a route's writes actually persist — see below |
| `test_schema_drift.py` (3) | PostgreSQL + `alembic` | that the live schema matches the models |

`test_api_and_approval.py`, `test_mcp_tools.py`, `test_pipeline_persistence.py`,
`test_schema_drift.py`, `test_cross_loop_session.py`, and
`test_db_session_dependency.py` need a database. `test_grpc_scanning.py` and
`test_scanner_transport.py` bind `port=0` and need nothing else.

## The skip mechanism

`SENTINEL_TEST_DATABASE_URL`, default
`postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test`.

```bash
docker compose up -d postgres
export SENTINEL_TEST_DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel_test
SENTINEL_DATABASE_URL=$SENTINEL_TEST_DATABASE_URL alembic upgrade head
pytest -m integration
```

The test database is created automatically by
`docker/postgres-init/01-create-test-db.sql` on first start, so `docker compose
up` is the only setup step.

The reachability probe (`_skip_if_unreachable`) is **synchronous**
(`psycopg2.connect(..., connect_timeout=3)`) and cached per URL. Both details are
deliberate:

- *Synchronous* because it is called from both an async fixture and a sync one,
  and under `asyncio_mode = "auto"` the sync one runs inside a live event loop
  where `anyio.run()` would raise `Already running asyncio in this thread`.
- *Cached* because ~120 tests would otherwise each open a throwaway connection
  just to discover the database is not there.

## The database is truncated, not recreated

`db_session` issues `TRUNCATE TABLE ... RESTART IDENTITY CASCADE` before each
test. Not `DROP`/`CREATE`, because Alembic owns the schema and re-running
migrations 120 times is slow; truncate is the only reset that is safe when the
schema is not yours. `RESTART IDENTITY` and `CASCADE` are both required — without
CASCADE a truncate fails on foreign keys, and without RESTART IDENTITY the
sequences keep advancing and every test sees a different ticket number.

The consequence worth knowing: **a test that leaves a row behind leaks it into
the next test.** Every test gets a clean slate, so a leak shows up as a
mysterious extra row rather than as a failure.

## The suite is hermetic

`tests/conftest.py` pins `SENTINEL_SCANNER_TRANSPORT=in_process` before any
application import.

Without that, the default `auto` transport would probe the configured gRPC target
and fall back — meaning a developer with `make scanner` running in another
terminal gets a *different transport* than CI, and the suite's result depends on
ambient network state. That is not hypothetical: it happened, and it produced a
confusing failure where a discovery endpoint returned nothing because a stray
scanner answered the probe.

The gRPC transport is still covered for real — by the two files that start their
own `ScannerServer` on an ephemeral port and point a client at it explicitly.

## Two rules the suite follows

**1. If a test overrides a dependency, some other test has to run the real one.**
Otherwise the override is not a test double, it is a hole.

Every route test overrides `get_db_session` with a session it manages itself,
which is right for testing a route and catastrophic for testing the dependency.
So `test_db_session_dependency.py` builds the app with **no override** and drives
real requests through it. That file exists because it caught two bugs that a
300-green suite missed:

- `get_session()` documented "commits on clean exit" and did not commit, so
  every write made through a route was discarded. `POST /scans` answered
  `{"new_findings": 8}` and left the table empty.
- `get_db_session()` tore its generator down with `asend(None)`, which raised
  `StopAsyncIteration` → `RuntimeError` on the way out of a coroutine. In a
  `finally`, that turned every authenticated request into a 500.

**2. No test module basename is reused across directories.** `tests/` has no
`__init__.py` (pytest does not need them), so two `test_rules.py` files in
different subdirectories collide under pytest's rootdir-based module naming. If
you add a file, check the name is unique.

## Above all of this: the smoke test

The suite is thorough, and it is still not the same as running the system.
`scripts/smoke_e2e.py` starts the gRPC scanning service and the FastAPI app as
two real OS processes on ephemeral ports, against a freshly created database, and
asserts 21 things a human would check:

```bash
python scripts/smoke_e2e.py
```

It runs the API with `SENTINEL_SCANNER_TRANSPORT=grpc`, so a regression that
makes the boundary decorative **fails loudly** instead of quietly proving
nothing. It also verifies the project's central claim end to end: a draft pull
request is blocked, an analyst gets 403, an approver succeeds, and the result is
still not merged.

Both of the session-dependency bugs were found by this script and not by
`pytest`. That is not a criticism of the suite — it is the argument for having
both.

## Adding an integration test

```python
import pytest

pytestmark = pytest.mark.integration


async def test_something(db_session: Any) -> None: ...
```

- Need a database: take `db_session` (or `seeded_session`, which runs a real
  scan first so the data satisfies production invariants — correct fingerprints,
  SLA deadlines, audit rows).
- Need the real app: take `real_client` from `test_db_session_dependency.py`'s
  pattern rather than the `client` fixture that overrides the dependency.
- Need a real socket: bind `port=0` and never a fixed port.
- Do not create fixtures outside `conftest.py` that shadow these ones.
