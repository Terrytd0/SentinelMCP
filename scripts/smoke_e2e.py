"""End-to-end smoke test across two real processes and a real gRPC socket.

Run with:  python scripts/smoke_e2e.py

This is deliberately not a pytest module. It starts the gRPC scanning service
and the FastAPI app as separate OS processes, drives the whole pipeline over
HTTP, and asserts on what a human would check:

    1. the API reports it is using the gRPC transport, not the in-process one
    2. a scan really crossed the wire and persisted findings
    3. the agent loop drafted a pull request that is blocked from auto-merge
    4. an analyst cannot approve it
    5. an approver can, and it STILL does not merge
    6. nothing merged itself

Steps 3-6 are the project's central claim, and the unit suite proves them
against fakes. This proves them against two processes and a database.

It exits non-zero on the first failure, so it works in CI as-is. Every service it
starts is torn down in `finally`, including on failure.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from backend.database.enums import UserRole

ROOT = Path(__file__).resolve().parent.parent
BASE = ""
DB_NAME = "sentinel_smoke"
DB = f"postgresql+asyncpg://sentinel:sentinel@localhost:5432/{DB_NAME}"

_checks = 0


def free_port() -> int:
    """An ephemeral port, released before we bind it.

    Picking fixed ports in a smoke test is how you get "address already in use"
    on a machine that happens to have something running -- including a stray
    `make scanner` from an earlier session, which is exactly what happened the
    first time this was run.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def check(label: str, condition: bool, detail: str = "") -> None:
    global _checks
    _checks += 1
    mark = "PASS" if condition else "FAIL"
    line = f"  [{mark}] {label}"
    if detail:
        line += f"\n         {detail}"
    print(line)
    if not condition:
        raise SystemExit(f"\nSMOKE FAILED at: {label}")


def env(**overrides: str) -> dict[str, str]:
    merged = {**os.environ, **overrides}
    for key in ("SENTINEL_TEST_DATABASE_URL",):
        merged.pop(key, None)
    return merged


def http(path: str, *, token: str = "", method: str = "GET", body: Any = None) -> Any:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        return {"__status": exc.code, "__body": exc.read().decode()[:400]}


def wait_for(url: str, seconds: int = 90) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except Exception:  # noqa: BLE001 - polling a socket that may not be up yet
            time.sleep(1)
    return False


def _reset_database() -> None:
    """Drop and recreate the smoke database, so a run starts from nothing.

    The script has to do this itself. A smoke test that inherits the previous
    run's findings is not repeatable: the agent has an attempt budget, so the
    second run through a finding is legitimately refused and the test fails for
    a reason that has nothing to do with the code under test.

    `WITH (FORCE)` terminates existing connections, which is what makes this
    safe to run while something is still attached.
    """
    import psycopg2

    admin_url = DB.rsplit("/", 1)[0] + "/postgres"
    admin_url = admin_url.replace("postgresql+asyncpg://", "postgresql://")

    # Not `with psycopg2.connect(...) as conn`: that context manager manages a
    # transaction, and DROP DATABASE cannot run inside one. Autocommit has to be
    # set on the bare connection, before any statement.
    connection = psycopg2.connect(admin_url, connect_timeout=10)
    try:
        connection.autocommit = True
        with connection.cursor() as cursor:
            cursor.execute(f'DROP DATABASE IF EXISTS "{DB_NAME}" WITH (FORCE)')
            cursor.execute(f'CREATE DATABASE "{DB_NAME}"')
    finally:
        connection.close()


def main() -> int:
    global BASE

    api_port = free_port()
    grpc_port = free_port()
    BASE = f"http://127.0.0.1:{api_port}"

    # The annotation is separate from the assignment on purpose. Written as
    # `spawn: dict[str, Any] = {...}` inside the branch, mypy discards it when it
    # evaluates the other branch as the reachable one -- and on Linux it does,
    # because `sys.platform` is resolved at type-check time. It then infers
    # `dict[str, bool]` from `{"start_new_session": True}` alone and no Popen
    # overload accepts that, so CI failed on a script that runs correctly on both
    # platforms. Declaring first pins the type on every platform.
    spawn: dict[str, Any]
    if sys.platform == "win32":
        # A new process group, so Ctrl-C does not race the cleanup handlers.
        spawn = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    else:
        spawn = {"start_new_session": True}

    processes: list[subprocess.Popen[Any]] = []
    try:
        print(f"0. resetting the {DB_NAME} database")
        _reset_database()

        print(f"1. applying the schema to {DB}")
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT,
            env=env(SENTINEL_DATABASE_URL=DB),
            check=True,
            capture_output=True,
        )

        print(f"2. starting the gRPC scanning service on :{grpc_port}")
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "backend.scripts.run_grpc_server",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(grpc_port),
                ],
                cwd=ROOT,
                env=env(SENTINEL_GRPC_SERVER_PORT=str(grpc_port)),
                **spawn,
            )
        )

        print(f"3. starting the FastAPI app on :{api_port}")
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "uvicorn",
                    "backend.main:app",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(api_port),
                ],
                cwd=ROOT,
                # `grpc` not `auto`: if this process is not genuinely talking to
                # the scanning service, the smoke test should fail loudly rather
                # than quietly fall back and prove nothing.
                env=env(
                    SENTINEL_DATABASE_URL=DB,
                    SENTINEL_SCANNER_TRANSPORT="grpc",
                    SENTINEL_GRPC_CLIENT_TARGET=f"127.0.0.1:{grpc_port}",
                    SENTINEL_TELEMETRY_SINK="file",
                ),
                **spawn,
            )
        )

        if not wait_for(f"{BASE}/health"):
            raise SystemExit("SMOKE FAILED: the API never became healthy")

        print("\n--- the boundary ---")
        health = http("/health")
        check(
            "the API reports itself healthy",
            health.get("status") == "ok" and health.get("database") == "reachable",
            json.dumps(health)[:260],
        )
        check(
            "and that the scanning service behind it is reachable",
            health.get("scanning_service", {}).get("healthy") is True,
            json.dumps(health.get("scanning_service"))[:220],
        )

        policy = http("/health/policy")
        check(
            "auto-merge is blocked and human approval is required",
            policy.get("auto_merge") == "blocked" and policy.get("human_approval_required") is True,
            json.dumps(policy)[:260],
        )

        targets = http("/scans/targets")
        check(
            "fixture targets are discoverable over gRPC",
            "app/" in targets.get("fixture_targets", []),
            f"fixture_targets={targets.get('fixture_targets')}",
        )

        print("\n--- the scan ---")
        # Scanning is an authenticated route, so this is the first request that
        # exercises the real `get_db_session` dependency in a real process.
        analyst_token = _login("smoke-analyst", UserRole.ANALYST)
        scan = http("/scans", token=analyst_token, method="POST", body={"target": "app/"})
        check("the scan succeeded", "__status" not in scan, json.dumps(scan)[:220])
        check(
            "findings were persisted",
            int(scan.get("total_findings", 0)) > 0,
            f"new={scan.get('new_findings')} refreshed={scan.get('refreshed_findings')} "
            f"total={scan.get('total_findings')} duration_ms={scan.get('duration_ms')}",
        )
        check(
            "the severity histogram is populated",
            sum(int(v) for v in (scan.get("counts_by_severity") or {}).values()) > 0,
            str(scan.get("counts_by_severity")),
        )

        print("\n--- the agent loop ---")
        remediation = http(
            "/remediations",
            token=analyst_token,
            method="POST",
            body={"finding_id": _pick(scan)},
        )
        check(
            "remediation was attempted",
            "__status" not in remediation,
            json.dumps(remediation)[:240],
        )
        check(
            "the outcome is a legitimate agent result, not an error",
            remediation.get("outcome") in {"approved", "rejected", "escalated"},
            f"outcome={remediation.get('outcome')} rounds={remediation.get('rounds')} "
            f"llm_calls={remediation.get('llm_calls')} cost={remediation.get('cost_usd')}",
        )
        pr_id = remediation.get("draft_pull_request_id")
        check(
            "a successful remediation produced a draft pull request",
            bool(pr_id) or remediation.get("outcome") != "approved",
            f"draft_pull_request_id={pr_id} outcome={remediation.get('outcome')}",
        )
        check(
            "cost attribution is consistent with the engine that ran",
            # Two engine implementations, and this checks the accounting holds for
            # whichever one ran rather than assuming one. The deterministic
            # engine is rule-based, so `llm_model` is None and the cost is
            # genuinely 0.0 -- recording a made-up model name there would be
            # worse than recording nothing.
            (
                remediation.get("llm_model") is not None
                and float(remediation.get("cost_usd", 0.0)) > 0.0
            )
            or (
                remediation.get("llm_model") is None
                and float(remediation.get("cost_usd", -1.0)) == 0.0
                and int(remediation.get("llm_calls", 0)) > 0
            ),
            f"engine={remediation.get('llm_model')} calls={remediation.get('llm_calls')} "
            f"tokens={remediation.get('tokens_used')} cost={remediation.get('cost_usd')}",
        )
        print("\n--- the human gate ---")
        if pr_id:
            pr = http(f"/pull-requests/{pr_id}")
            check(
                "the draft is blocked from auto-merge",
                pr.get("auto_merge_blocked") is True,
                f"status={pr.get('status')} auto_merge_blocked={pr.get('auto_merge_blocked')}",
            )
            check(
                "and it starts unapproved",
                pr.get("human_approved_at") in (None, ""),
                f"human_approved_at={pr.get('human_approved_at')}",
            )
            check(
                "its status is DRAFT, not MERGED",
                str(pr.get("status")) not in {"MERGED", "PullRequestStatus.MERGED"},
                f"status={pr.get('status')}",
            )

            refused = http(
                f"/pull-requests/{pr_id}/approve", token=analyst_token, method="POST", body={}
            )
            check(
                "an ANALYST cannot approve",
                refused.get("__status") in (401, 403),
                f"HTTP {refused.get('__status')}: {str(refused.get('__body'))[:120]}",
            )

            approver = _login("smoke-approver", UserRole.APPROVER)
            approved = http(
                f"/pull-requests/{pr_id}/approve", token=approver, method="POST", body={}
            )
            check("an APPROVER can approve", "__status" not in approved, json.dumps(approved)[:200])

            after = http(f"/pull-requests/{pr_id}")
            check(
                "and approving it STILL does not merge it",
                "MERGED" not in str(after.get("status")),
                f"status={after.get('status')} blocked={after.get('auto_merge_blocked')}",
            )
            check(
                "and it is still blocked from auto-merge afterwards",
                after.get("auto_merge_blocked") is True,
                f"auto_merge_blocked={after.get('auto_merge_blocked')}",
            )

        print("\n--- the audit trail ---")
        correlation = scan.get("correlation_id") or ""
        if correlation:
            entries = http(f"/audit/correlation/{correlation}")
            check(
                "the whole pipeline is auditable by correlation id",
                len(entries) > 0,
                f"{len(entries)} rows for {correlation}",
            )
        # `/audit` is a paged envelope, not a bare list.
        trail = http("/audit?limit=500")
        rows = trail.get("entries") or trail.get("audit") or trail.get("findings") or []
        if not rows and isinstance(trail, dict):
            # Fall back to whatever single list-valued key it used, so this does
            # not silently pass on an empty result.
            lists = [v for v in trail.values() if isinstance(v, list)]
            rows = max(lists, key=len) if lists else []
        actions = {str(row.get("action")) for row in rows if isinstance(row, dict)}
        check(
            "the whole pipeline is on the audit trail",
            # The dotted `entity.action` form, and specifically the
            # auto_merge_blocked event -- which is written by `system:policy`
            # rather than the approver, so its presence proves the guarantee is
            # recorded independently of whoever clicked approve.
            {
                "scan.run",
                "finding.created",
                "remediation.proposed",
                "pull_request.drafted",
                "pull_request.approved",
                "pull_request.auto_merge_blocked",
            }
            <= actions,
            f"{len(actions)} distinct action types: {sorted(actions)}",
        )
        blocked_row = next(
            (r for r in rows if r.get("action") == "pull_request.auto_merge_blocked"), None
        )
        check(
            "the auto-merge block was recorded by the policy engine, not the approver",
            blocked_row is not None and str(blocked_row.get("actor", "")).startswith("system:"),
            f"actor={blocked_row.get('actor') if blocked_row else None} "
            f"payload={blocked_row.get('payload') if blocked_row else None}",
        )

        print(f"\nSMOKE PASSED -- {_checks} checks")
        return 0
    finally:
        # CTRL_BREAK_EVENT on Windows because the children were created in their
        # own process group; SIGTERM everywhere else. Either way they get a
        # chance to drain, and a child that ignores it is killed.
        #
        # `getattr` rather than a bare attribute: CTRL_BREAK_EVENT exists only in
        # the Windows typeshed, so naming it directly is an attr-defined error on
        # every other platform even though the branch is unreachable there. The
        # default is what the non-Windows branch wanted anyway, so this is not a
        # behavioural change on either platform.
        stop_signal = getattr(signal, "CTRL_BREAK_EVENT", signal.SIGTERM)
        for process in reversed(processes):
            process.send_signal(stop_signal)
        for process in reversed(processes):
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover - cleanup path
                process.kill()


def _pick(scan: Any) -> str:
    """The first created finding's id, for the remediation step.

    Prefers a finding created by *this* scan so the remediation is operating on
    fresh state rather than whatever a previous run left behind.
    """
    created = scan.get("created") or []
    if created:
        return str(created[0]["finding_id"])
    # `/findings` is a paged envelope, not a bare list.
    queue = http("/findings?limit=1")
    rows = queue.get("findings") if isinstance(queue, dict) else queue
    if not rows:
        raise SystemExit("SMOKE FAILED: no findings to remediate")
    return str(rows[0]["finding_id"])


def _login(username: str, role: Any) -> str:
    """Ensure a throwaway user exists and mint a token for it.

    `/auth/login` only issues tokens for rows in `users`, so this inserts one.
    It uses the repository rather than raw SQL so the smoke test cannot drift
    from the application's own idea of a valid user, and it deliberately does
    *not* go through the password endpoint -- the point here is a role, not a
    login flow (which `tests/integration/test_api_and_approval.py` covers).
    """
    import asyncio

    from sqlalchemy import select

    from backend.auth.hashing import hash_password
    from backend.auth.jwt import create_access_token
    from backend.config.settings import get_settings, reload_settings
    from backend.database.models.audit_log import User
    from backend.database.session import session_scope

    # This function runs inside the parent process, which has not been pointed at
    # the smoke database the way the spawned children were.
    os.environ["SENTINEL_DATABASE_URL"] = DB
    reload_settings()

    async def _ensure() -> None:
        # One `asyncio.run` for both. Splitting them leaves the first loop's
        # asyncpg connections to be garbage-collected after their loop is gone,
        # which prints "Exception closing connection" noise that buries the real
        # output.
        from backend.database.session import dispose_engines

        async with session_scope() as session:
            # `User` has a UUID primary key, so the username is looked up as a
            # column rather than passed to `session.get` as a key.
            existing = await session.scalar(select(User).where(User.username == username))
            if existing is None:
                session.add(
                    User(
                        username=username,
                        role=role,
                        hashed_password=hash_password("smoke-test-password"),
                    )
                )
        await dispose_engines()

    asyncio.run(_ensure())

    # Asserted rather than imported-and-ignored: if the parent process were
    # pointed at the wrong database, every user check below would silently be
    # testing the wrong rows.
    assert get_settings().database_url == DB
    return create_access_token(subject=username, role=role)


if __name__ == "__main__":
    raise SystemExit(main())
