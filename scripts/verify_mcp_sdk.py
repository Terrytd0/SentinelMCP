"""Verify the MCP surface under whichever SDK major is installed.

Run it wherever the project is installed -- locally (SDK v1), or inside the
runtime image (SDK v2):

    python scripts/verify_mcp_sdk.py
    docker run --rm sentinelmcp:verify python scripts/verify_mcp_sdk.py

The container resolves **SDK v2** because `semgrep` is not installed there and
`semgrep` pins `mcp<2`; a local environment that has `semgrep` gets **v1**. So
the two environments exercise different branches of the import shim, and running
this in both is what proves
[ADR 004](../../docs/adr/004-mcp-sdk-major-version.md) actually holds rather
than merely compiling.

Deliberately not a pytest module: the runtime image has no pytest, and should
not. This runs under plain `python`.

**With** a reachable database it checks the tool round-trips too. **Without** one
it still checks everything that needs no data -- tool count, schemas,
descriptions, and protocol-level rejection -- and says which checks it skipped
rather than quietly passing them.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
from collections.abc import AsyncIterator
from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("SENTINEL_SCANNER_TRANSPORT", "in_process")
os.environ.setdefault("SENTINEL_TELEMETRY_SINK", "null")

from backend.config.settings import get_settings  # noqa: E402
from backend.grpc_service.client import InProcessScannerClient  # noqa: E402
from backend.mcp_server.server import (  # noqa: E402
    _server_class,
    build_mcp_server,
    mcp_sdk_major_version,
    sdk_tool_error_type,
)
from backend.scanners.registry import build_registry  # noqa: E402

EXPECTED_TOOLS = {"list_findings", "get_cve_details", "propose_fix", "create_ticket"}

_passed: list[str] = []
_skipped: list[str] = []
_failed: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(
        f"  [{'PASS' if condition else 'FAIL'}] {label}"
        + (f"\n         {detail}" if detail else "")
    )
    (_passed if condition else _failed).append(label)


def skip(label: str, why: str) -> None:
    print(f"  [SKIP] {label}\n         {why}")
    _skipped.append(label)


def _input_schema(tool: object) -> dict:
    """The attribute was renamed between majors; read whichever exists."""
    return getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {}) or {}


def _payload(result: object) -> dict:
    """The tool's JSON result, read from the text content block.

    `call_tool` returns two different shapes across the SDK majors:

        v1  a `(content_blocks, structured_dict)` tuple
        v2  a `CallToolResult` object

    and `structured_content` nests the union return under a `result` key in v2
    while being a separate tuple element in v1 -- so the two are not
    interchangeable. The text block is the shape both majors agree on, which is
    what `tests/integration/test_mcp_tools.py` reads too.
    """
    content = result[0] if isinstance(result, tuple) else getattr(result, "content", None)
    if not content:
        return {}
    text = getattr(content[0], "text", None)
    if not text:
        return {}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {}


@contextlib.asynccontextmanager
async def _maybe_session() -> AsyncIterator[object | None]:
    """A real session if the database is reachable, otherwise `None`.

    Yields `None` rather than raising: running this with no database is a
    legitimate use, and it should still check everything that needs no data while
    saying clearly what it skipped.

    Reachability is a real query, not a constructed session. SQLAlchemy connects
    lazily, so `session_scope()` against a host that does not resolve is built
    without complaint and only fails on the first statement. Probing by
    construction therefore reported "database reachable" for an unreachable one,
    the data-dependent checks ran anyway, and `gaierror` came back out of a tool
    call as a test failure instead of a skip -- which is the one thing this
    function exists to prevent.
    """
    from sqlalchemy import text

    from backend.database.session import session_scope

    context = session_scope()
    try:
        session = await context.__aenter__()
    except Exception as exc:  # noqa: BLE001 - "no database" is a normal outcome
        print(f"         (no database: {type(exc).__name__})")
        yield None
        return

    try:
        await session.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001 - see above
        print(f"         (no database: {type(exc).__name__})")
        await context.__aexit__(None, None, None)
        yield None
        return

    try:
        yield session
    finally:
        await context.__aexit__(None, None, None)


async def main() -> int:
    major = mcp_sdk_major_version()
    print(f"\nMCP SDK v{major}, server class {_server_class().__name__}\n")

    async with _maybe_session() as session:
        have_db = session is not None
        if not have_db:
            print("  (no database: data-dependent checks will be skipped)\n")

        # With no database there is no session to pass, and a `cast` is honest
        # about that: the checks that need data are skipped below, and the ones
        # that do not never touch the session at all.
        server = build_mcp_server(
            cast("AsyncSession", session),
            InProcessScannerClient(build_registry(get_settings())),
        )

        # --- the surface, which needs no data -----------------------------
        tools = await server.list_tools()
        names = {t.name for t in tools}
        check("exactly the four tools are exposed", names == EXPECTED_TOOLS, f"got {sorted(names)}")
        check(
            "every tool publishes an object input schema",
            all(_input_schema(t).get("type") == "object" for t in tools),
        )
        check(
            "every tool has an actionable description",
            all(len(t.description or "") > 40 for t in tools),
            f"shortest description: {min(len(t.description or '') for t in tools)} chars",
        )
        check(
            "the SDK's own tool error type resolves",
            isinstance(sdk_tool_error_type(), type),
            sdk_tool_error_type().__name__,
        )

        rejections: tuple[tuple[str, str, dict[str, Any]], ...] = (
            ("a missing required argument is rejected by the protocol", "get_cve_details", {}),
            ("an unknown tool name is rejected", "no_such_tool", {}),
        )
        for label, tool, arguments in rejections:
            try:
                await server.call_tool(tool, arguments)
                check(label, False, "the SDK accepted the call")
            except Exception as exc:  # noqa: BLE001 - any rejection is the point
                check(label, True, f"{type(exc).__name__}: {str(exc)[:80]}")

        # --- the round trips, which need data -----------------------------
        if not have_db:
            for label, why in (
                ("a known CVE round-trips with its advisory", "needs the CVE feed and a database"),
                ("an unknown CVE is a result, not an exception", "needs a database"),
                ("a malformed uuid is a structured error with a remedy", "needs a database"),
                ("an omitted filter is not an error", "needs a database"),
            ):
                skip(label, why)
        else:
            hit = _payload(await server.call_tool("get_cve_details", {"cve_id": "CVE-2023-46695"}))
            check(
                "a known CVE round-trips with its advisory",
                hit.get("found") is True,
                f"cvss_band={hit.get('cvss_band')} severity={hit.get('severity')}",
            )

            miss = _payload(await server.call_tool("get_cve_details", {"cve_id": "CVE-0000-0000"}))
            check(
                "an unknown CVE is a result, not an exception",
                bool(miss) and miss.get("found") is False,
                f"keys={sorted(miss)[:6]}",
            )

            bad = _payload(await server.call_tool("propose_fix", {"finding_id": "not-a-uuid"}))
            # The contract is not a particular error code -- it is that a bad
            # input comes back as a structured result carrying a remedy, rather
            # than as an exception the model would retry.
            check(
                "a malformed uuid is a structured error with a remedy",
                bool(bad.get("error")) and bool(bad.get("remedy")) and "correlation_id" in bad,
                f"error={bad.get('error')} remedy={str(bad.get('remedy'))[:55]}",
            )

            empty = _payload(await server.call_tool("list_findings", {}))
            check(
                "an omitted filter is not an error",
                isinstance(empty, dict) and "findings" in empty,
                f"keys={sorted(empty)[:6]}",
            )

    # --- verdict ----------------------------------------------------------
    ran = len(_passed) + len(_failed)
    print(f"\n  SDK v{major}: {ran} checks run, {len(_failed)} failed, {len(_skipped)} skipped")
    if _failed:
        print(f"  FAILED: {_failed}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
