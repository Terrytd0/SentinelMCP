"""MCP protocol server wiring.

Builds an `MCPServer` (the `mcp` SDK v2 name for what was `FastMCP`) and
registers the four triage tools. Everything the tools need -- a database
session, a scanner backend -- arrives through the server's `lifespan`, so a
session is opened once per MCP connection rather than per tool call, and the
session is always closed on disconnect.

Transport is stdio by default, which is what Claude Desktop and most MCP hosts
speak. `streamable-http` is also available for a deployment that wants to reach
the server over the network -- see `run_mcp_server.py`.

Every tool body is a one-liner that validates arguments and delegates to
`SentinelTools`. The reason: `SentinelTools` is plain async Python that can be
called from a test without constructing a protocol server, so the business
logic is verified by unit tests and the registration is verified by a
round-trip test through the real `MCPServer`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from backend.config.settings import get_settings
from backend.core.logging import get_logger
from backend.database.session import session_scope
from backend.grpc_service.client import ScannerBackend
from backend.mcp_server.tools import (
    SERVER_INSTRUCTIONS,
    SERVER_NAME,
    SERVER_VERSION,
    CreateTicketArgs,
    CreateTicketResult,
    GetCveDetailsArgs,
    GetCveDetailsResult,
    ListFindingsArgs,
    ListFindingsResult,
    ProposeFixArgs,
    ProposeFixResult,
    SentinelTools,
    ToolError,
)
from backend.scanners.registry import build_registry

logger = get_logger(__name__)

SESSION_KEY = "sentinel_session"
BACKEND_KEY = "sentinel_scanner_backend"

# How long `scanner_transport=auto` waits for the scanning service before
# deciding it is not there. Deliberately much shorter than
# `grpc_timeout_seconds`: this is a start-up connectivity check, not a scan.
GRPC_PROBE_TIMEOUT_SECONDS = 2.0


def _server_class() -> type:
    """Return the MCP server class, whichever SDK major version is installed.

    The SDK renamed its high-level server between v1 and v2:

        v1  `mcp.server.fastmcp.FastMCP`
        v2  `mcp.server.mcpserver.MCPServer`   (FastMCP was renamed)

    Everything this project actually uses -- the constructor, `.tool()`,
    `.list_tools()`, `.call_tool()`, `.run_stdio_async()`,
    `.run_streamable_http_async()` -- kept the same names and semantics across
    the rename, so one import line is the only thing that differs.

    Supporting both is not gold-plating. A reviewer running this project
    installs whatever `pip` resolves, and `semgrep` (the roadmap's SAST stretch
    goal) pins `mcp<2` hard. Pinning the project to one major would mean the
    scanner and the MCP surface cannot both be installed in the same
    environment, which is worse than a fifteen-line import shim. The version in
    use is logged at startup and exposed on `/health/policy`, so it is never a
    mystery.
    """
    try:
        from mcp.server.mcpserver import MCPServer  # type: ignore[import-not-found]

        return MCPServer
    except ModuleNotFoundError:
        from mcp.server.fastmcp import FastMCP  # type: ignore[attr-defined]

        return FastMCP


def sdk_tool_error_type() -> Any:
    """The SDK's own tool-argument error type, for whichever major is installed.

    The SDK raises this when *arity or type* validation fails, before a tool
    body runs -- as distinct from our own `ToolError`, which covers semantic
    validation. Exposed here so tests do not have to branch on the version.
    """
    if mcp_sdk_major_version() >= 2:
        from mcp.server.mcpserver.exceptions import ToolError as _SdkToolError

        return _SdkToolError

    from mcp.server.fastmcp.exceptions import ToolError as _SdkToolErrorV1

    return _SdkToolErrorV1


def mcp_sdk_major_version() -> int:
    """1 or 2 -- reported by `/health/policy` so a deployment knows which.

    Detected by *trying the v2 import* rather than by reading a version string,
    because the v2 `ModuleNotFoundError` is a deliberate, explicit error message
    from the SDK itself, and it is what actually determines which API exists.
    """
    import importlib.util

    if importlib.util.find_spec("mcp.server.mcpserver") is not None:
        return 2
    return 1


async def build_scanner_backend(settings: Any | None = None) -> ScannerBackend:
    """Build the scanner backend this process will use, per `scanner_transport`.

    The three callers want different things, and the setting is how they say so
    rather than three call sites each hard-coding a decision:

        "grpc"        the scanning service is a separate process and must be
                      reachable. A dead target is a startup failure, not a
                      silent degradation -- a deployment that *thinks* it is
                      crossing the gRPC boundary but is not is worse than one
                      that fails loudly.
        "in_process"  one process does everything. The test suite and a bare
                      `uvicorn backend.main:app` need this to work with no
                      second process and no port.
        "auto"        try the real boundary, fall back to in-process when the
                      health probe finds nothing listening.

    "auto" is the default because a portfolio reviewer should be able to
    `uvicorn backend.main:app` and have it work, while `docker compose up` --
    which runs a real `scanner` service -- genuinely crosses the wire. The
    fallback is logged at WARNING with the reason, so "which transport am I
    actually on?" is answerable from the logs and from `GET /health/ready`
    rather than requiring a guess.
    """
    resolved = settings or get_settings()
    transport = getattr(resolved, "scanner_transport", "auto")

    if transport == "in_process":
        from backend.grpc_service.client import InProcessScannerClient

        return InProcessScannerClient(build_registry(resolved))

    from backend.grpc_service.client import GrpcScannerClient, InProcessScannerClient

    target = str(getattr(resolved, "grpc_client_target", "") or "")
    timeout = float(getattr(resolved, "grpc_timeout_seconds", 30.0))

    if transport == "grpc":
        client = GrpcScannerClient(target, timeout_seconds=timeout)
        logger.info("scanner transport: gRPC target=%s timeout=%ss", target, timeout)
        return client

    # The probe gets its own, much shorter deadline than a scan would. A
    # stdio MCP client spawns this process and waits for it to speak, so a
    # fallback that took the full 30s scan timeout to notice nothing is
    # listening would look like a hung server. Refusing to connect is fast;
    # scanning is allowed to be slow.
    client = GrpcScannerClient(target, timeout_seconds=GRPC_PROBE_TIMEOUT_SECONDS)
    probe = await client.health()
    if probe.get("healthy"):
        # Swap in a client with the real scan timeout now that we know the
        # service is there.
        await client.close()
        client = GrpcScannerClient(target, timeout_seconds=timeout)
        logger.info(
            "scanner transport: gRPC target=%s scanners=%s", target, probe.get("available_scanners")
        )
        return client

    await client.close()
    reason = probe.get("grpc_code") or probe.get("error") or "health check returned unhealthy"
    logger.warning(
        "scanner transport: gRPC target=%s is not answering (%s); "
        "falling back to the in-process scanner registry. Set "
        "SENTINEL_SCANNER_TRANSPORT=grpc to make this a hard failure instead.",
        target,
        reason,
    )
    return InProcessScannerClient(build_registry(resolved))


@asynccontextmanager
async def mcp_session() -> AsyncIterator[AsyncSession]:
    """Open one database session for the life of an MCP connection.

    Per-connection rather than per-call because opening a session is real work
    (a pool checkout) and an agent making four related tool calls should not
    pay for four of them. The engine is loop-scoped and the MCP server owns
    its loop for the connection's lifetime, so a single session is safe.
    """
    context = session_scope()
    session = await context.__aenter__()
    try:
        yield session
    finally:
        await context.__aexit__(None, None, None)


@asynccontextmanager
async def mcp_lifespan(server: Any) -> AsyncIterator[dict[str, Any]]:
    """Protocol-server lifecycle: startup logging and shutdown cleanup.

    The database session is *not* managed here. It is opened explicitly by
    `run_server()` and handed to `build_mcp_server()`, because the tool bodies
    are constructed once and need a session they can close over -- a session
    published through the lifespan context would have to be re-fetched by name
    on every call, which is the indirection this design is avoiding.
    """
    from backend.core.asyncio_utils import shutdown_background_loop
    from backend.database.session import dispose_engines

    settings = get_settings()
    registry = build_registry(settings)
    logger.info(
        "MCP server starting version=%s scanners_available=%s database=%s",
        SERVER_VERSION,
        [k.value for k in registry.available_kinds()],
        _safe_db_label(settings),
    )
    try:
        yield {"scanners_available": [k.value for k in registry.available_kinds()]}
    finally:
        await dispose_engines()
        shutdown_background_loop()
        logger.info("MCP server stopped")


def _safe_db_label(settings: Any) -> str:
    """The database host, with any password stripped.

    A settings value is a DSN, and a DSN can carry a password. Logging the host
    is useful for "which am I actually talking to"; logging the DSN is how
    credentials end up in a log aggregator.
    """
    return settings.database_url.rsplit("@", 1)[-1] if "@" in settings.database_url else "unset"


def build_mcp_server(session: AsyncSession, scanner_backend: ScannerBackend) -> Any:
    """Build an `MCPServer` with the four tools registered.

    Takes the session and backend explicitly rather than reading them from the
    lifespan context, so a test can construct a fully wired server and drive it
    through the real protocol with a real session. That is what
    `tests/integration/test_mcp_tools.py` does.
    """
    server_class = _server_class()
    tools = SentinelTools(session, scanner_backend)

    # Constructor kwargs are filtered against the installed signature rather
    # than hard-coded per branch. `version` is the one real difference between
    # the majors -- v1's `FastMCP` has no version parameter -- and filtering
    # keeps the call site free of a version check while still passing
    # `instructions` and `name`, which both majors accept.
    #
    # `signature()` on the *class* is what we want: it reports the constructor
    # parameters minus `self`. Reaching for `server_class.__init__` directly
    # gets the same set but mypy rejects it (an instance's `__init__` may come
    # from an incompatible subclass, so reading it off the object is unsound).
    import inspect

    accepted = set(inspect.signature(server_class).parameters)
    requested = {
        "name": SERVER_NAME,
        "version": SERVER_VERSION,
        "instructions": SERVER_INSTRUCTIONS,
    }
    supported = {key: value for key, value in requested.items() if key in accepted}
    dropped = sorted(set(requested) - set(supported))
    if dropped:
        logger.info("mcp sdk v%s does not accept %s", mcp_sdk_major_version(), dropped)

    server: Any = server_class(**supported)

    @server.tool(
        name="list_findings",
        description=(
            "List open security findings from the triage backlog, most urgent first. "
            "Start here. Supports severity, status, and scanner filters plus a text "
            "query. Snippets are omitted for speed; call this on one finding's id to "
            "see the code."
        ),
    )
    async def list_findings(
        severity: list[str] | None = None,
        status: list[str] | None = None,
        scanner: list[str] | None = None,
        query: str | None = None,
        include_closed: bool = False,
        limit: int = 20,
    ) -> ListFindingsResult | ToolError:
        args = _validate(
            ListFindingsArgs,
            severity=severity,
            status=status,
            scanner=scanner,
            query=query,
            include_closed=include_closed,
            limit=limit,
            tool="list_findings",
        )
        if isinstance(args, ToolError):
            return args
        return await tools.list_findings(args)

    @server.tool(
        name="get_cve_details",
        description=(
            "Look up a CVE advisory: description, CVSS score and band, affected "
            "products and fixed versions, and the recommended remediation. Also "
            "returns every finding in this backlog that references the CVE. Reads a "
            "local advisory feed, so a very recent CVE may return found=false."
        ),
    )
    async def get_cve_details(cve_id: str) -> GetCveDetailsResult | ToolError:
        args = _validate(GetCveDetailsArgs, cve_id=cve_id, tool="get_cve_details")
        if isinstance(args, ToolError):
            return args
        return await tools.get_cve_details(args)

    @server.tool(
        name="propose_fix",
        description=(
            "Have the developer/reviewer agent pair draft a remediation for one "
            "finding and open a DRAFT pull request. This runs an autonomous agent "
            "loop and costs LLM tokens. Returns outcome=approved (draft PR opened), "
            "rejected (reviewer refused the patch), or escalated (agents could not "
            "converge). THIS NEVER MERGES: a human approver must authorize the pull "
            "request and a human must merge it in the git host. Do not tell a user a "
            "vulnerability is fixed after calling this -- it has only been proposed."
        ),
    )
    async def propose_fix(
        finding_id: str,
        correlation_id: str | None = None,
        open_ticket: bool = True,
    ) -> ProposeFixResult | ToolError:
        args = _validate(
            ProposeFixArgs,
            finding_id=finding_id,
            correlation_id=correlation_id,
            open_ticket=open_ticket,
            tool="propose_fix",
        )
        if isinstance(args, ToolError):
            return args
        return await tools.propose_fix(args)

    @server.tool(
        name="create_ticket",
        description=(
            "Open a tracked remediation ticket for a finding so a human analyst "
            "picks it up. Use after deciding a finding needs work that no draft PR "
            "covers, or to hand an escalated finding to a person."
        ),
    )
    async def create_ticket(
        finding_id: str,
        title: str,
        description: str = "",
        assignee: str | None = None,
        priority: str | None = None,
    ) -> CreateTicketResult | ToolError:
        args = _validate(
            CreateTicketArgs,
            finding_id=finding_id,
            title=title,
            description=description,
            assignee=assignee,
            priority=priority,
            tool="create_ticket",
        )
        if isinstance(args, ToolError):
            return args
        return await tools.create_ticket(args)

    logger.info(
        "MCP server built with 4 tools (session-scoped, no remote git access, sdk v%s)",
        mcp_sdk_major_version(),
    )
    return server


def _validate(model: type, /, *, tool: str, **kwargs: Any) -> Any:
    """Validate tool arguments, returning a `ToolError` on failure.

    A validation failure is returned as a *result*, not raised, so the client
    gets a structured explanation it can show the user. `ToolError` is what
    every other failure in this module returns too, so a client handles one
    shape.

    The two validation layers are distinct and both are wanted. The SDK checks
    *arity and type* from the function signature and raises `ToolError` before
    the body runs; this checks *semantics* -- that `severity="apocalyptic"` is
    not a severity -- which the signature's `list[str]` cannot express. The
    second layer is the one that produces our `ToolError`.
    """
    from pydantic import ValidationError

    try:
        return model(**kwargs)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc']) or 'input'}: {e['msg']}" for e in exc.errors()
        )
        logger.info("mcp tool %s rejected arguments: %s", tool, problems)
        return ToolError(
            error="invalid_arguments",
            detail=problems,
            remedy=f"Check the argument names and types for {tool} and try again.",
        )
