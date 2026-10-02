"""Run the MCP server.

    python -m backend.scripts.run_mcp_server              # stdio, the default
    python -m backend.scripts.run_mcp_server --transport streamable-http

stdio is what Claude Desktop and most MCP hosts speak, and is the mode to
configure in an `mcpServers` block. `streamable-http` is there for a
deployment that would rather reach the server over the network.

With stdio, **stdout is the protocol channel**. That is why this module
configures logging to stdout in `main()` and then everything below logs at
DEBUG or above -- a single stray `print` or INFO line on stdout corrupts the
JSON-RPC stream and the client disconnects with an unhelpful parse error. This
is the most common way a new MCP server breaks, so the logging setup is the
first thing `main()` does rather than being left to the SDK.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from backend.config.settings import get_settings
from backend.core.logging import configure_logging, get_logger
from backend.mcp_server.server import (
    build_mcp_server,
    build_scanner_backend,
    mcp_session,
)

logger = get_logger(__name__)


async def serve(transport: str, host: str, port: int) -> None:
    """Open a session, build the server, and serve until the client disconnects."""
    settings = get_settings()

    async with mcp_session() as session:
        backend = await build_scanner_backend(settings)
        server = build_mcp_server(session, backend)

        if transport == "stdio":
            logger.info("serving MCP over stdio (Ctrl-D to disconnect)")
            await server.run_stdio_async()
        elif transport == "streamable-http":
            logger.info("serving MCP over streamable-http on %s:%s", host, port)
            await server.run_streamable_http_async(host=host, port=port)
        else:  # pragma: no cover - argparse restricts the choices
            raise SystemExit(f"unsupported transport: {transport}")


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description="Run the SentinelMCP tool server.")
    parser.add_argument(
        "--transport",
        choices=["stdio", "streamable-http"],
        default="stdio",
        help="MCP transport to serve (default: stdio).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host for streamable-http.")
    parser.add_argument("--port", type=int, default=8080, help="Bind port for streamable-http.")
    parser.add_argument(
        "--log-level",
        default=None,
        help="Override SENTINEL_LOG_LEVEL.",
    )
    args = parser.parse_args(argv)

    configure_logging(args.log_level or get_settings().log_level)

    # stdout is the stdio protocol channel. Confirm it before serving, because
    # the failure mode otherwise appears as a client-side JSON parse error with
    # nothing in this process's own logs.
    if args.transport == "stdio":
        _assert_clean_stdout()

    try:
        asyncio.run(serve(args.transport, args.host, args.port))
    except KeyboardInterrupt:
        logger.info("interrupted; shutting down")
    return 0


def _assert_clean_stdout() -> None:
    """Fail loudly if stdout has already been written to.

    Catches the common cause -- an import that printed a warning or a library
    that logged to the root logger before this module configured it -- and
    reports it here, where the operator is looking, instead of as a mystifying
    disconnect on the client side.
    """
    if sys.stdout.tell() > 0:
        print(
            "refusing to start: stdout is not clean, and it is the MCP stdio "
            "protocol channel. Set SENTINEL_LOG_LEVEL=INFO and check for a "
            "library logging to stdout at import time.",
            file=sys.stderr,
        )
        raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())
