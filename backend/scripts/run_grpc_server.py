"""Run the gRPC scanning service.

    python -m backend.scripts.run_grpc_server

A separate process from the API on purpose: scans are CPU-bound and
subprocess-heavy, and the API is I/O-bound. In a real deployment they scale
independently; here, running them separately is what lets the API keep serving
`/health` while a slow Semgrep scan is in flight.

The scanner registry is built once at startup and its availability is logged
before the port opens, so "the service came up but every scan fails" is
visible in the startup log rather than at the first request.
"""

from __future__ import annotations

import argparse
import asyncio
import signal

from backend.config.settings import get_settings
from backend.core.logging import configure_logging, get_logger
from backend.grpc_service.server import ScannerServer
from backend.scanners.registry import build_registry

logger = get_logger(__name__)


async def serve(host: str, port: int) -> None:
    """Start the gRPC server and block until SIGINT/SIGTERM."""
    settings = get_settings()
    registry = build_registry(settings)

    available = registry.available_kinds()
    if not available:
        # Not fatal -- the service can start and report itself unhealthy, which
        # is more useful than refusing to boot, because a client polling health
        # gets a clear "unavailable" rather than a connection refused.
        logger.error(
            "no scanners available; the service will report healthy=false. "
            "Set SENTINEL_ENABLED_SCANNERS (default: fixture) and check the "
            "scanner directories exist."
        )
    else:
        logger.info("scanners available: %s", [k.value for k in available])

    server = ScannerServer(
        registry,
        host=host,
        port=port,
        service_name=settings.app_name,
    )
    bound_port = await server.start()
    logger.info("bound port %d; press Ctrl-C to stop", bound_port)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # pragma: no cover - platform without proactor loop
            logger.debug("signal handler for %s unsupported on this platform", sig.name)

    await stop.wait()

    logger.info("draining in-flight scans (grace=5s)")
    await server.stop(grace=5.0)


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    parser = argparse.ArgumentParser(description="Run the SentinelMCP gRPC scanning service.")
    parser.add_argument(
        "--host", default=None, help="Bind host (default: SENTINEL_GRPC_SERVER_HOST)."
    )
    parser.add_argument(
        "--port", type=int, default=None, help="Bind port (default: SENTINEL_GRPC_SERVER_PORT)."
    )
    parser.add_argument("--log-level", default=None, help="Override SENTINEL_LOG_LEVEL.")
    args = parser.parse_args(argv)

    settings = get_settings()
    configure_logging(args.log_level or settings.log_level)

    host = args.host or settings.grpc_server_host
    port = args.port if args.port is not None else settings.grpc_server_port

    try:
        asyncio.run(serve(host, port))
    except KeyboardInterrupt:  # pragma: no cover - asyncio.run already consumed the signal
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
