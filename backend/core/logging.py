"""Application logging.

Idempotent `configure_logging()` called once at process start by every entry
point (`backend.main`, `backend.scripts.*`, the gRPC server, the MCP server).

Identifiers only at INFO: never snippets, patches, LLM prompts, or
credentials. The snippet of vulnerable source code and the diff an agent
drafts are exactly the things an attacker would want from a log aggregator,
and they are already stored in Postgres.
"""

from __future__ import annotations

import logging
import sys
from typing import Final

_CONFIGURED: bool = False
_FORMAT: Final[str] = "%(asctime)s %(levelname)s %(name)s :: %(message)s"
_DATEFMT: Final[str] = "%Y-%m-%dT%H:%M:%S%z"


def configure_logging(level: str = "INFO") -> None:
    """Install a single stdout handler at `level`. Safe to call repeatedly.

    Idempotent because several entrypoints call this defensively (the gRPC
    server, the MCP server, and FastAPI's lifespan all want logging set up)
    and adding a second handler would double every log line.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return

    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(logging.Formatter(fmt=_FORMAT, datefmt=_DATEFMT))

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level.upper())

    # These are chatty at DEBUG and drown out our own output during scans.
    logging.getLogger("grpc").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger. Use this instead of `print`."""
    return logging.getLogger(name)
