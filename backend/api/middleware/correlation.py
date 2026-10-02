"""ASGI middleware: request correlation ids and access logging.

`CorrelationIdMiddleware` does the one thing every request-scoped log line
needs to be useful: give it an id, and make sure the id is on the response so
a user can paste it into a support ticket and it can be found with one query
across the audit log, the telemetry stream, and the application log.

Uses the raw ASGI interface rather than `@app.middleware("http")` because the
correlation id has to be established for *every* scope including a 404 from
the router and an exception from a handler -- a `BaseHTTPMiddleware` that
raises before dispatching leaves the id unset for exactly the requests you most
want to trace.
"""

from __future__ import annotations

import time
import uuid

from starlette.requests import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.core.logging import get_logger

logger = get_logger(__name__)

CORRELATION_HEADER = "x-correlation-id"

# Injected into `request.scope` so a route or service can reach it without it
# having to be threaded through every signature.
SCOPE_KEY = "correlation_id"


class CorrelationIdMiddleware:
    """Attach a correlation id to every request and response.

    Reuses an inbound `X-Correlation-Id` when the client supplies one, so a
    caller's own trace id is preserved across the hop rather than being
    replaced with ours -- which is what makes this composable with an existing
    gateway.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        correlation_id = headers.get(CORRELATION_HEADER) or uuid.uuid4().hex
        scope[SCOPE_KEY] = correlation_id

        started = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                raw_headers = list(message.get("headers", []))
                raw_headers.append(
                    (CORRELATION_HEADER.encode("latin-1"), correlation_id.encode("latin-1"))
                )
                message = {**message, "headers": raw_headers}
            await send(message)

        try:
            await self._app(scope, receive, send_wrapper)
        finally:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            # One line per request at INFO, with the id first so it is the first
            # thing to grep for. The path is logged, never the query string --
            # a query string is the most common place a token ends up.
            logger.info(
                "%s %s -> %d in %.1fms correlation_id=%s",
                scope.get("method", "?"),
                scope.get("path", "?"),
                status_code,
                elapsed_ms,
                correlation_id,
            )


def correlation_id_from(request: Request) -> str:
    """The correlation id for a request, or a fresh one outside a request."""
    return str(request.scope.get(SCOPE_KEY) or uuid.uuid4().hex)


class AccessLogMiddleware:
    """Log unhandled exceptions with their type, then let them propagate.

    FastAPI's default handler turns an unexpected exception into a 500 with a
    bare body and logs the full traceback at ERROR -- which is right, but it
    does not say *which request* failed, and in a system where one request
    carries a correlation id across four tables, losing that link is painful.
    This adds the link and then re-raises, so the normal handler still runs.
    """

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        try:
            await self._app(scope, receive, send)
        except Exception as exc:
            logger.error(
                "unhandled exception path=%s correlation_id=%s error_type=%s",
                scope.get("path", "?"),
                scope.get(SCOPE_KEY),
                type(exc).__name__,
                exc_info=True,
            )
            raise
