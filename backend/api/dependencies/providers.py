"""Shared FastAPI dependencies.

Thin wrappers that turn the settings-driven configuration into injected
dependencies. Keeping them here means a route signature says
`Depends(get_scanner_backend)` rather than reaching for a module singleton, so
substituting the backend in a test is a dependency override and not a
monkeypatch.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request

from backend.config.settings import Settings, get_settings
from backend.grpc_service.client import ScannerBackend
from backend.services.cve import CveService
from backend.telemetry import TelemetryClient


async def get_scanner_backend(request: Request) -> ScannerBackend:
    """The scanner backend, built once and cached on the app state.

    Built per-app rather than per-request: a `GrpcScannerClient` owns a
    channel, and opening a channel per request would pay a TCP handshake each
    time and exhaust gRPC's connection pool under load.

    Falls back to the in-process backend when no gRPC client was installed on
    the app at startup, so the API is usable in a single-process `pytest` run
    and in a local `uvicorn backend.main:app` with nothing else running.
    """
    backend = getattr(request.app.state, "scanner_backend", None)
    if backend is None:
        from backend.mcp_server.server import build_scanner_backend

        backend = await build_scanner_backend(get_settings())
        request.app.state.scanner_backend = backend
    return backend


ScannerBackendDep = Annotated[ScannerBackend, Depends(get_scanner_backend)]


def get_telemetry() -> TelemetryClient:
    """The process-wide telemetry client."""
    from backend.telemetry import get_telemetry_client

    return get_telemetry_client()


TelemetryDep = Annotated[TelemetryClient, Depends(get_telemetry)]


def get_cve_service() -> CveService:
    """A `CveService` reading the configured local feed."""
    return CveService(get_settings().cve_feed_dir + "/advisories.json")


CveServiceDep = Annotated[CveService, Depends(get_cve_service)]


def get_app_settings() -> Settings:
    """Settings, for the few routes that need to report configuration."""
    return get_settings()


AppSettings = Annotated[Settings, Depends(get_app_settings)]
