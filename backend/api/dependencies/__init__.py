"""FastAPI dependencies.

`providers.py` holds the concrete dependency functions; this module re-exports
them under the `Annotated` aliases routes actually annotate with, so a route
module has a single import and a short signature.
"""

from __future__ import annotations

from backend.api.dependencies.providers import (
    AppSettings,
    CveServiceDep,
    ScannerBackendDep,
    TelemetryDep,
    get_app_settings,
    get_cve_service,
    get_scanner_backend,
    get_telemetry,
)
from backend.auth.dependencies import (
    AdminPrincipal,
    ApproverPrincipal,
    CurrentPrincipal,
    DbSession,
    Principal,
    require_admin,
    require_approver,
    require_principal,
)

__all__ = [
    "AdminPrincipal",
    "AppSettings",
    "ApproverPrincipal",
    "CveServiceDep",
    "CurrentPrincipal",
    "DbSession",
    "Principal",
    "ScannerBackendDep",
    "TelemetryDep",
    "get_app_settings",
    "get_cve_service",
    "get_scanner_backend",
    "get_telemetry",
    "require_admin",
    "require_approver",
    "require_principal",
]
