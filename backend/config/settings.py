"""Environment-driven configuration.

Every tunable in SentinelMCP is declared here and nowhere else. Nothing
outside `backend/config/` reads `os.environ` directly, so the full set of
knobs a deployment can turn is one readable file.

Settings field names mirror their environment variables exactly, lowercased
(`database_url` <- `DATABASE_URL`), so there is never a translation layer to
get wrong.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings, loaded from the environment and `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # Every variable is namespaced `SENTINEL_*`. Without the prefix,
        # `LOG_LEVEL`, `APP_ENV`, and `TARGET_REPO` would be read out of the
        # host environment, and a developer's shell would silently change how
        # the service behaves depending on which directory they launched it
        # from. Namespacing also leaves the `SENTINEL_` prefix as a single
        # string to search for when debugging "where is this value coming from".
        env_prefix="SENTINEL_",
    )

    # --- Application ---
    app_name: str = "SentinelMCP"
    app_env: str = "development"
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"

    # --- Database (system of record) ---
    # Defaults to the docker-compose service name so `docker compose up` needs
    # no override; override for a local install via DATABASE_URL.
    database_url: str = "postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel"
    # Used by Alembic, which runs synchronously and therefore cannot use the
    # asyncpg driver. Derived from database_url when not set explicitly.
    database_url_sync: str = ""
    db_echo: bool = False
    db_pool_size: int = 5
    db_max_overflow: int = 10

    # --- Auth ---
    jwt_secret: str = "dev-only-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    # Auth is entirely optional. With auth disabled the API and MCP server run
    # open, which is the only sensible posture for a local `docker compose up`
    # demo -- and the ONLY posture that is never acceptable in a real
    # deployment. Startup refuses to disable auth when app_env == "production".
    auth_enabled: bool = True

    # --- gRPC scanning service ---
    grpc_server_host: str = "0.0.0.0"
    grpc_server_port: int = 50051
    # In-network address of the scanning service, e.g. "scanner:50051" under
    # Docker Compose or "localhost:50051" for two local terminals.
    grpc_client_target: str = "scanner:50051"
    grpc_timeout_seconds: float = 30.0
    # How this process reaches the scanners. See
    # `backend/mcp_server/server.py::build_scanner_backend` and
    # docs/adr/003-grpc-scanning-boundary.md.
    #   "grpc"       always dial the scanning service; fail if it is not there
    #   "in_process" call the scanner registry directly, no wire at all
    #   "auto"       dial it, and fall back to in-process if the health probe
    #                says nothing is listening (the default, so a single
    #                `uvicorn backend.main:app` is a working dev setup)
    scanner_transport: str = "auto"

    # --- Scanners ---
    # Which scanners the gRPC service advertises. Restricted to names the
    # scanner registry actually knows; unknown names are rejected at startup
    # rather than silently producing a service that reports healthy and then
    # errors on every request.
    enabled_scanners: list[str] = Field(default_factory=lambda: ["fixture"])
    # Semgrep binary path. Scanner is auto-disabled when this is not executable.
    semgrep_binary: str = "semgrep"
    # Where the fixture scanner reads its canned findings from.
    fixtures_dir: str = "data/fixtures"
    # Local CVE advisory feed used by get_cve_details.
    cve_feed_dir: str = "data/cve"

    # --- AutoGen remediation loop ---
    # When false, the deterministic rule-based developer/reviewer is used
    # instead of a live LLM. This is the default so the whole remediation path
    # is runnable and testable with no API key and no network. See
    # docs/adr/002-autogen-vs-langgraph-crewai.md.
    autogen_enabled: bool = False
    llm_model: str = "gpt-4o-mini"
    llm_api_key: str = ""
    llm_base_url: str = ""
    # Max developer<->reviewer critique/revise rounds. Past this the loop stops
    # and escalates to a human rather than burning tokens on an unwinnable
    # argument between two agents.
    remediation_max_rounds: int = 3
    # LLM calls are billed and slow; cap the loop so one bad finding cannot
    # spend an unbounded budget.
    remediation_max_llm_calls: int = 8
    # Ceiling on how much source the remediation loop is shown, in lines.
    #
    # A scanner reports one line, and one line is not enough for the reviewer to
    # judge a multi-line patch: its scope check requires every removed line to
    # appear in the snippet, so a five-line fix against a one-line snippet is
    # "out of scope" by construction. Measured over 30 real merged security
    # fixes, that produced 9 rejections where 3 were warranted -- see
    # docs/evidence.md. So the loop is shown the finding's enclosing block, and
    # this bounds it.
    #
    # A ceiling rather than a fixed width because a finding inside a 2,000-line
    # class would otherwise put the whole class in an LLM prompt. 120 lines holds
    # a substantial function with room to spare, and costs about 1.5k tokens
    # against the default model.
    remediation_snippet_max_lines: int = 120

    # --- Pull-request safety rails (the hard guarantees) ---
    # The single most important value in this file. False is not a supported
    # configuration: backend/services/approvals.py refuses to start with it.
    allow_auto_merge: bool = False
    # Repo the "pull request" is opened against. This project deliberately
    # fakes the git side (backend/services/publisher.py) -- a portfolio project
    # must not be able to push to a real repository by accident.
    target_repo: str = "ironclad-cyber/sentinel-remediations"
    target_base_branch: str = "main"

    # --- SLA policy (hours to remediate, by severity) ---
    sla_critical_hours: int = 4
    sla_high_hours: int = 24
    sla_medium_hours: int = 168  # 7 days
    sla_low_hours: int = 720  # 30 days
    sla_info_hours: int = 2160  # 90 days; informational items still need closing out
    # "At risk" = past this fraction of the SLA but not yet breached. Drives the
    # dashboard's amber state.
    sla_at_risk_fraction: float = 0.75

    # --- Auto-remediation safety rails ---
    # Path prefixes the agent is allowed to draft patches under. Anything
    # outside this list is refused by backend/policy/rules.py -- an agent that
    # can patch `infra/terraform/prod/` can break production.
    remediation_source_roots: list[str] = Field(
        default_factory=lambda: ["app/", "src/", "services/", "lib/", "config/"]
    )

    # --- Telemetry (Aegis contract) ---
    # Where standardized telemetry events go. "file" writes JSONL locally,
    # "http" POSTs to telemetry_endpoint, "null" discards. See
    # backend/telemetry/README.md.
    telemetry_sink: str = "file"
    telemetry_endpoint: str = ""
    telemetry_file: str = "data/telemetry/events.jsonl"
    # Telemetry must never be able to fail the operation it is measuring, so
    # every emit is wrapped and swallowed. This is the timeout budget for the
    # HTTP sink.
    telemetry_timeout_seconds: float = 2.0
    # Which service name to stamp on events. Aegis keys fleet metrics by this,
    # so it must match the tenant name registered in the fleet registry.
    telemetry_service: str = "SentinelMCP"

    @field_validator("log_level")
    @classmethod
    def _upper_log_level(cls, value: str) -> str:
        return value.upper()

    @field_validator("telemetry_sink")
    @classmethod
    def _known_sink(cls, value: str) -> str:
        allowed = {"file", "http", "null"}
        if value not in allowed:
            raise ValueError(f"telemetry_sink must be one of {sorted(allowed)}, got {value!r}")
        return value

    @field_validator("scanner_transport")
    @classmethod
    def _known_transport(cls, value: str) -> str:
        allowed = {"auto", "grpc", "in_process"}
        if value not in allowed:
            raise ValueError(f"scanner_transport must be one of {sorted(allowed)}, got {value!r}")
        return value

    @field_validator("sla_at_risk_fraction")
    @classmethod
    def _fraction_in_range(cls, value: float) -> float:
        if not 0.0 < value <= 1.0:
            raise ValueError(f"sla_at_risk_fraction must be in (0, 1], got {value}")
        return value

    @property
    def effective_database_url_sync(self) -> str:
        """Synchronous SQLAlchemy URL for Alembic and other blocking drivers.

        Derived from `database_url` by swapping the asyncpg driver for
        psycopg2 when not set explicitly, so there is exactly one place a
        database DSN is configured.
        """
        if self.database_url_sync:
            return self.database_url_sync
        return self.database_url.replace("+asyncpg", "").replace(
            "postgresql+psycopg2", "postgresql"
        )


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton.

    `lru_cache` because settings are immutable for the life of a process and
    re-parsing `.env` per request would be both wasteful and a source of
    confusing mid-process config changes. Tests that need to vary settings call
    `get_settings.cache_clear()` first.
    """
    return Settings()


def reload_settings() -> Settings:
    """Clear the cache and re-read the environment.

    Exists for tests and for the one-off scripts that mutate the environment
    before touching the app (e.g. `backend/scripts/run_remediation.py`).
    """
    get_settings.cache_clear()
    return get_settings()
