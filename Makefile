# SentinelMCP developer commands. Requires `make` (Git Bash/WSL/macOS/Linux --
# there is no native `make` on plain Windows cmd/PowerShell) and either
# `uv` (https://docs.astral.sh/uv/) or an activated .venv. Targets that need
# `uv` say so in their help text.

.DEFAULT_GOAL := help

.PHONY: help install sync run api scanner mcp remediate seed migrate proto lint format format-check typecheck test test-integration smoke verify-mcp evidence check up down logs clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

install: ## Create/refresh .venv, install all deps (incl. dev), install git hooks
	uv sync --extra dev
	uv run pre-commit install

sync: ## Sync .venv to exactly match pyproject.toml
	uv sync --extra dev

run: api ## Alias for `make api`

api: ## Run the FastAPI triage API (http://localhost:8000/docs)
	uv run uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

scanner: ## Run the gRPC scanning service (port 50051)
	uv run python -m backend.scripts.run_grpc_server

mcp: ## Run the MCP tool server over stdio (what Claude Desktop launches)
	uv run python -m backend.scripts.run_mcp_server

remediate: ## Draft a remediation for a finding: `make remediate FINDING=<uuid>`
	uv run python -m backend.scripts.run_remediation --finding-id $(FINDING)

seed: ## Seed development data (idempotent; runs a real scan + a real remediation)
	uv run python -m backend.scripts.seed

migrate: ## Apply migrations to the configured database
	uv run alembic upgrade head

proto: ## Regenerate the gRPC stubs from proto/sentinel/v1/scanner.proto
	uv run python -m grpc_tools.protoc -I proto \
		--python_out=backend/grpc_service/generated \
		--pyi_out=backend/grpc_service/generated \
		--grpc_python_out=backend/grpc_service/generated \
		proto/sentinel/v1/scanner.proto
	@echo "Regenerated. protoc emits 'from sentinel.v1 import ...', which is why"
	@echo "backend/grpc_service/generated/__init__.py puts this directory on sys.path."
	@echo "Run 'make lint typecheck test' afterwards: generated code is excluded from both."

lint: ## Lint with ruff
	uv run ruff check .

format: ## Auto-format with ruff (rewrites files)
	uv run ruff format .

format-check: ## Check formatting without modifying files (what CI runs)
	uv run ruff format --check .

typecheck: ## Type-check with mypy
	uv run mypy .

test: ## Run the whole suite (integration tests skip themselves without services)
	uv run pytest

test-integration: ## Run only the real-service tests (needs `make up` first)
	uv run pytest -m integration

smoke: ## End-to-end across two real processes (needs postgres; see scripts/smoke_e2e.py)
	uv run python scripts/smoke_e2e.py

verify-mcp: ## Check the MCP surface under the installed SDK major
	uv run python scripts/verify_mcp_sdk.py

evidence: ## Measured evidence about patch correctness (docs/evidence.md)
	uv run python scripts/evidence_report.py

evidence-all: ## The same, over all 19 real advisories instead of the default 6
	uv run python scripts/evidence_report.py --all

check: format-check lint typecheck test ## Full quality gate (what CI runs)

up: ## Start the full local stack: postgres, api, scanner (then seed it)
	docker compose up -d --build
	docker compose exec api python -m backend.scripts.seed

down: ## Stop the stack and delete its volumes
	docker compose down -v

logs: ## Tail the stack's logs
	docker compose logs -f

clean: ## Remove caches and build artifacts (keeps .venv and the database volumes)
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage dist build ./*.egg-info
	find . -type d -name __pycache__ -not -path "./.venv/*" -exec rm -rf {} +
