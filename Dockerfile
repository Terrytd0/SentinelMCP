# syntax=docker/dockerfile:1
#
# SentinelMCP image. One image, three commands: the API (uvicorn), the gRPC
# scanner (run_grpc_server), and one-off scripts (seed, alembic, run_remediation).
# They share a codebase, so building them separately would mean three copies of
# the same dependency resolution drifting apart.
#
# The scanner is a separate *service* rather than a separate image because the
# only real difference between the two processes is CPU-bound vs I/O-bound
# work -- not the code they run. See docs/architecture.md for why that split is
# worth an extra process.

# --- build stage -------------------------------------------------------------
FROM python:3.13-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# A build-only dependency, dropped before the runtime stage copies anything, so
# it never reaches the final image.
RUN pip install --no-cache-dir "hatchling>=1.25.0" "hatch-vcs" 2>/dev/null || \
    pip install --no-cache-dir "hatchling>=1.25.0"

# Wheel build first, deps second. Copying only pyproject.toml for the install
# step means `docker build` reuses the cached dependency layer on any change to
# application code -- which during a dev loop is every change.
COPY pyproject.toml README.md ./
COPY backend ./backend

RUN pip wheel --wheel-dir /wheels .

# --- runtime stage -----------------------------------------------------------
FROM python:3.13-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

# semgrep is a stretch goal rather than a runtime requirement, so it is not
# baked in: the scanner registry auto-disables the `semgrep` scanner when the
# binary is absent (see backend/scanners/registry.py). Install it in a derived
# image if you want the real SAST source.
WORKDIR /app

COPY --from=builder /wheels /wheels
COPY pyproject.toml README.md alembic.ini ./
COPY backend ./backend
COPY proto ./proto
COPY alembic ./alembic
COPY data ./data
COPY tests ./tests

RUN pip install --no-cache-dir /wheels/* && \
    rm -rf /wheels

# Run unprivileged. The image needs no write access outside /app, and a
# container that can write to its own filesystem as root is one step away from
# being one that can write anywhere.
RUN useradd --create-home --uid 10001 sentinel && \
    chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8000 50051

# Overridden per service in docker-compose.yml. The default is the API.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
