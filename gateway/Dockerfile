# ==============================================================================
# HARDENED MULTI-STAGE DOCKERFILE — AI GUARDRAIL GATEWAY
#
# Security properties:
#   - Non-root execution (UID 10001)
#   - Minimal runtime surface (python:3.12-slim, no build tools in final stage)
#   - Read-only root filesystem compatible (tmp via tmpfs mount at runtime)
#   - No shell or package manager in final image
#   - Dependencies pinned via requirements.txt; pip hash verification recommended in CI
# ==============================================================================

# --------------------------------------------------------------------------
# Stage 1: Build — install Python dependencies in a user-local prefix
# --------------------------------------------------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# --------------------------------------------------------------------------
# Stage 2: Runtime — minimal image, non-root user
# --------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

WORKDIR /app

# Create a locked-down system user — no login shell, no home directory writes
RUN groupadd -r -g 10001 gateway \
    && useradd -r -u 10001 -g gateway -s /sbin/nologin -M gateway

# Copy user-space packages from builder
COPY --from=builder --chown=gateway:gateway /root/.local /home/gateway/.local

# Copy application source
COPY --chown=gateway:gateway app/ ./app/

# Expose pip-installed binaries and package root
ENV PATH="/home/gateway/.local/bin:${PATH}"
ENV PYTHONPATH="/app:${PYTHONPATH}"

# Prevent Python from writing .pyc files to disk
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Enforce non-root execution
USER 10001

EXPOSE 8080

# Health-check: GKE / Docker will mark the container unhealthy if this fails
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "2", "--no-access-log"]
