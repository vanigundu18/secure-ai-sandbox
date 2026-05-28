# ==============================================================================
# HARDENED MULTI-STAGE DOCKERFILE FOR AI GATEWAY
# Builds a minimal, secure container running as a non-privileged user.
# ==============================================================================

# Stage 1: Build & Package dependencies
FROM python:3.12-slim AS builder

WORKDIR /app

# Ensure we use latest security updates for system tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Stage 2: Final Minimal Runtime Image
FROM python:3.12-slim AS runtime

WORKDIR /app

# Create a non-root system user & group for zero-privilege execution
RUN groupadd -g 10001 gatewaygroup && \
    useradd -u 10001 -g gatewaygroup -m -s /bin/bash gatewayuser

# Copy dependencies installed in user space from builder
COPY --from=builder /root/.local /home/gatewayuser/.local
COPY app/ ./app/

# Set correct environment variables to include the pip bin and python packages
ENV PATH=/home/gatewayuser/.local/bin:$PATH
ENV PYTHONPATH=/app:$PYTHONPATH

# Adjust folder ownership to the non-root user
RUN chown -R gatewayuser:gatewaygroup /app

# Enforce secure user context
USER 10001

EXPOSE 8080

# Run diagnostic script on startup
CMD ["python", "app/gateway.py"]
