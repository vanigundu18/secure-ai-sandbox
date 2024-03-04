"""
FastAPI HTTP server for the Guardrail Gateway.

Endpoints
---------
POST /v1/query      Submit a prompt; returns sanitized LLM response or rejection
GET  /health        Kubernetes liveness probe
GET  /ready         Kubernetes readiness probe
GET  /metrics       Prometheus-compatible plaintext metrics
"""

from __future__ import annotations

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

import anthropic
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .config import settings
from .guardrails import GuardrailGateway, Severity

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=settings.log_level,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger("gateway.server")

# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "gateway_requests_total",
    "Total requests processed by the gateway",
    ["status", "model"],
)
REQUEST_LATENCY = Histogram(
    "gateway_request_duration_seconds",
    "Request processing latency in seconds",
    ["status"],
    buckets=[0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)
VIOLATION_COUNT = Counter(
    "gateway_violations_total",
    "Prompt violations detected by guardrail layer",
    ["layer", "severity"],
)

# ---------------------------------------------------------------------------
# Guardrail singleton & Anthropic client
# ---------------------------------------------------------------------------
_guardrail: GuardrailGateway | None = None
_anthropic_client: anthropic.Anthropic | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _guardrail, _anthropic_client
    logger.info("Initialising guardrail pipeline and Anthropic client…")
    _guardrail = GuardrailGateway(max_prompt_length=settings.max_prompt_length)
    if settings.anthropic_api_key:
        _anthropic_client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
        logger.info("Anthropic client initialised (model=%s)", settings.anthropic_model)
    else:
        logger.warning("ANTHROPIC_API_KEY not set — running in mock/dry-run mode")
    yield
    logger.info("Gateway shutting down")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Secure AI Guardrail Gateway",
    description="LLM proxy with layered prompt injection detection, PII redaction, and output compliance.",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Request-ID"],
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class QueryRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32000, description="User prompt to forward to the LLM.")
    system: Optional[str] = Field(None, max_length=8000, description="Optional system context (non-sensitive).")


class QueryResponse(BaseModel):
    request_id: str
    status: str
    response: Optional[str] = None
    error: Optional[str] = None
    processing_time_ms: float


# ---------------------------------------------------------------------------
# Middleware — attach request ID to every request
# ---------------------------------------------------------------------------
@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/health", tags=["ops"])
async def health():
    """Kubernetes liveness probe — returns 200 if the process is alive."""
    return {"status": "ok"}


@app.get("/ready", tags=["ops"])
async def ready():
    """Kubernetes readiness probe — returns 200 only when all components are initialised."""
    if _guardrail is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Guardrail not initialised")
    return {"status": "ready", "model": settings.anthropic_model}


@app.get("/metrics", tags=["ops"])
async def metrics():
    """Prometheus-compatible metrics endpoint."""
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/v1/query", response_model=QueryResponse, tags=["gateway"])
@limiter.limit(f"{settings.rate_limit_per_minute}/minute")
async def query(request: Request, body: QueryRequest):
    """
    Main gateway endpoint.

    1. Screen the incoming prompt through all guardrail layers.
    2. If allowed, forward to Claude and sanitize the response.
    3. Return the safe response or a structured rejection.
    """
    start = time.perf_counter()
    request_id = request.state.request_id

    # --- Input guardrails ---
    result = _guardrail.screen_input(body.prompt)

    if not result.allowed:
        v = result.primary_violation
        VIOLATION_COUNT.labels(layer=v.layer, severity=v.severity.value).inc()
        REQUEST_COUNT.labels(status="blocked", model="none").inc()
        elapsed = (time.perf_counter() - start) * 1000
        REQUEST_LATENCY.labels(status="blocked").observe(elapsed / 1000)
        return QueryResponse(
            request_id=request_id,
            status="blocked",
            error=v.message,
            processing_time_ms=round(elapsed, 2),
        )

    # --- LLM dispatch ---
    safe_prompt = result.sanitized_text or body.prompt
    try:
        raw_response = _call_llm(safe_prompt, body.system)
    except Exception as exc:
        logger.error("LLM call failed [request_id=%s]: %s", request_id, exc)
        REQUEST_COUNT.labels(status="error", model=settings.anthropic_model).inc()
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="Upstream LLM error") from exc

    # --- Output guardrails ---
    safe_response = _guardrail.sanitize_output(raw_response, request_id)

    elapsed = (time.perf_counter() - start) * 1000
    REQUEST_COUNT.labels(status="success", model=settings.anthropic_model).inc()
    REQUEST_LATENCY.labels(status="success").observe(elapsed / 1000)

    return QueryResponse(
        request_id=request_id,
        status="success",
        response=safe_response,
        processing_time_ms=round(elapsed, 2),
    )


# ---------------------------------------------------------------------------
# LLM dispatch helper
# ---------------------------------------------------------------------------
def _call_llm(prompt: str, system: Optional[str]) -> str:
    """Route the sanitized prompt to the configured Claude model."""
    if _anthropic_client is None:
        # Dry-run / test mode — return a deterministic mock
        return f"[DRY-RUN] Echo: {prompt[:100]}"

    kwargs: dict = {
        "model": settings.anthropic_model,
        "max_tokens": settings.anthropic_max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        kwargs["system"] = system

    message = _anthropic_client.messages.create(**kwargs)
    return message.content[0].text


# ---------------------------------------------------------------------------
# Entry point for local development
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("gateway.app.main:app", host="0.0.0.0", port=8080, reload=True)
