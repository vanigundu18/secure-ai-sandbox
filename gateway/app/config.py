"""
Runtime configuration — all values loaded from environment variables.
Never hard-code secrets in source; inject them via Kubernetes Secrets or
Secret Manager sidecar at pod startup.
"""

from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Anthropic
    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key — mount from Secret Manager in production.",
    )
    anthropic_model: str = Field(
        default="claude-opus-4-6",
        description="Claude model ID to route requests to.",
    )
    anthropic_max_tokens: int = Field(
        default=1024,
        ge=1,
        le=4096,
        description="Maximum tokens to request from the Claude API.",
    )

    # Gateway behaviour
    max_prompt_length: int = Field(
        default=4000,
        ge=1,
        le=32000,
        description="Hard ceiling on incoming prompt character count.",
    )
    rate_limit_per_minute: int = Field(
        default=60,
        ge=1,
        description="Maximum requests per minute per client IP.",
    )
    allowed_origins: list[str] = Field(
        default=["*"],
        description="CORS allowed origins. Set explicitly in production.",
    )

    # Observability
    log_level: str = Field(default="INFO")
    log_json: bool = Field(
        default=True,
        description="Emit structured JSON logs (recommended for GCP Cloud Logging).",
    )

    @field_validator("log_level")
    @classmethod
    def normalise_log_level(cls, v: str) -> str:
        return v.upper()


settings = Settings()
