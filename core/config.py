"""
core/config.py — Application configuration loaded from environment variables.

All values are validated at startup via Pydantic Settings.
Secrets are NEVER printed or logged; only safe summary information is exposed.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # silently ignore unknown env vars
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    secret_key: str = Field(..., min_length=32)

    # ── Wazuh ────────────────────────────────────────────────────────────────
    wazuh_api_url: str
    wazuh_api_user: str
    wazuh_api_password: str = Field(..., repr=False)  # repr=False prevents leak in str()
    wazuh_verify_ssl: bool = False
    wazuh_poll_interval_seconds: int = Field(default=15, ge=5, le=3600)

    # ── PostgreSQL ───────────────────────────────────────────────────────────
    postgres_host: str = "localhost"
    postgres_port: int = Field(default=5432, ge=1, le=65535)
    postgres_db: str = "threatfusion"
    postgres_user: str = "threatfusion_user"
    postgres_password: str = Field(..., repr=False)

    # ── Redis ────────────────────────────────────────────────────────────────
    redis_host: str = "localhost"
    redis_port: int = Field(default=6379, ge=1, le=65535)
    redis_password: str = Field(..., repr=False)

    # ── Neo4j ────────────────────────────────────────────────────────────────
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = Field(..., repr=False)

    # ── MISP ─────────────────────────────────────────────────────────────────
    misp_url: str
    misp_api_key: str = Field(..., repr=False)
    misp_verify_ssl: bool = False
    misp_timeout_seconds: int = Field(default=10, ge=1, le=60)

    # ── LLM ──────────────────────────────────────────────────────────────────
    llm_provider: Literal["openai", "anthropic", "gemini", "ollama"] = "openai"
    fast_llm_model: str = "gpt-4o-mini"
    reasoning_llm_model: str = "gpt-4o"
    llm_api_key: str = Field(..., repr=False)

    # ── Guardrail policy ─────────────────────────────────────────────────────
    max_isolation_blast_radius: int = Field(default=3, ge=1, le=50)
    privileged_accounts_require_manual_override: bool = True

    # ── Computed helpers ─────────────────────────────────────────────────────

    @property
    def postgres_dsn(self) -> str:
        """Async-compatible DSN using asyncpg driver."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Redis URL (password embedded; do not log this string)."""
        return f"redis://:{self.redis_password}@{self.redis_host}:{self.redis_port}/0"

    # ── Field validators ─────────────────────────────────────────────────────

    @field_validator("wazuh_api_url")
    @classmethod
    def wazuh_url_must_be_https(cls, v: str) -> str:
        if not v.startswith("https://"):
            raise ValueError("WAZUH_API_URL must use HTTPS (got: %s)" % v.split("//")[0])
        return v

    @field_validator("neo4j_uri")
    @classmethod
    def neo4j_uri_scheme(cls, v: str) -> str:
        if not (v.startswith("bolt://") or v.startswith("neo4j://") or v.startswith("neo4j+s://")):
            raise ValueError("NEO4J_URI must use bolt:// or neo4j:// scheme")
        return v

    @model_validator(mode="after")
    def warn_non_production_defaults(self) -> "AppSettings":
        """Refuse to start in production if placeholder secrets are present."""
        placeholders = {"CHANGE_ME", "REPLACE_WITH", "your-secret"}
        if self.app_env == "production":
            for field_name in ("secret_key", "postgres_password", "neo4j_password", "redis_password"):
                value: str = getattr(self, field_name)
                if any(p in value for p in placeholders):
                    raise ValueError(
                        f"Field '{field_name}' contains a placeholder value. "
                        "Replace all secrets before running in production."
                    )
        return self

    def safe_summary(self) -> dict[str, object]:
        """Return a redacted dict safe to log at startup — no secrets included."""
        return {
            "app_env": self.app_env,
            "log_level": self.log_level,
            "wazuh_api_url": self.wazuh_api_url,
            "wazuh_verify_ssl": self.wazuh_verify_ssl,
            "wazuh_poll_interval_seconds": self.wazuh_poll_interval_seconds,
            "postgres_host": self.postgres_host,
            "postgres_port": self.postgres_port,
            "postgres_db": self.postgres_db,
            "redis_host": self.redis_host,
            "redis_port": self.redis_port,
            "neo4j_uri": self.neo4j_uri,
            "misp_url": self.misp_url,
            "misp_verify_ssl": self.misp_verify_ssl,
            "llm_provider": self.llm_provider,
            "fast_llm_model": self.fast_llm_model,
            "reasoning_llm_model": self.reasoning_llm_model,
            "max_isolation_blast_radius": self.max_isolation_blast_radius,
            "privileged_accounts_require_manual_override": self.privileged_accounts_require_manual_override,
        }


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """
    Return the cached singleton settings instance.

    Called at module import time by application code; the cache ensures
    the .env file is parsed only once per process.
    """
    return AppSettings()  # type: ignore[call-arg]
