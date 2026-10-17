"""
core/config.py — Application configuration loaded from environment variables.

All values are validated at startup via Pydantic Settings.
Secrets are NEVER printed or logged; only safe summary information is exposed.
Computed URL helpers use urllib.parse.quote to safely encode credentials
containing reserved characters such as @, :, /, and #.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal
from urllib.parse import quote

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _encode(value: str) -> str:
    """Percent-encode a credential component for safe embedding in a URL."""
    return quote(value, safe="")


class AppSettings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # "ignore" is deliberate: deployment tooling injects many env vars
        # (CI secrets, AWS/GCP metadata, etc.) that are unrelated to this app.
        # Strict mode would break standard containerised deployments.
        # Misspelled vars are caught by separate tests that verify all required
        # fields are present and have valid values.
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────────────────
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    secret_key: str = Field(..., min_length=32)

    # ── Wazuh ────────────────────────────────────────────────────────────────
    # TLS verification is ENABLED by default.
    # Set WAZUH_VERIFY_SSL=false only for local development with self-signed
    # certificates. Production rejects verify_ssl=false (see model_validator).
    wazuh_api_url: str
    wazuh_api_user: str
    wazuh_api_password: str = Field(..., repr=False)
    wazuh_verify_ssl: bool = True
    wazuh_poll_interval_seconds: int = Field(default=15, ge=5, le=3600)
    wazuh_timeout_seconds: int = Field(default=10, ge=1, le=120)

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
    # TLS verification is ENABLED by default.
    # Set MISP_VERIFY_SSL=false only for local development with self-signed certs.
    misp_url: str
    misp_api_key: str = Field(..., repr=False)
    misp_verify_ssl: bool = True
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
        """Async-compatible DSN using asyncpg driver.

        Credentials are percent-encoded so passwords containing reserved URL
        characters (@, :, /, #, ?) are handled correctly by the driver.
        Do NOT log this string — it embeds the password.
        """
        user = _encode(self.postgres_user)
        pw = _encode(self.postgres_password)
        return (
            f"postgresql+asyncpg://{user}:{pw}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_url(self) -> str:
        """Redis connection URL.

        Password is percent-encoded so special characters are handled safely.
        Do NOT log this string — it embeds the password.
        """
        pw = _encode(self.redis_password)
        return f"redis://:{pw}@{self.redis_host}:{self.redis_port}/0"

    # ── Field validators ─────────────────────────────────────────────────────

    @field_validator("wazuh_api_url")
    @classmethod
    def wazuh_url_must_be_https(cls, v: str) -> str:
        v = v.rstrip("/")
        if not v.startswith("https://"):
            scheme = v.split("//")[0]
            raise ValueError(
                f"WAZUH_API_URL must use HTTPS (got: {scheme}). "
                "Wazuh API credentials must never be sent over plain HTTP."
            )
        return v

    @field_validator("misp_url")
    @classmethod
    def misp_url_strip_trailing_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @field_validator("neo4j_uri")
    @classmethod
    def neo4j_uri_scheme(cls, v: str) -> str:
        if not (
            v.startswith("bolt://")
            or v.startswith("neo4j://")
            or v.startswith("neo4j+s://")
        ):
            raise ValueError("NEO4J_URI must use bolt:// or neo4j:// scheme")
        return v

    @model_validator(mode="after")
    def enforce_production_rules(self) -> AppSettings:
        """Apply production-only rules that span multiple fields."""
        placeholders = {"CHANGE_ME", "REPLACE_WITH", "your-secret"}

        if self.app_env == "production":
            # 1. Reject placeholder secrets — all of them.
            all_secrets = (
                "secret_key",
                "postgres_password",
                "neo4j_password",
                "redis_password",
                "wazuh_api_password",
                "misp_api_key",
                "llm_api_key",
            )
            for field_name in all_secrets:
                value: str = getattr(self, field_name)
                if any(p in value for p in placeholders):
                    raise ValueError(
                        f"Field '{field_name}' contains a placeholder value. "
                        "Replace all secrets before running in production."
                    )

            # 2. Reject insecure TLS in production.
            if not self.wazuh_verify_ssl:
                raise ValueError(
                    "WAZUH_VERIFY_SSL=false is not allowed in production. "
                    "Configure a valid TLS certificate for the Wazuh API."
                )
            if not self.misp_verify_ssl:
                raise ValueError(
                    "MISP_VERIFY_SSL=false is not allowed in production. "
                    "Configure a valid TLS certificate for the MISP instance."
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
            "wazuh_timeout_seconds": self.wazuh_timeout_seconds,
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
            "privileged_accounts_require_manual_override": (
                self.privileged_accounts_require_manual_override
            ),
        }


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return the cached singleton settings instance.

    Called at startup; the cache ensures the .env file is parsed once per
    process. Tests must call get_settings.cache_clear() between cases that
    mutate environment variables.
    """
    return AppSettings()  # type: ignore[call-arg]
