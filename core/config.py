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
    # Background polling of the Wazuh API is opt-in; alerts can always be
    # submitted via POST /api/v1/alerts/ingest instead.
    wazuh_enabled: bool = False
    wazuh_api_url: str
    wazuh_api_user: str
    wazuh_api_password: str = Field(..., repr=False)
    wazuh_verify_ssl: bool = True
    wazuh_poll_interval_seconds: int = Field(default=15, ge=5, le=3600)
    wazuh_timeout_seconds: int = Field(default=10, ge=1, le=120)
    wazuh_alerts_endpoint: str = "/alerts"
    wazuh_batch_size: int = Field(default=100, ge=1, le=1000)
    wazuh_max_retries: int = Field(default=3, ge=1, le=10)
    wazuh_retry_backoff_seconds: float = Field(default=1.0, ge=0.01, le=30.0)

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
    # Only the investigation narrative may use an LLM. "none" selects the
    # deterministic template. openai/gemini are accepted for backward
    # compatibility but are not implemented (template fallback, labelled).
    llm_provider: Literal["none", "openai", "anthropic", "gemini", "ollama"] = "none"
    fast_llm_model: str = "claude-haiku-5-5"
    reasoning_llm_model: str = "claude-opus-5-5"
    llm_api_key: str = Field(..., repr=False)
    llm_base_url: str | None = None
    llm_timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)

    # ── Guardrail policy ─────────────────────────────────────────────────────
    max_isolation_blast_radius: int = Field(default=3, ge=1, le=50)
    privileged_accounts_require_manual_override: bool = True
    approval_timeout_seconds: int = Field(default=1800, ge=30, le=86400)

    # ── API security ─────────────────────────────────────────────────────────
    # Comma-separated "name:role:key" triples. Keys with placeholders are ignored.
    api_keys: str = Field(default="", repr=False)
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    max_request_bytes: int = Field(default=262_144, ge=1024, le=10_485_760)
    # Per-client request budget (0 disables) and auth brute-force lockout.
    rate_limit_per_minute: int = Field(default=600, ge=0, le=100_000)
    auth_max_failures: int = Field(default=10, ge=0, le=1000)
    auth_lockout_seconds: int = Field(default=300, ge=10, le=86_400)

    # ── Persistence & runtime modes ──────────────────────────────────────────
    persistence_backend: Literal["postgres", "sqlite", "memory"] = "postgres"
    sqlite_path: str = "./threatfusion.db"
    neo4j_enabled: bool = True
    demo_mode: bool = True

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
    def cors_origin_list(self) -> list[str]:
        """Explicit CORS allow-list; wildcard origins are never returned."""
        return [o.strip() for o in self.cors_origins.split(",") if o.strip() and o.strip() != "*"]

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

    @field_validator("wazuh_alerts_endpoint")
    @classmethod
    def wazuh_alerts_endpoint_format(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith("/"):
            v = f"/{v}"
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
            "wazuh_alerts_endpoint": self.wazuh_alerts_endpoint,
            "wazuh_batch_size": self.wazuh_batch_size,
            "wazuh_max_retries": self.wazuh_max_retries,
            "wazuh_retry_backoff_seconds": self.wazuh_retry_backoff_seconds,
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
            "approval_timeout_seconds": self.approval_timeout_seconds,
            "rate_limit_per_minute": self.rate_limit_per_minute,
            "auth_max_failures": self.auth_max_failures,
            "persistence_backend": self.persistence_backend,
            "neo4j_enabled": self.neo4j_enabled,
            "demo_mode": self.demo_mode,
            "cors_origins": self.cors_origin_list,
        }


@lru_cache(maxsize=1)
def get_settings() -> AppSettings:
    """Return the cached singleton settings instance.

    Called at startup; the cache ensures the .env file is parsed once per
    process. Tests must call get_settings.cache_clear() between cases that
    mutate environment variables.
    """
    return AppSettings()  # type: ignore[call-arg]
