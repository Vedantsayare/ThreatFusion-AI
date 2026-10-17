"""
tests/unit/test_config.py — Unit tests for core.config.AppSettings.

Verifies:
  - Required fields are loaded correctly from environment variables.
  - Computed properties (postgres_dsn, redis_url) are structured correctly.
  - Placeholder secrets are rejected in production mode.
  - Invalid field values raise ValidationError with meaningful messages.
  - safe_summary() contains no secret fields.
  - Wazuh URL must use HTTPS.
  - Neo4j URI must use a supported scheme.

All tests run without a live .env file — the conftest.py fixture provides
injected env vars and clears the settings cache between tests.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from core.config import AppSettings, get_settings


class TestSettingsLoadFromEnv:
    """AppSettings correctly reads and types env vars."""

    def test_loads_basic_fields(self) -> None:
        s = get_settings()
        assert s.app_env == "development"
        assert s.log_level == "DEBUG"

    def test_wazuh_fields(self) -> None:
        s = get_settings()
        assert s.wazuh_api_url == "https://192.168.1.99:55000"
        assert s.wazuh_verify_ssl is False
        assert s.wazuh_poll_interval_seconds == 15

    def test_postgres_fields(self) -> None:
        s = get_settings()
        assert s.postgres_host == "localhost"
        assert s.postgres_port == 5432
        assert s.postgres_db == "threatfusion_test"

    def test_redis_fields(self) -> None:
        s = get_settings()
        assert s.redis_host == "localhost"
        assert s.redis_port == 6379

    def test_neo4j_fields(self) -> None:
        s = get_settings()
        assert s.neo4j_uri == "bolt://localhost:7687"
        assert s.neo4j_user == "neo4j"

    def test_guardrail_defaults(self) -> None:
        s = get_settings()
        assert s.max_isolation_blast_radius == 3
        assert s.privileged_accounts_require_manual_override is True


class TestComputedProperties:
    """Computed DSN / URL helpers are correctly structured."""

    def test_postgres_dsn_uses_asyncpg_driver(self) -> None:
        s = get_settings()
        dsn = s.postgres_dsn
        assert dsn.startswith("postgresql+asyncpg://")
        assert "localhost" in dsn
        assert "threatfusion_test" in dsn
        # Password must be embedded (not a placeholder)
        assert "test-postgres-password" in dsn

    def test_redis_url_has_correct_scheme(self) -> None:
        s = get_settings()
        url = s.redis_url
        assert url.startswith("redis://:")
        assert "@localhost:6379" in url


class TestSafeSummary:
    """safe_summary() must not expose any secret values."""

    _SECRET_FIELD_NAMES = {
        "wazuh_api_password",
        "postgres_password",
        "redis_password",
        "neo4j_password",
        "misp_api_key",
        "llm_api_key",
        "secret_key",
    }

    def test_no_secret_keys_in_summary(self) -> None:
        summary = get_settings().safe_summary()
        for secret in self._SECRET_FIELD_NAMES:
            assert secret not in summary, f"secret field '{secret}' should not appear in safe_summary"

    def test_no_secret_values_in_summary(self) -> None:
        """No value in safe_summary should be a test password string."""
        summary = get_settings().safe_summary()
        for key, val in summary.items():
            assert "password" not in str(val).lower(), (
                f"safe_summary['{key}'] looks like it contains a password: {val!r}"
            )
            assert "api-key" not in str(val).lower(), (
                f"safe_summary['{key}'] looks like it contains an API key: {val!r}"
            )

    def test_summary_contains_expected_safe_fields(self) -> None:
        summary = get_settings().safe_summary()
        assert "app_env" in summary
        assert "wazuh_api_url" in summary
        assert "postgres_host" in summary
        assert "llm_provider" in summary


class TestFieldValidation:
    """Invalid inputs raise ValidationError with meaningful messages."""

    def test_wazuh_url_must_be_https(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAZUH_API_URL", "http://192.168.1.99:55000")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="HTTPS"):
            AppSettings()  # type: ignore[call-arg]

    def test_neo4j_uri_must_use_bolt_or_neo4j_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NEO4J_URI", "mysql://localhost:7687")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]

    def test_secret_key_minimum_length(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SECRET_KEY", "short")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]

    def test_invalid_app_env_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APP_ENV", "experimental")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]

    def test_invalid_log_level_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LOG_LEVEL", "VERBOSE")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]

    def test_poll_interval_minimum_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("WAZUH_POLL_INTERVAL_SECONDS", "2")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]


class TestProductionGuard:
    """Placeholder secrets must be rejected when APP_ENV=production."""

    def test_production_rejects_placeholder_secret_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("SECRET_KEY", "CHANGE_ME_generate_with_openssl_rand_hex_32")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="placeholder"):
            AppSettings()  # type: ignore[call-arg]

    def test_production_rejects_placeholder_postgres_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("SECRET_KEY", "a-real-secret-key-that-is-long-enough-xyz123")
        monkeypatch.setenv("POSTGRES_PASSWORD", "REPLACE_WITH_POSTGRES_PASSWORD")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="placeholder"):
            AppSettings()  # type: ignore[call-arg]

    def test_development_allows_placeholder_secrets(self) -> None:
        """Development mode must not block startup with placeholder secrets."""
        s = get_settings()
        assert s.app_env == "development"  # confirm we are in dev
        # No exception means the model_validator passed — this is the intended behaviour


class TestGetSettingsCache:
    """get_settings() returns the same object on multiple calls (lru_cache)."""

    def test_returns_same_instance(self) -> None:
        s1 = get_settings()
        s2 = get_settings()
        assert s1 is s2


# ---------------------------------------------------------------------------
# NEW REGRESSION TESTS  (Phase 0 remediation)
# ---------------------------------------------------------------------------


class TestTLSDefaults:
    """TLS verification is ENABLED by default (Finding 2)."""

    def test_wazuh_verify_ssl_class_default_is_true(self) -> None:
        """The field-level default for wazuh_verify_ssl must be True."""
        from core.config import AppSettings
        field_default = AppSettings.model_fields["wazuh_verify_ssl"].default
        assert field_default is True, (
            f"wazuh_verify_ssl field default must be True; got {field_default!r}"
        )

    def test_misp_verify_ssl_class_default_is_true(self) -> None:
        """The field-level default for misp_verify_ssl must be True."""
        from core.config import AppSettings
        field_default = AppSettings.model_fields["misp_verify_ssl"].default
        assert field_default is True, (
            f"misp_verify_ssl field default must be True; got {field_default!r}"
        )

    def test_dev_mode_accepts_verify_ssl_false(self) -> None:
        """Development mode allows WAZUH_VERIFY_SSL=false (conftest sets this)."""
        s = get_settings()
        assert s.app_env == "development"
        assert s.wazuh_verify_ssl is False  # conftest fixture sets this

    def test_dev_mode_accepts_misp_verify_ssl_false(self) -> None:
        """Development mode allows MISP_VERIFY_SSL=false (conftest sets this)."""
        s = get_settings()
        assert s.app_env == "development"
        assert s.misp_verify_ssl is False  # conftest fixture sets this


class TestProductionTLSGuard:
    """Production mode must reject insecure TLS settings (Finding 2)."""

    def _apply_prod_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("SECRET_KEY", "prod-safe-key-minimum-32-chars-xxxxx")
        monkeypatch.setenv("POSTGRES_PASSWORD", "prod-pg-password-safe")
        monkeypatch.setenv("NEO4J_PASSWORD", "prod-neo4j-safe")
        monkeypatch.setenv("REDIS_PASSWORD", "prod-redis-safe")
        monkeypatch.setenv("WAZUH_API_PASSWORD", "prod-wazuh-safe")
        monkeypatch.setenv("MISP_API_KEY", "prod-misp-safe")
        monkeypatch.setenv("LLM_API_KEY", "prod-llm-safe")
        monkeypatch.setenv("WAZUH_VERIFY_SSL", "true")
        monkeypatch.setenv("MISP_VERIFY_SSL", "true")

    def test_production_rejects_wazuh_insecure_tls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._apply_prod_base(monkeypatch)
        monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="WAZUH_VERIFY_SSL"):
            AppSettings()  # type: ignore[call-arg]

    def test_production_rejects_misp_insecure_tls(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._apply_prod_base(monkeypatch)
        monkeypatch.setenv("MISP_VERIFY_SSL", "false")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="MISP_VERIFY_SSL"):
            AppSettings()  # type: ignore[call-arg]

    def test_production_accepts_valid_tls_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fully valid production config with TLS enabled must not raise."""
        self._apply_prod_base(monkeypatch)
        get_settings.cache_clear()
        s = AppSettings()  # type: ignore[call-arg]
        assert s.app_env == "production"
        assert s.wazuh_verify_ssl is True
        assert s.misp_verify_ssl is True


class TestProductionGuardAllSecrets:
    """Production guard covers all 7 secret fields, not just 4 (Bug 2)."""

    def _apply_prod_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("APP_ENV", "production")
        monkeypatch.setenv("SECRET_KEY", "prod-safe-key-minimum-32-chars-xxxxx")
        monkeypatch.setenv("POSTGRES_PASSWORD", "prod-pg-password-safe")
        monkeypatch.setenv("NEO4J_PASSWORD", "prod-neo4j-safe")
        monkeypatch.setenv("REDIS_PASSWORD", "prod-redis-safe")
        monkeypatch.setenv("WAZUH_API_PASSWORD", "prod-wazuh-safe")
        monkeypatch.setenv("MISP_API_KEY", "prod-misp-safe")
        monkeypatch.setenv("LLM_API_KEY", "prod-llm-safe")
        monkeypatch.setenv("WAZUH_VERIFY_SSL", "true")
        monkeypatch.setenv("MISP_VERIFY_SSL", "true")

    def test_rejects_placeholder_wazuh_password(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._apply_prod_base(monkeypatch)
        monkeypatch.setenv("WAZUH_API_PASSWORD", "REPLACE_WITH_WAZUH_PASSWORD")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="placeholder"):
            AppSettings()  # type: ignore[call-arg]

    def test_rejects_placeholder_misp_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._apply_prod_base(monkeypatch)
        monkeypatch.setenv("MISP_API_KEY", "REPLACE_WITH_MISP_API_KEY")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="placeholder"):
            AppSettings()  # type: ignore[call-arg]

    def test_rejects_placeholder_llm_api_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._apply_prod_base(monkeypatch)
        monkeypatch.setenv("LLM_API_KEY", "REPLACE_WITH_LLM_API_KEY")
        get_settings.cache_clear()
        with pytest.raises(ValidationError, match="placeholder"):
            AppSettings()  # type: ignore[call-arg]


class TestURLEncoding:
    """DSN builders handle passwords with reserved URL characters (Finding 4).

    Characters tested: @  :  /  #  (all break naive f-string DSN construction).
    """

    def _pg(self, monkeypatch: pytest.MonkeyPatch, password: str) -> AppSettings:
        monkeypatch.setenv("POSTGRES_PASSWORD", password)
        get_settings.cache_clear()
        return AppSettings()  # type: ignore[call-arg]

    def _redis(self, monkeypatch: pytest.MonkeyPatch, password: str) -> AppSettings:
        monkeypatch.setenv("REDIS_PASSWORD", password)
        get_settings.cache_clear()
        return AppSettings()  # type: ignore[call-arg]

    def test_postgres_dsn_encodes_at_sign(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dsn = self._pg(monkeypatch, "pass@word").postgres_dsn
        assert "pass%40word" in dsn, "@ must be encoded as %40"
        assert dsn.count("@") == 1, "Exactly one @ (host separator) must remain"

    def test_postgres_dsn_encodes_colon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert "pa%3Ass" in self._pg(monkeypatch, "pa:ss").postgres_dsn

    def test_postgres_dsn_encodes_slash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert "pa%2Fss" in self._pg(monkeypatch, "pa/ss").postgres_dsn

    def test_postgres_dsn_encodes_hash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert "pa%23ss" in self._pg(monkeypatch, "pa#ss").postgres_dsn

    def test_redis_url_encodes_at_sign(self, monkeypatch: pytest.MonkeyPatch) -> None:
        url = self._redis(monkeypatch, "pass@word").redis_url
        assert "pass%40word" in url, "@ must be encoded as %40"
        assert url.count("@") == 1, "Exactly one @ (host separator) must remain"

    def test_redis_url_encodes_colon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert "pa%3Ass" in self._redis(monkeypatch, "pa:ss").redis_url

    def test_redis_url_encodes_slash(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert "pa%2Fss" in self._redis(monkeypatch, "pa/ss").redis_url

    def test_plain_password_passes_through(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Passwords with no reserved chars must not be altered."""
        assert "simplepassword123" in self._pg(monkeypatch, "simplepassword123").postgres_dsn


class TestURLNormalisation:
    """Wazuh and MISP URLs have trailing slashes stripped (Finding 4)."""

    def test_wazuh_url_trailing_slash_stripped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("WAZUH_API_URL", "https://192.168.1.99:55000/")
        get_settings.cache_clear()
        s = AppSettings()  # type: ignore[call-arg]
        assert s.wazuh_api_url == "https://192.168.1.99:55000"

    def test_misp_url_trailing_slash_stripped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MISP_URL", "https://misp.test.local/")
        get_settings.cache_clear()
        s = AppSettings()  # type: ignore[call-arg]
        assert s.misp_url == "https://misp.test.local"


class TestExtraEnvVarHandling:
    """extra=ignore is tested and its implications documented (Finding 5)."""

    def test_unknown_env_var_is_silently_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Irrelevant env vars from CI/cloud must not cause startup failure.

        extra=ignore is deliberate: CI systems inject many vars (AWS_*, GITHUB_*)
        unrelated to this app. Misspelled REQUIRED vars are still caught because
        Pydantic sees the expected field as absent and raises ValidationError.
        """
        monkeypatch.setenv("COMPLETELY_UNKNOWN_VAR_XYZ", "irrelevant")
        get_settings.cache_clear()
        s = AppSettings()  # type: ignore[call-arg]
        assert not hasattr(s, "completely_unknown_var_xyz")

    def test_misspelled_required_var_raises_missing_field_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A misspelled required env var is caught as a missing required field."""
        monkeypatch.delenv("POSTGRES_PASSWORD", raising=False)
        monkeypatch.setenv("POSTGRESS_PASSWORD", "typo-extra-s")
        get_settings.cache_clear()
        with pytest.raises(ValidationError):
            AppSettings()  # type: ignore[call-arg]
