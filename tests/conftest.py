"""
tests/conftest.py — Shared pytest fixtures and environment bootstrap.

Provides a minimal but complete set of environment variables so that
AppSettings can be instantiated in tests without a real .env file.
Secrets use obvious placeholder values; tests never connect to live services.
"""

from __future__ import annotations

import os  # noqa: F401  (kept for future direct os.environ usage in tests)

import pytest

# ── Minimum set of env vars needed for AppSettings to validate ────────────────
_TEST_ENV: dict[str, str] = {
    "APP_ENV": "development",
    "LOG_LEVEL": "DEBUG",
    "SECRET_KEY": "test-secret-key-minimum-32-chars-long-ok",
    # Wazuh
    "WAZUH_API_URL": "https://192.168.1.99:55000",
    "WAZUH_API_USER": "test-user",
    "WAZUH_API_PASSWORD": "test-wazuh-password",
    "WAZUH_VERIFY_SSL": "false",
    # Postgres
    "POSTGRES_HOST": "localhost",
    "POSTGRES_PORT": "5432",
    "POSTGRES_DB": "threatfusion_test",
    "POSTGRES_USER": "tf_test",
    "POSTGRES_PASSWORD": "test-postgres-password",
    # Redis
    "REDIS_HOST": "localhost",
    "REDIS_PORT": "6379",
    "REDIS_PASSWORD": "test-redis-password",
    # Neo4j
    "NEO4J_URI": "bolt://localhost:7687",
    "NEO4J_USER": "neo4j",
    "NEO4J_PASSWORD": "test-neo4j-password",
    # MISP
    "MISP_URL": "https://misp.test.local",
    "MISP_API_KEY": "test-misp-key",
    "MISP_VERIFY_SSL": "false",
    # LLM
    "LLM_PROVIDER": "openai",
    "FAST_LLM_MODEL": "gpt-4o-mini",
    "REASONING_LLM_MODEL": "gpt-4o",
    "LLM_API_KEY": "test-llm-api-key",
}


@pytest.fixture(autouse=True)
def isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """
    Patch environment variables for every test so no real .env file is required.

    Also clears the lru_cache on get_settings() before and after each test
    so that env var changes in one test do not bleed into the next.
    """
    # Clear cached settings from previous test
    from core.config import get_settings
    get_settings.cache_clear()

    for key, value in _TEST_ENV.items():
        monkeypatch.setenv(key, value)

    yield

    # Clear again after the test
    get_settings.cache_clear()
