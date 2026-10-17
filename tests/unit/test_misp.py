"""
tests/unit/test_misp.py — Unit tests for MISP threat intelligence client.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from core.config import AppSettings
from core.health import ServiceStatus
from ingestion.misp import (
    MISPClient,
    MISPLookupStatus,
)


def make_settings(**overrides: Any) -> AppSettings:
    """Helper creating valid AppSettings with safe dummy defaults."""
    base: dict[str, Any] = {
        "secret_key": "safe-test-secret-key-32-chars-length",
        "wazuh_api_url": "https://192.168.1.10:55000",
        "wazuh_api_user": "test_wazuh_user",
        "wazuh_api_password": "test_wazuh_password",
        "wazuh_verify_ssl": True,
        "wazuh_timeout_seconds": 10,
        "postgres_password": "safe",
        "redis_password": "safe",
        "neo4j_password": "safe",
        "misp_url": "https://misp.local",
        "misp_api_key": "test-auth-key-12345",
        "misp_verify_ssl": True,
        "misp_timeout_seconds": 5,
        "llm_api_key": "safe",
    }
    base.update(overrides)
    return AppSettings(**base)


@pytest.fixture
def mock_settings() -> AppSettings:
    """Create test settings with MISP enabled."""
    return make_settings()


@pytest.fixture
def misp_client(mock_settings: AppSettings) -> MISPClient:
    """Instantiate MISPClient with test settings."""
    return MISPClient(settings=mock_settings)


@pytest.mark.asyncio
async def test_misp_rejects_unverified_tls_in_production() -> None:
    """Verify that unverified TLS is rejected in production environments."""
    # 1. AppSettings validation rejection
    with pytest.raises(Exception, match="MISP_VERIFY_SSL=false is not allowed in production"):
        make_settings(
            app_env="production",
            wazuh_verify_ssl=True,
            misp_url="https://misp.corp.local",
            misp_api_key="secret-prod-key",
            misp_verify_ssl=False,
        )

    # 2. Defense-in-depth: MISPClient.__init__ validation rejection
    prod_valid_settings = make_settings(
        app_env="production",
        wazuh_verify_ssl=True,
        misp_url="https://misp.corp.local",
        misp_api_key="secret-prod-key",
        misp_verify_ssl=True,
    )
    with pytest.raises(ValueError, match="MISP TLS verification cannot be disabled in production"):
        MISPClient(settings=prod_valid_settings, verify_ssl=False)


@pytest.mark.asyncio
async def test_misp_disabled_returns_disabled_status() -> None:
    """Verify that disabled MISP client returns DISABLED status without HTTP request."""
    disabled_settings = make_settings(
        misp_url="https://misp.local",
        misp_api_key="test-auth-key-12345",
    )
    client = MISPClient(settings=disabled_settings, enabled=False)

    result = await client.lookup_indicator("198.51.100.22", "ip-dst")
    assert result.status == MISPLookupStatus.DISABLED
    assert len(result.matches) == 0
    assert result.is_confirmed_safe is False

    health = await client.check_health()
    assert health.status == ServiceStatus.UNKNOWN
    assert "disabled" in health.detail.lower()


@pytest.mark.asyncio
async def test_misp_lookup_indicator_match(misp_client: MISPClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify successful indicator lookup returning matched threat attributes."""
    fake_response: dict[str, Any] = {
        "response": {
            "Attribute": [
                {
                    "id": "999",
                    "event_id": "101",
                    "category": "Network activity",
                    "type": "ip-dst",
                    "value": "198.51.100.22",
                    "to_ids": True,
                    "first_seen": "2026-01-01T00:00:00Z",
                    "last_seen": "2026-01-02T00:00:00Z",
                    "Event": {
                        "id": "101",
                        "info": "APT29 Command and Control Infrastructure",
                        "threat_level_id": 1,
                    },
                    "Tag": [
                        {"name": "tlp:amber"},
                        {"name": "threat-type:c2"},
                    ],
                }
            ]
        }
    }

    async def mock_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("POST", url)
        return httpx.Response(200, json=fake_response, request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    res = await misp_client.lookup_indicator("198.51.100.22", "ip-dst")
    assert res.status == MISPLookupStatus.MATCH_FOUND
    assert len(res.matches) == 1
    match = res.matches[0]
    assert match.indicator == "198.51.100.22"
    assert match.threat_level_id == 1
    assert match.event_info == "APT29 Command and Control Infrastructure"
    assert "tlp:amber" in match.tags
    assert res.is_confirmed_safe is False


@pytest.mark.asyncio
async def test_misp_lookup_indicator_no_match(misp_client: MISPClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that no-match returns NO_MATCH, but is_confirmed_safe is False (explicit uncertainty)."""
    fake_response: dict[str, Any] = {"response": {"Attribute": []}}

    async def mock_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("POST", url)
        return httpx.Response(200, json=fake_response, request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    res = await misp_client.lookup_indicator("192.168.1.50", "ip-src")
    assert res.status == MISPLookupStatus.NO_MATCH
    assert len(res.matches) == 0
    # Crucial principle: Absence of threat intelligence does NOT imply confirmed safety
    assert res.is_confirmed_safe is False


@pytest.mark.asyncio
async def test_misp_auth_failure(misp_client: MISPClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that HTTP 401/403 maps to ERROR status."""
    async def mock_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("POST", url)
        return httpx.Response(401, json={"message": "Authentication failed"}, request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    res = await misp_client.lookup_indicator("10.0.0.1")
    assert res.status == MISPLookupStatus.ERROR
    assert "authentication" in (res.error_message or "").lower()
    assert res.is_confirmed_safe is False


@pytest.mark.asyncio
async def test_misp_timeout_failure(misp_client: MISPClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that timeout maps to SERVICE_UNAVAILABLE status."""
    async def mock_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("POST", url)
        raise httpx.TimeoutException("Connection timed out", request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    res = await misp_client.lookup_indicator("10.0.0.1")
    assert res.status == MISPLookupStatus.SERVICE_UNAVAILABLE
    assert "timed out" in (res.error_message or "").lower()
    assert res.is_confirmed_safe is False
