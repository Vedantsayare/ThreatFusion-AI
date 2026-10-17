"""
tests/unit/test_wazuh_client.py — Unit tests for the secure Wazuh API client.

All tests use mocked HTTP transports; no live Wazuh server or credentials required.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from core.config import AppSettings
from core.health import ServiceStatus
from ingestion.wazuh_client import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhClient,
    WazuhConnectionError,
    WazuhTLSError,
)


def _make_settings(**overrides: Any) -> AppSettings:
    """Helper to build an AppSettings instance with optional overrides."""
    base: dict[str, Any] = {
        "app_env": "development",
        "secret_key": "x" * 32,
        "wazuh_api_url": "https://192.168.114.140:55000",
        "wazuh_api_user": "test_wazuh_user",
        "wazuh_api_password": "test_wazuh_password",
        "wazuh_verify_ssl": True,
        "wazuh_timeout_seconds": 10,
        "postgres_password": "safe",
        "redis_password": "safe",
        "neo4j_password": "safe",
        "misp_url": "https://misp.local",
        "misp_api_key": "safe",
        "misp_verify_ssl": True,
        "llm_api_key": "safe",
    }
    base.update(overrides)
    return AppSettings(**base)


class TestWazuhClientInit:
    """Initialization and configuration behavior."""

    def test_initial_state_and_safe_repr(self) -> None:
        settings = _make_settings()
        client = WazuhClient(settings)
        assert client.base_url == "https://192.168.114.140:55000"
        assert client.verify_ssl is True
        assert client.is_authenticated is False

        repr_str = repr(client)
        assert "https://192.168.114.140:55000" in repr_str
        assert "test_wazuh_user" in repr_str
        assert "authenticated=False" in repr_str
        # Secrets MUST NOT appear
        assert "test_wazuh_password" not in repr_str

    def test_base_url_strips_trailing_slash(self) -> None:
        settings = _make_settings(wazuh_api_url="https://192.168.114.140:55000/")
        client = WazuhClient(settings)
        assert client.base_url == "https://192.168.114.140:55000"

    def test_production_rejects_insecure_tls_override(self) -> None:
        # In production, WazuhClient enforces defense-in-depth even if AppSettings bypassed
        settings = _make_settings(app_env="production")
        # Force verify_ssl to False on settings object to test client defense-in-depth
        object.__setattr__(settings, "wazuh_verify_ssl", False)
        with pytest.raises(WazuhTLSError, match="strictly prohibited in production"):
            WazuhClient(settings)


class TestWazuhAuthentication:
    """Authentication and token handling tests."""

    @pytest.mark.asyncio
    async def test_successful_authentication(self) -> None:
        auth_called = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal auth_called
            assert request.url.path == "/security/user/authenticate"
            assert request.method == "POST"
            # Verify basic auth header is present
            auth_header = request.headers.get("Authorization", "")
            assert auth_header.startswith("Basic ")
            auth_called = True
            return httpx.Response(
                200,
                json={"data": {"token": "mock-jwt-token-12345"}, "error": 0},
            )

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        token = await client.authenticate()

        assert token == "mock-jwt-token-12345"
        assert client.is_authenticated is True
        assert auth_called is True

    @pytest.mark.asyncio
    async def test_authentication_401_raises_wazuh_auth_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                401,
                json={"title": "Unauthorized", "detail": "Invalid credentials", "error": 1000},
            )

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhAuthError, match="401 Unauthorized"):
            await client.authenticate()
        assert client.is_authenticated is False

    @pytest.mark.asyncio
    async def test_authentication_missing_token_raises_auth_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"data": {}, "error": 0})

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhAuthError, match="missing JWT token"):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_authentication_error_code_raises_auth_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"error": 1005, "message": "User locked"})

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhAuthError, match="returned error 1005"):
            await client.authenticate()


class TestWazuhRequests:
    """Authenticated requests, token caching, and retry logic."""

    @pytest.mark.asyncio
    async def test_authenticated_get_attaches_bearer_token(self) -> None:
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(request.url.path)
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(
                    200,
                    json={"data": {"token": "jwt-token-abc"}, "error": 0},
                )
            if request.url.path == "/manager/status":
                assert request.headers.get("Authorization") == "Bearer jwt-token-abc"
                return httpx.Response(
                    200,
                    json={"data": {"status": "running"}, "error": 0},
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        res = await client.get("/manager/status")

        assert res["data"]["status"] == "running"
        # First call authenticated, second made request
        assert calls == ["/security/user/authenticate", "/manager/status"]

    @pytest.mark.asyncio
    async def test_reuses_cached_token_on_subsequent_requests(self) -> None:
        auth_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal auth_count
            if request.url.path == "/security/user/authenticate":
                auth_count += 1
                return httpx.Response(
                    200,
                    json={"data": {"token": "jwt-token-reuse"}, "error": 0},
                )
            if request.url.path == "/test-endpoint":
                assert request.headers.get("Authorization") == "Bearer jwt-token-reuse"
                return httpx.Response(200, json={"data": "ok", "error": 0})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        await client.get("/test-endpoint")
        await client.get("/test-endpoint")

        # authenticate should only have been called ONCE
        assert auth_count == 1

    @pytest.mark.asyncio
    async def test_auto_reauthenticates_on_401(self) -> None:
        auth_tokens = ["token-1", "token-2"]
        request_count = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_count
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(
                    200,
                    json={"data": {"token": auth_tokens.pop(0)}, "error": 0},
                )
            if request.url.path == "/data":
                request_count += 1
                if request.headers.get("Authorization") == "Bearer token-1":
                    # Simulate token expiry / 401
                    return httpx.Response(401, json={"error": 1001, "message": "Token expired"})
                if request.headers.get("Authorization") == "Bearer token-2":
                    return httpx.Response(200, json={"data": "success", "error": 0})
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        result = await client.get("/data")

        assert result["data"] == "success"
        assert request_count == 2


class TestWazuhErrors:
    """Network, TLS, and protocol error mapping."""

    @pytest.mark.asyncio
    async def test_connection_error_mapped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Network unreachable")

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhConnectionError, match="Failed to connect"):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_tls_certificate_error_mapped_to_wazuh_tls_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhTLSError, match="TLS certificate verification failed"):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_timeout_mapped_to_connection_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("Timed out after 10s")

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhConnectionError, match="timed out"):
            await client.authenticate()

    @pytest.mark.asyncio
    async def test_api_error_response_mapped(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "tok"}, "error": 0})
            return httpx.Response(500, json={"error": 5000, "message": "Internal manager crash"})

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        with pytest.raises(WazuhAPIError) as exc_info:
            await client.get("/broken")
        assert exc_info.value.status_code == 500


class TestWazuhHealthCheck:
    """ServiceHealth integration tests."""

    @pytest.mark.asyncio
    async def test_check_health_reports_ok(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/security/user/authenticate":
                return httpx.Response(200, json={"data": {"token": "tok"}, "error": 0})
            if request.url.path == "/":
                return httpx.Response(
                    200,
                    json={
                        "data": {
                            "msg": "Welcome to Wazuh API",
                            "api_version": "4.9.0",
                        },
                        "error": 0,
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        health = await client.check_health()

        assert health.name == "wazuh"
        assert health.status == ServiceStatus.OK
        assert "4.9.0" in health.detail

    @pytest.mark.asyncio
    async def test_check_health_reports_down_on_auth_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": 1000, "message": "Bad creds"})

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        health = await client.check_health()

        assert health.name == "wazuh"
        assert health.status == ServiceStatus.DOWN
        assert "401" in health.detail

    @pytest.mark.asyncio
    async def test_check_health_reports_down_on_network_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("Connection refused")

        transport = httpx.MockTransport(handler)
        mock_http = httpx.AsyncClient(transport=transport, base_url="https://192.168.114.140:55000")

        client = WazuhClient(_make_settings(), client=mock_http)
        health = await client.check_health()

        assert health.name == "wazuh"
        assert health.status == ServiceStatus.DOWN
        assert "Failed to connect" in health.detail


class TestWazuhContextManager:
    """Resource cleanup and context management."""

    @pytest.mark.asyncio
    async def test_context_manager_closes_client(self) -> None:
        async with WazuhClient(_make_settings()) as client:
            assert client.is_authenticated is False
        # When context exits, client was closed
        assert client._client.is_closed is True
