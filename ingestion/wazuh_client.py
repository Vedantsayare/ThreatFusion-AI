"""
ingestion/wazuh_client.py — Secure asynchronous Wazuh API client.

Handles authentication, safe token caching, defense-in-depth TLS enforcement,
and error handling for Wazuh API interactions.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from core.config import AppSettings, get_settings
from core.health import ServiceHealth, ServiceStatus
from core.logger import get_logger

logger = get_logger("ingestion.wazuh_client")


class WazuhError(Exception):
    """Base exception for all Wazuh API client operations."""


class WazuhConnectionError(WazuhError):
    """Raised on network connection errors, DNS resolution failures, or timeouts."""


class WazuhTLSError(WazuhConnectionError):
    """Raised on TLS/SSL certificate verification failures."""


class WazuhAuthError(WazuhError):
    """Raised when Wazuh authentication fails (invalid credentials or rejected token)."""


class WazuhAPIError(WazuhError):
    """Raised when Wazuh API returns an error response (HTTP status >= 400 or error code != 0)."""

    def __init__(self, message: str, status_code: int = 0, error_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class WazuhClient:
    """Secure asynchronous HTTP client for the Wazuh API.

    Features:
    - Authenticates against Wazuh API (/security/user/authenticate).
    - Safe in-memory JWT token caching with automatic re-authentication on 401.
    - TLS certificate verification enabled by default; explicitly rejected in production.
    - Development-only override logs a clear warning; never silently disables verification.
    - Credentials and tokens are redacted from __repr__, logs, and exception strings.
    - Provides check_health() returning core.health.ServiceHealth.
    """

    def __init__(
        self,
        settings: AppSettings | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._base_url = self._settings.wazuh_api_url.rstrip("/")
        self._user = self._settings.wazuh_api_user
        self._password = self._settings.wazuh_api_password
        self._verify_ssl = self._settings.wazuh_verify_ssl
        self._timeout = float(self._settings.wazuh_timeout_seconds)

        # Defense-in-depth: Never allow verify_ssl=False in production
        if not self._verify_ssl:
            if self._settings.app_env == "production":
                raise WazuhTLSError(
                    "WAZUH_VERIFY_SSL=false is strictly prohibited in production mode. "
                    "Configure a valid TLS certificate for the Wazuh API."
                )
            logger.warning(
                "wazuh_tls_verification_disabled",
                url=self._base_url,
                reason="Development mode self-signed certificate override is active",
            )

        self._custom_client = client is not None
        self._client = client or httpx.AsyncClient(
            base_url=self._base_url,
            verify=self._verify_ssl,
            timeout=httpx.Timeout(self._timeout),
        )

        self._token: str | None = None
        self._token_acquired_at: float = 0.0
        self._token_ttl_seconds: float = 840.0  # 14 minutes (Wazuh token default is 15 minutes)
        self._auth_lock = asyncio.Lock()

    @property
    def is_authenticated(self) -> bool:
        """Return True if a non-expired token is held in memory."""
        if not self._token:
            return False
        return (time.monotonic() - self._token_acquired_at) < self._token_ttl_seconds

    @property
    def base_url(self) -> str:
        """Return the target Wazuh API base URL."""
        return self._base_url

    @property
    def verify_ssl(self) -> bool:
        """Return whether TLS verification is active."""
        return self._verify_ssl

    def __repr__(self) -> str:
        """Safe representation omitting passwords and authentication tokens."""
        return (
            f"<WazuhClient base_url={self._base_url!r} "
            f"user={self._user!r} "
            f"verify_ssl={self._verify_ssl!r} "
            f"authenticated={self.is_authenticated}>"
        )

    def _classify_connect_error(self, err: httpx.ConnectError) -> WazuhConnectionError:
        """Classify httpx.ConnectError into WazuhTLSError or WazuhConnectionError."""
        err_msg = str(err).lower()
        if (
            "certificate" in err_msg
            or "ssl" in err_msg
            or "verify" in err_msg
            or "cert" in err_msg
        ):
            return WazuhTLSError(
                f"TLS certificate verification failed connecting to Wazuh API at {self._base_url}. "
                "If using a self-signed certificate in development, set WAZUH_VERIFY_SSL=false."
            )
        return WazuhConnectionError(
            f"Failed to connect to Wazuh API at {self._base_url}: {err}"
        )

    async def authenticate(self) -> str:
        """Authenticate with the Wazuh API and cache the JWT token.

        Calls POST /security/user/authenticate using HTTP Basic Authentication.

        Returns:
            str: Acquired JWT token.

        Raises:
            WazuhAuthError: If credentials are invalid or token is missing from response.
            WazuhTLSError: If TLS verification fails.
            WazuhConnectionError: If network connectivity or timeout fails.
            WazuhAPIError: If the server returns an unexpected error.
        """
        logger.info("wazuh_authenticating", base_url=self._base_url, user=self._user)
        try:
            response = await self._client.post(
                "/security/user/authenticate",
                auth=(self._user, self._password),
                headers={"Content-Type": "application/json"},
            )
        except httpx.ConnectError as err:
            raise self._classify_connect_error(err) from err
        except httpx.TimeoutException as err:
            raise WazuhConnectionError(
                f"Authentication request timed out after {self._timeout}s"
            ) from err
        except httpx.RequestError as err:
            raise WazuhConnectionError(
                f"HTTP request error during authentication: {err}"
            ) from err

        if response.status_code == 401:
            raise WazuhAuthError(
                f"Wazuh authentication failed (401 Unauthorized) for user '{self._user}'. "
                "Verify WAZUH_API_USER and WAZUH_API_PASSWORD."
            )

        if response.status_code >= 400:
            raise WazuhAPIError(
                f"Wazuh authentication failed with status {response.status_code}",
                status_code=response.status_code,
            )

        try:
            payload: Any = response.json()
        except Exception as err:
            raise WazuhAPIError(
                f"Wazuh authentication response was not valid JSON: {err}",
                status_code=response.status_code,
            ) from err

        if not isinstance(payload, dict):
            raise WazuhAPIError(
                "Unexpected authentication response format from Wazuh API",
                status_code=response.status_code,
            )

        if payload.get("error", 0) != 0:
            error_code = payload.get("error", 0)
            message = payload.get("message", payload.get("detail", "Authentication error"))
            raise WazuhAuthError(
                f"Wazuh authentication returned error {error_code}: {message}"
            )

        data = payload.get("data")
        token = data.get("token") if isinstance(data, dict) else None
        if not token or not isinstance(token, str):
            raise WazuhAuthError("Wazuh authentication response missing JWT token in data.token")

        self._token = token
        self._token_acquired_at = time.monotonic()
        logger.info("wazuh_authenticated", base_url=self._base_url, user=self._user)
        return self._token

    async def _ensure_token(self) -> str:
        """Ensure a valid authentication token is cached, acquiring one if needed."""
        if self.is_authenticated and self._token:
            return self._token

        async with self._auth_lock:
            if self.is_authenticated and self._token:
                return self._token
            return await self.authenticate()

    async def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Send an authenticated request to the Wazuh API.

        Automatically attaches the Bearer token. If the response is HTTP 401,
        re-authenticates once and retries the request.

        Raises:
            WazuhAuthError: If authentication fails.
            WazuhTLSError: If TLS verification fails.
            WazuhConnectionError: If network connectivity or timeout fails.
            WazuhAPIError: If the server returns an error response.
        """
        token = await self._ensure_token()

        endpoint_path = endpoint if endpoint.startswith("/") else f"/{endpoint}"

        async def _send(auth_token: str) -> httpx.Response:
            req_headers: dict[str, str] = {"Authorization": f"Bearer {auth_token}"}
            if headers:
                req_headers.update(headers)

            try:
                return await self._client.request(
                    method=method,
                    url=endpoint_path,
                    params=params,
                    json=json,
                    headers=req_headers,
                    **kwargs,
                )
            except httpx.ConnectError as err:
                raise self._classify_connect_error(err) from err
            except httpx.TimeoutException as err:
                raise WazuhConnectionError(
                    f"Request to {endpoint_path} timed out after {self._timeout}s"
                ) from err
            except httpx.RequestError as err:
                raise WazuhConnectionError(f"HTTP request error: {err}") from err

        response = await _send(token)

        # Token expiration / rejection recovery: retry once after fresh authentication
        if response.status_code == 401:
            logger.warning("wazuh_token_rejected_retrying", endpoint=endpoint_path)
            async with self._auth_lock:
                self._token = None
                new_token = await self.authenticate()
            response = await _send(new_token)
            if response.status_code == 401:
                raise WazuhAuthError(
                    f"Wazuh API returned 401 Unauthorized for {endpoint_path} even after re-authenticating."
                )

        if response.status_code >= 400:
            raise WazuhAPIError(
                f"Wazuh API request to {endpoint_path} failed with status {response.status_code}",
                status_code=response.status_code,
            )

        try:
            result: Any = response.json()
        except Exception as err:
            raise WazuhAPIError(
                f"Wazuh API response for {endpoint_path} was not valid JSON: {err}",
                status_code=response.status_code,
            ) from err

        if not isinstance(result, dict):
            raise WazuhAPIError(
                f"Wazuh API response for {endpoint_path} was not a JSON object",
                status_code=response.status_code,
            )

        if result.get("error", 0) != 0:
            error_code = result.get("error", 0)
            msg = result.get("message", result.get("detail", "Wazuh API error"))
            raise WazuhAPIError(
                f"Wazuh API error {error_code}: {msg}",
                status_code=response.status_code,
                error_code=error_code,
            )

        return result

    async def get(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Send an authenticated GET request to the Wazuh API."""
        return await self.request("GET", endpoint, params=params, **kwargs)

    async def get_api_info(self) -> dict[str, Any]:
        """Retrieve basic API status and version information from Wazuh GET /."""
        return await self.get("/")

    async def check_health(self) -> ServiceHealth:
        """Perform a health check by pinging the Wazuh API.

        Returns:
            ServiceHealth: With status OK on success, or DOWN on failure.
        """
        try:
            info = await self.get_api_info()
            data = info.get("data", {})
            version = data.get("api_version", "unknown") if isinstance(data, dict) else "unknown"
            return ServiceHealth(
                name="wazuh",
                status=ServiceStatus.OK,
                detail=f"Wazuh API version: {version}",
            )
        except WazuhError as err:
            logger.error("wazuh_health_check_failed", error=str(err))
            return ServiceHealth(
                name="wazuh",
                status=ServiceStatus.DOWN,
                detail=str(err),
            )
        except Exception as err:
            logger.error("wazuh_health_check_unexpected_error", error=str(err))
            return ServiceHealth(
                name="wazuh",
                status=ServiceStatus.DOWN,
                detail=f"Unexpected error: {err}",
            )

    async def close(self) -> None:
        """Close the underlying HTTP client session."""
        if not self._custom_client:
            await self._client.aclose()

    async def __aenter__(self) -> WazuhClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.close()
