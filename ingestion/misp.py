"""
ingestion/misp.py — Asynchronous MISP threat-intelligence client and enrichment service.

Features:
- Queries configured MISP REST API (/attributes/restSearch) for IP/domain indicators.
- Production TLS enforcement (rejects insecure TLS when app_env == "production").
- Safe credential handling (API key omitted from __repr__ and logs).
- Distinguishes MATCH_FOUND, NO_MATCH, SERVICE_UNAVAILABLE, ERROR, and DISABLED.
- Principle of Explicit Uncertainty: Missing threat-intelligence is UNKNOWN, never "confirmed safe".
- Treats external MISP descriptions as untrusted passive data.
- Bounded retries and explicit timeouts.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from core.config import AppSettings, get_settings
from core.health import ServiceHealth, ServiceStatus
from core.logger import get_logger

logger = get_logger("ingestion.misp")


class MISPError(Exception):
    """Base exception for all MISP client operations."""


class MISPConnectionError(MISPError):
    """Raised on network failure, DNS resolution failure, or connection timeout."""


class MISPTLSError(MISPConnectionError):
    """Raised on TLS/SSL certificate verification failure."""


class MISPAuthError(MISPError):
    """Raised when MISP API key is rejected (401 or 403)."""


class MISPTimeoutError(MISPConnectionError):
    """Raised when MISP request exceeds configured timeout."""


class MISPAPIError(MISPError):
    """Raised when MISP returns an unexpected HTTP >= 400 error."""

    def __init__(self, message: str, status_code: int = 0) -> None:
        super().__init__(message)
        self.status_code = status_code


class MISPLookupStatus(str, Enum):
    """Outcome status of a threat-intelligence lookup."""

    MATCH_FOUND = "MATCH_FOUND"
    NO_MATCH = "NO_MATCH"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    ERROR = "ERROR"
    DISABLED = "DISABLED"


class MISPIndicatorMatch(BaseModel):
    """Single matching threat-intelligence attribute from MISP."""

    model_config = ConfigDict(extra="ignore")

    indicator: str
    category: str = "Network activity"
    attribute_type: str = "ip-dst"
    event_id: str
    event_info: str
    threat_level_id: int | None = None
    confidence: float = 0.8
    timestamp: str | None = None
    tags: list[str] = Field(default_factory=list)


class MISPEnrichmentResult(BaseModel):
    """Structured enrichment result for an indicator."""

    model_config = ConfigDict(extra="ignore")

    indicator: str
    status: MISPLookupStatus
    source: str = "misp"
    retrieved_at: float = Field(default_factory=time.time)
    matches: list[MISPIndicatorMatch] = Field(default_factory=list)
    match_count: int = 0
    error_message: str | None = None
    confidence: float = 0.0

    # Explicit Safety Boundary: Missing intel NEVER equals confirmed safe
    is_confirmed_safe: bool = False


class MISPClient:
    """Asynchronous HTTP client for MISP REST API with defensive controls."""

    def __init__(
        self,
        settings: AppSettings | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        verify_ssl: bool | None = None,
        timeout_seconds: float | None = None,
        max_retries: int = 2,
        enabled: bool = True,
    ) -> None:
        cfg = settings or get_settings()

        self._base_url = (base_url or cfg.misp_url).rstrip("/")
        self._api_key = api_key or cfg.misp_api_key
        self._verify_ssl = verify_ssl if verify_ssl is not None else cfg.misp_verify_ssl
        self._timeout = timeout_seconds if timeout_seconds is not None else float(cfg.misp_timeout_seconds)
        self._max_retries = max(0, max_retries)
        self._enabled = enabled

        # Defense-in-depth: Reject disabled TLS verification in production
        if cfg.app_env == "production" and not self._verify_ssl:
            raise ValueError(
                "MISP TLS verification cannot be disabled in production. "
                "Configure a valid TLS certificate."
            )

        self._headers = {
            "Authorization": self._api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def __repr__(self) -> str:
        masked_key = f"{self._api_key[:4]}***" if len(self._api_key) > 4 else "***"
        return (
            f"MISPClient(base_url='{self._base_url}', verify_ssl={self._verify_ssl}, "
            f"timeout={self._timeout}s, api_key='{masked_key}', enabled={self._enabled})"
        )

    @property
    def is_enabled(self) -> bool:
        """True if integration is configured and enabled."""
        placeholder = any(p in self._api_key for p in ("REPLACE_WITH", "CHANGE_ME", "your-secret"))
        return self._enabled and bool(self._base_url) and not placeholder

    async def lookup_indicator(
        self,
        indicator: str,
        indicator_type: str | None = None,
    ) -> MISPEnrichmentResult:
        """Query MISP for indicator matches (/attributes/restSearch).

        Args:
            indicator: IP address, domain, or hash to query.
            indicator_type: Optional MISP type filter (e.g. "ip-dst", "domain").

        Returns:
            MISPEnrichmentResult: Typed result with matches or explicit partial failure status.
        """
        clean_indicator = indicator.strip()
        now = time.time()

        if not clean_indicator:
            return MISPEnrichmentResult(
                indicator=indicator,
                status=MISPLookupStatus.ERROR,
                retrieved_at=now,
                error_message="Indicator value is empty",
            )

        if not self.is_enabled:
            return MISPEnrichmentResult(
                indicator=clean_indicator,
                status=MISPLookupStatus.DISABLED,
                retrieved_at=now,
                error_message="MISP integration is not configured or disabled",
            )

        endpoint = f"{self._base_url}/attributes/restSearch"
        payload: dict[str, Any] = {
            "value": clean_indicator,
            "limit": 10,
        }
        if indicator_type:
            payload["type"] = indicator_type

        # Bounded retry loop for transient failures
        last_error: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                async with httpx.AsyncClient(
                    verify=self._verify_ssl,
                    timeout=self._timeout,
                ) as client:
                    response = await client.post(
                        endpoint,
                        json=payload,
                        headers=self._headers,
                    )

                    if response.status_code in (401, 403):
                        logger.error("misp_auth_failed", status_code=response.status_code)
                        raise MISPAuthError(
                            f"MISP API authentication rejected (HTTP {response.status_code})"
                        )

                    if response.status_code >= 400:
                        raise MISPAPIError(
                            f"MISP search returned HTTP {response.status_code}",
                            status_code=response.status_code,
                        )

                    data = response.json()
                    attributes = []
                    # MISP restSearch format: {"response": {"Attribute": [...]}}
                    if isinstance(data, dict):
                        resp_obj = data.get("response", {})
                        if isinstance(resp_obj, dict):
                            attributes = resp_obj.get("Attribute", [])
                        elif isinstance(resp_obj, list):
                            attributes = resp_obj

                    matches: list[MISPIndicatorMatch] = []
                    for attr in attributes:
                        if not isinstance(attr, dict):
                            continue
                        event = attr.get("Event", {}) if isinstance(attr.get("Event"), dict) else {}
                        event_info = str(event.get("info") or attr.get("comment") or "")
                        # Treat external description as passive text
                        clean_info = event_info[:200]

                        matches.append(
                            MISPIndicatorMatch(
                                indicator=str(attr.get("value", clean_indicator)),
                                category=str(attr.get("category", "Network activity")),
                                attribute_type=str(attr.get("type", "ip-dst")),
                                event_id=str(attr.get("event_id") or event.get("id") or "unknown"),
                                event_info=clean_info,
                                threat_level_id=attr.get("threat_level_id") or event.get("threat_level_id"),
                                confidence=0.85 if attr.get("to_ids") else 0.7,
                                timestamp=str(attr.get("timestamp") or ""),
                                tags=[str(t.get("name", "")) for t in attr.get("Tag", []) if isinstance(t, dict)],
                            )
                        )

                    if not matches:
                        return MISPEnrichmentResult(
                            indicator=clean_indicator,
                            status=MISPLookupStatus.NO_MATCH,
                            retrieved_at=now,
                            matches=[],
                            match_count=0,
                            confidence=0.0,
                            is_confirmed_safe=False,  # Unseen in MISP != safe!
                        )

                    return MISPEnrichmentResult(
                        indicator=clean_indicator,
                        status=MISPLookupStatus.MATCH_FOUND,
                        retrieved_at=now,
                        matches=matches,
                        match_count=len(matches),
                        confidence=max(m.confidence for m in matches),
                        is_confirmed_safe=False,
                    )

            except MISPAuthError as err:
                # Auth errors are not retryable
                return MISPEnrichmentResult(
                    indicator=clean_indicator,
                    status=MISPLookupStatus.ERROR,
                    retrieved_at=now,
                    error_message=str(err),
                )
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as err:
                last_error = err
                if attempt < self._max_retries:
                    await asyncio.sleep(0.2 * (attempt + 1))
                    continue
            except httpx.HTTPError as err:
                last_error = err
                break
            except Exception as err:
                last_error = err
                break

        # Fallback if connection failed or retries exhausted
        logger.warning("misp_lookup_failed", indicator=clean_indicator, error=str(last_error))
        return MISPEnrichmentResult(
            indicator=clean_indicator,
            status=MISPLookupStatus.SERVICE_UNAVAILABLE,
            retrieved_at=now,
            error_message=f"MISP lookup unavailable: {last_error}",
            is_confirmed_safe=False,
        )

    async def check_health(self) -> ServiceHealth:
        """Check MISP connectivity and health."""
        if not self.is_enabled:
            return ServiceHealth(
                name="misp",
                status=ServiceStatus.UNKNOWN,
                detail="MISP integration disabled or not configured",
            )

        try:
            async with httpx.AsyncClient(
                verify=self._verify_ssl,
                timeout=min(self._timeout, 4.0),
            ) as client:
                resp = await client.get(
                    f"{self._base_url}/servers/getVersion",
                    headers=self._headers,
                )
                if resp.status_code == 200:
                    return ServiceHealth(
                        name="misp",
                        status=ServiceStatus.OK,
                        detail=f"MISP reachable at {self._base_url}",
                    )
                if resp.status_code in (401, 403):
                    return ServiceHealth(
                        name="misp",
                        status=ServiceStatus.DOWN,
                        detail="MISP authentication failed (invalid API key)",
                    )
                return ServiceHealth(
                    name="misp",
                    status=ServiceStatus.DEGRADED,
                    detail=f"MISP returned HTTP {resp.status_code}",
                )
        except Exception as err:
            return ServiceHealth(
                name="misp",
                status=ServiceStatus.DOWN,
                detail=f"MISP connection failed: {err}",
            )
