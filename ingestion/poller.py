"""
ingestion/poller.py — Bounded, paginated alert ingestion for the Wazuh API.

Retrieves security alerts through the existing WazuhClient, handles pagination,
deduplication, bounded retries, overlap prevention, and graceful shutdown.
Raw alert data is preserved without modification for downstream processing.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import Any

from core.config import AppSettings, get_settings
from core.logger import get_logger
from ingestion.wazuh_client import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhClient,
    WazuhConnectionError,
    WazuhError,
    WazuhTLSError,
)

logger = get_logger("ingestion.poller")

# Type alias for downstream alert handler callback
AlertHandler = Callable[[list[dict[str, Any]]], Coroutine[Any, Any, None]]


class WazuhIngestionError(WazuhError):
    """Base exception for Wazuh alert ingestion errors."""


class IngestionMaxRetriesError(WazuhIngestionError):
    """Raised when an operation exceeds maximum retry attempts."""

    def __init__(self, message: str, attempts: int, last_error: Exception) -> None:
        super().__init__(message)
        self.attempts = attempts
        self.last_error = last_error


class IngestionMalformedResponseError(WazuhIngestionError):
    """Raised when the Wazuh API returns an unparseable or schema-violating payload."""


@dataclass(frozen=True)
class RawAlertBatch:
    """Container for a batch of ingested raw alerts with query metadata."""

    alerts: list[dict[str, Any]]
    total_available: int
    offset: int
    limit: int
    polled_at: float
    endpoint: str
    metadata: dict[str, Any] = field(default_factory=dict)


class WazuhAlertPoller:
    """Configurable, robust poller for retrieving Wazuh security alerts.

    Features:
    - Bounded retries with exponential backoff on transient/retryable network errors.
    - Non-retryable errors (auth, TLS, 4xx) abort immediately to prevent wasted cycles.
    - Pagination support (iterates through batches using limit and offset).
    - Watermarking and bounded ID deduplication to avoid re-processing historical alerts.
    - Overlap prevention (async lock ensures one poll execution at a time).
    - Graceful startup and shutdown lifecycle management.
    - Safe handling of untrusted input and malformed responses.
    - Preserves raw alert payloads for downstream normalization (Phase 3+).
    """

    def __init__(
        self,
        client: WazuhClient,
        settings: AppSettings | None = None,
        *,
        handler: AlertHandler | None = None,
        max_seen_ids: int = 10_000,
    ) -> None:
        self._client = client
        self._settings = settings or get_settings()
        self._handler = handler

        self._endpoint = self._settings.wazuh_alerts_endpoint
        self._batch_size = self._settings.wazuh_batch_size
        self._poll_interval = float(self._settings.wazuh_poll_interval_seconds)
        self._max_retries = self._settings.wazuh_max_retries
        self._retry_backoff = float(self._settings.wazuh_retry_backoff_seconds)

        self._max_seen_ids = max_seen_ids
        self._seen_ids: set[str] = set()
        self._seen_ids_order: list[str] = []

        self._last_timestamp: str | None = None
        self._poll_lock = asyncio.Lock()

        self._running = False
        self._stop_event = asyncio.Event()
        self._loop_task: asyncio.Task[None] | None = None

    @property
    def is_running(self) -> bool:
        """Return True if the background polling loop is active."""
        return self._running

    @property
    def seen_count(self) -> int:
        """Return count of deduplicated alert IDs currently cached."""
        return len(self._seen_ids)

    @property
    def last_watermark(self) -> str | None:
        """Return the latest timestamp watermark processed."""
        return self._last_timestamp

    def _extract_alert_id(self, alert: dict[str, Any]) -> str | None:
        """Extract a unique identifier from a raw alert dictionary safely."""
        # Standard Wazuh alerts contain "id" or "_id"
        raw_id = alert.get("id") or alert.get("_id")
        if raw_id:
            return str(raw_id).strip()

        # Fallback composite key for alerts lacking explicit id:
        # timestamp + agent.id + rule.id
        ts = str(alert.get("timestamp", "")).strip()
        rule = alert.get("rule")
        rule_id = str(rule.get("id", "")).strip() if isinstance(rule, dict) else ""
        agent = alert.get("agent")
        agent_id = str(agent.get("id", "")).strip() if isinstance(agent, dict) else ""

        if ts and (rule_id or agent_id):
            return f"{ts}:{agent_id}:{rule_id}"

        return None

    def _record_seen_id(self, alert_id: str) -> None:
        """Record an alert ID in the bounded FIFO cache."""
        if alert_id in self._seen_ids:
            return

        if len(self._seen_ids) >= self._max_seen_ids:
            oldest = self._seen_ids_order.pop(0)
            self._seen_ids.discard(oldest)

        self._seen_ids.add(alert_id)
        self._seen_ids_order.append(alert_id)

    def _extract_timestamp(self, alert: dict[str, Any]) -> str | None:
        """Safely extract ISO timestamp string without executing untrusted data."""
        ts = alert.get("timestamp")
        if isinstance(ts, str) and ts.strip():
            return ts.strip()
        return None

    def _validate_response_schema(self, response: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
        """Validate Wazuh API response schema and return (valid_items, total_count).

        Accepts standard Wazuh collection schemas:
        - data.affected_items (Wazuh 4 collection standard)
        - data.items (Wazuh collection alternative)
        - data as a direct list

        Raises:
            IngestionMalformedResponseError: If response is not a dict or has error != 0.
        """
        if not isinstance(response, dict):
            raise IngestionMalformedResponseError(
                f"Wazuh API response must be a JSON object, got: {type(response).__name__}"
            )

        if response.get("error", 0) != 0:
            err_code = response.get("error")
            msg = response.get("message", response.get("detail", "Unknown error"))
            raise IngestionMalformedResponseError(
                f"Wazuh API returned error {err_code}: {msg}"
            )

        data = response.get("data")
        raw_items: list[Any] = []
        total_available = 0

        if isinstance(data, dict):
            if "affected_items" in data and isinstance(data["affected_items"], list):
                raw_items = data["affected_items"]
                total_available = int(data.get("total_affected_items", len(raw_items)))
            elif "items" in data and isinstance(data["items"], list):
                raw_items = data["items"]
                total_available = int(data.get("total_affected_items", len(raw_items)))
            else:
                raise IngestionMalformedResponseError(
                    "Wazuh API response 'data' object missing 'affected_items' or 'items' list"
                )
        elif isinstance(data, list):
            raw_items = data
            total_available = len(raw_items)
        elif data is None:
            raw_items = []
            total_available = 0
        else:
            raise IngestionMalformedResponseError(
                f"Wazuh API 'data' field must be an object or list, got: {type(data).__name__}"
            )

        # Validate that each alert item is a dictionary (treat fields as untrusted)
        valid_items: list[dict[str, Any]] = []
        for idx, item in enumerate(raw_items):
            if isinstance(item, dict):
                valid_items.append(item)
            else:
                logger.warning(
                    "wazuh_malformed_item_skipped",
                    index=idx,
                    expected="dict",
                    got=type(item).__name__,
                )

        return valid_items, total_available

    async def fetch_page(
        self,
        offset: int = 0,
        limit: int | None = None,
        params: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Fetch a single page of alerts with bounded retries and backoff.

        Raises:
            WazuhAuthError: On authentication failure (aborts immediately without retrying).
            WazuhTLSError: On certificate verification failure (aborts immediately).
            IngestionMaxRetriesError: When transient errors exceed max retry attempts.
            IngestionMalformedResponseError: If response fails schema validation.
        """
        page_limit = limit if limit is not None else self._batch_size
        query_params: dict[str, Any] = {
            "offset": offset,
            "limit": page_limit,
            "sort": "+timestamp",
        }
        if params:
            query_params.update(params)

        attempt = 0
        last_error: Exception | None = None

        while attempt < self._max_retries:
            attempt += 1
            try:
                logger.debug(
                    "wazuh_fetching_page",
                    endpoint=self._endpoint,
                    offset=offset,
                    limit=page_limit,
                    attempt=attempt,
                )
                response = await self._client.get(self._endpoint, params=query_params)
                return self._validate_response_schema(response)

            except (WazuhAuthError, WazuhTLSError):
                # Non-retryable: credentials or cert configuration will not succeed on retry
                raise

            except IngestionMalformedResponseError:
                # Schema/malformed response errors are non-retryable and must be preserved
                raise

            except WazuhAPIError as err:
                last_error = err
                # 4xx client errors (other than 401 which is handled by client) are non-retryable
                if 400 <= err.status_code < 500:
                    raise WazuhIngestionError(
                        f"Non-retryable Wazuh API error {err.status_code}: {err}"
                    ) from err

                # 5xx server errors are retryable
                if attempt >= self._max_retries:
                    break

                backoff = self._retry_backoff * (2 ** (attempt - 1))
                logger.warning(
                    "wazuh_fetch_retryable_api_error",
                    status_code=err.status_code,
                    attempt=attempt,
                    next_retry_delay=backoff,
                )
                await asyncio.sleep(backoff)

            except WazuhConnectionError as err:
                last_error = err
                if attempt >= self._max_retries:
                    break

                backoff = self._retry_backoff * (2 ** (attempt - 1))
                logger.warning(
                    "wazuh_fetch_connection_error",
                    error=str(err),
                    attempt=attempt,
                    next_retry_delay=backoff,
                )
                await asyncio.sleep(backoff)

            except asyncio.CancelledError:
                # Cooperative cancellation must never be swallowed
                raise

            except Exception as err:
                raise WazuhIngestionError(f"Unexpected error fetching alerts: {err}") from err

        raise IngestionMaxRetriesError(
            f"Failed to fetch alerts from {self._endpoint} after {attempt} attempts: {last_error}",
            attempts=attempt,
            last_error=last_error if last_error is not None else Exception("Unknown error"),
        )

    async def poll_once(self) -> RawAlertBatch:
        """Execute a single polling run across all available pages for this cycle.

        Prevents overlapping execution via an asyncio Lock.
        Applies watermark updates and bounded deduplication.
        Passes newly ingested raw alerts to registered handler if present.

        Returns:
            RawAlertBatch: Container holding all newly ingested raw alerts for this cycle.
        """
        if self._poll_lock.locked():
            logger.warning(
                "wazuh_poll_overlap_skipped",
                reason="Previous polling run still in progress",
            )
            return RawAlertBatch(
                alerts=[],
                total_available=0,
                offset=0,
                limit=self._batch_size,
                polled_at=time.time(),
                endpoint=self._endpoint,
            )

        async with self._poll_lock:
            polled_at = time.time()
            offset = 0
            all_new_alerts: list[dict[str, Any]] = []
            total_seen_in_run = 0

            logger.info("wazuh_poll_started", endpoint=self._endpoint, batch_size=self._batch_size)

            try:
                while True:
                    items, total_available = await self.fetch_page(offset=offset, limit=self._batch_size)
                    total_seen_in_run = total_available

                    if not items:
                        break

                    for alert in items:
                        alert_id = self._extract_alert_id(alert)
                        if alert_id:
                            if alert_id in self._seen_ids:
                                continue
                            self._record_seen_id(alert_id)

                        # Treat content as untrusted input; preserve raw payload
                        all_new_alerts.append(alert)

                        ts = self._extract_timestamp(alert)
                        if ts:
                            self._last_timestamp = ts

                    offset += len(items)

                    # Bounded termination: stop if we reached total or received partial batch
                    if offset >= total_available or len(items) < self._batch_size:
                        break

            except IngestionMaxRetriesError as err:
                logger.error(
                    "wazuh_poll_failed_max_retries",
                    attempts=err.attempts,
                    error=str(err.last_error),
                )
                # Yield partial progress gathered before failure
            except (WazuhAuthError, WazuhTLSError) as err:
                logger.error("wazuh_poll_fatal_auth_or_tls_error", error=str(err))
                raise
            except Exception as err:
                logger.error("wazuh_poll_unexpected_failure", error=str(err))
                raise

            # Dispatch raw alerts to downstream handler if registered
            if self._handler and all_new_alerts:
                try:
                    await self._handler(all_new_alerts)
                except Exception as err:
                    logger.error("wazuh_handler_failed", error=str(err))

            logger.info(
                "wazuh_poll_completed",
                new_alerts=len(all_new_alerts),
                total_available=total_seen_in_run,
                cached_ids=len(self._seen_ids),
                watermark=self._last_timestamp,
            )

            return RawAlertBatch(
                alerts=all_new_alerts,
                total_available=total_seen_in_run,
                offset=0,
                limit=offset,
                polled_at=polled_at,
                endpoint=self._endpoint,
            )

    async def _poll_loop(self) -> None:
        """Internal background loop running until stop() is requested."""
        while self._running:
            try:
                await self.poll_once()
            except (WazuhAuthError, WazuhTLSError):
                # Fatal configuration issues: log and halt loop to avoid tight failure cycles
                logger.critical("wazuh_poll_loop_halted_on_fatal_error")
                self._running = False
                break
            except Exception as err:
                logger.error("wazuh_poll_loop_iteration_error", error=str(err))

            # Sleep for poll_interval, but wake immediately if stop_event is signaled
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self._poll_interval)
                break  # stop_event was signaled
            except TimeoutError:
                continue
            except asyncio.CancelledError:
                break

    async def start(self) -> None:
        """Start the background alert polling loop."""
        if self._running:
            return

        self._running = True
        self._stop_event.clear()
        self._loop_task = asyncio.create_task(self._poll_loop())
        logger.info(
            "wazuh_poller_started",
            interval=self._poll_interval,
            endpoint=self._endpoint,
        )

    async def stop(self) -> None:
        """Stop the background polling loop gracefully."""
        if not self._running:
            return

        self._running = False
        self._stop_event.set()

        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except asyncio.CancelledError:
                pass

        logger.info("wazuh_poller_stopped")

    async def __aenter__(self) -> WazuhAlertPoller:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.stop()
