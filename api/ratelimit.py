"""
api/ratelimit.py — Request throttling, auth brute-force lockout, streaming body limit.

All state is in-process (one uvicorn worker, see docs/SECURITY.md). Clients are
identified by the socket peer address; behind a reverse proxy every request
shares the proxy's address, so put rate limiting at the proxy in that setup.

- SlidingWindowLimiter: at most N requests per client per window.
- AuthFailureGuard: after N failed authentications from one client within the
  window, every request from it gets 429 until the window passes (valid keys
  included, so a guessing client cannot tell when it found a valid key).
- BodySizeLimitMiddleware: buffers at most max_bytes of the body before the app
  runs, so chunked uploads without Content-Length are limited too (413).
"""

from __future__ import annotations

import json
import time
from collections import deque
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

EXEMPT_PATHS = frozenset({"/health/live"})


def client_key(scope: Scope) -> str:
    client = scope.get("client")
    return str(client[0]) if client else "unknown"


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float, max_clients: int = 10_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_clients = max_clients
        self._hits: dict[str, deque[float]] = {}

    def hit(self, key: str, now: float | None = None) -> float:
        """Record a request. Returns 0 if allowed, else seconds until retry."""
        if self.limit <= 0:
            return 0.0
        t = time.monotonic() if now is None else now
        q = self._hits.get(key)
        if q is None:
            if len(self._hits) >= self.max_clients:
                self._hits.pop(next(iter(self._hits)))
            q = self._hits[key] = deque()
        while q and q[0] <= t - self.window:
            q.popleft()
        if len(q) >= self.limit:
            return max(0.1, q[0] + self.window - t)
        q.append(t)
        return 0.0


class AuthFailureGuard:
    def __init__(self, max_failures: int, window_seconds: float) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._failures: dict[str, deque[float]] = {}

    def _prune(self, key: str, t: float) -> deque[float]:
        q = self._failures.setdefault(key, deque())
        while q and q[0] <= t - self.window:
            q.popleft()
        return q

    def locked_for(self, key: str, now: float | None = None) -> float:
        """Seconds the client remains locked out (0 if not locked)."""
        if self.max_failures <= 0:
            return 0.0
        t = time.monotonic() if now is None else now
        q = self._prune(key, t)
        if len(q) >= self.max_failures:
            return max(0.1, q[0] + self.window - t)
        return 0.0

    def record_failure(self, key: str, now: float | None = None) -> None:
        if self.max_failures <= 0:
            return
        t = time.monotonic() if now is None else now
        self._prune(key, t).append(t)


async def _reject(send: Send, status: int, detail: str, headers: list[tuple[bytes, bytes]] | None = None) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
        + (headers or []),
    })
    await send({"type": "http.response.body", "body": body})


class RateLimitMiddleware:
    def __init__(self, app: ASGIApp, limiter: SlidingWindowLimiter) -> None:
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return
        retry = self.limiter.hit(client_key(scope))
        if retry:
            await _reject(send, 429, "Rate limit exceeded", [(b"retry-after", str(int(retry) + 1).encode())])
            return
        await self.app(scope, receive, send)


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    if int(value) > self.max_bytes:
                        await _reject(send, 413, f"Request body exceeds {self.max_bytes} bytes")
                        return
                except ValueError:
                    await _reject(send, 400, "Invalid Content-Length")
                    return

        # Buffer the body (bounded by max_bytes) before the app sees it, so an
        # oversized chunked upload is rejected with 413 and never reaches the app.
        chunks: list[bytes] = []
        received = 0
        more = True
        while more:
            message = await receive()
            if message["type"] != "http.request":
                await self.app(scope, _replay([], message, receive), send)
                return
            body = message.get("body", b"")
            received += len(body)
            if received > self.max_bytes:
                await _reject(send, 413, f"Request body exceeds {self.max_bytes} bytes")
                return
            chunks.append(body)
            more = bool(message.get("more_body", False))

        await self.app(scope, _replay(chunks, None, receive), send)


def _replay(chunks: list[bytes], pending: Message | None, receive: Receive) -> Receive:
    """Receive callable that yields the buffered body once, then defers to the server."""
    sent = False

    async def replay() -> Message:
        nonlocal sent
        if pending is not None and not sent:
            sent = True
            return pending
        if not sent:
            sent = True
            return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
        return await receive()

    return replay


class BodyTooLargeError(Exception):
    """Raised while streaming a request body past the configured limit."""
