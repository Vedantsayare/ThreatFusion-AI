"""
api/auth.py — API-key authentication and role-based authorization.

Design:
- Keys are configured via the API_KEYS environment variable as comma-separated
  "name:role:key" triples. The principal *name* becomes the actor recorded in
  audit events — reviewers can never self-declare an identity in a request body.
- Roles are strictly ordered: viewer < analyst < approver < admin.
- Fail closed: if no valid keys are configured, every protected endpoint
  returns 401. Keys containing placeholder markers are ignored.
- Keys are compared with hmac.compare_digest against SHA-256 digests so the
  plaintext keys are not kept in the lookup table.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable, Coroutine
from enum import IntEnum
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from core.logger import get_logger

logger = get_logger("api.auth")

PLACEHOLDER_MARKERS = ("CHANGE_ME", "REPLACE_WITH", "your-secret")
MIN_KEY_LENGTH = 16


class Role(IntEnum):
    """Ordered roles; a higher value includes every lower permission."""

    VIEWER = 10
    ANALYST = 20
    APPROVER = 30
    ADMIN = 40


class Principal(BaseModel):
    """Authenticated caller."""

    model_config = ConfigDict(frozen=True)

    name: str
    role: Role

    @property
    def role_name(self) -> str:
        return self.role.name.lower()


class APIKeyRegistry:
    """Holds hashed API keys and resolves bearer tokens to principals."""

    def __init__(self, spec: str = "") -> None:
        self._entries: list[tuple[bytes, Principal]] = []
        self.rejected_entries = 0
        for raw in (part.strip() for part in spec.split(",")):
            if not raw:
                continue
            pieces = raw.split(":", 2)
            if len(pieces) != 3:
                self.rejected_entries += 1
                continue
            name, role_name, key = (p.strip() for p in pieces)
            role = Role.__members__.get(role_name.upper())
            if (
                not name
                or role is None
                or len(key) < MIN_KEY_LENGTH
                or any(marker in key for marker in PLACEHOLDER_MARKERS)
            ):
                self.rejected_entries += 1
                continue
            self._entries.append((self._digest(key), Principal(name=name, role=role)))

        if self.rejected_entries:
            logger.warning("api_keys_rejected", count=self.rejected_entries)

    @staticmethod
    def _digest(key: str) -> bytes:
        return hashlib.sha256(key.encode("utf-8")).digest()

    @property
    def configured(self) -> bool:
        return bool(self._entries)

    def resolve(self, token: str) -> Principal | None:
        digest = self._digest(token)
        match: Principal | None = None
        # Compare against every entry to keep timing independent of position.
        for stored, principal in self._entries:
            if hmac.compare_digest(stored, digest):
                match = principal
        return match


_registry = APIKeyRegistry()


def configure_registry(registry: APIKeyRegistry) -> None:
    """Install the key registry used by the auth dependencies."""
    global _registry
    _registry = registry


def get_registry() -> APIKeyRegistry:
    return _registry


def _extract_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() == "bearer" and value.strip():
        return value.strip()
    api_key = request.headers.get("x-api-key", "").strip()
    return api_key or None


async def get_principal(request: Request) -> Principal:
    """Authenticate the caller or raise 401 (429 while locked out after failures)."""
    guard = getattr(request.app.state, "auth_guard", None)
    client = request.client.host if request.client else "unknown"
    if guard is not None:
        locked = guard.locked_for(client)
        if locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed authentication attempts; try again later",
                headers={"Retry-After": str(int(locked) + 1)},
            )
    token = _extract_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key (send 'Authorization: Bearer <key>')",
            headers={"WWW-Authenticate": "Bearer"},
        )
    principal = _registry.resolve(token)
    if principal is None:
        if guard is not None:
            guard.record_failure(client)
        logger.warning("api_auth_failed", client=client, path=request.url.path)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_role(minimum: Role) -> Callable[..., Coroutine[Any, Any, Principal]]:
    """Dependency factory enforcing a minimum role."""

    async def _dependency(principal: Principal = Depends(get_principal)) -> Principal:
        if principal.role < minimum:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{principal.role_name}' lacks permission; requires '{minimum.name.lower()}'",
            )
        return principal

    return _dependency


require_viewer = require_role(Role.VIEWER)
require_analyst = require_role(Role.ANALYST)
require_approver = require_role(Role.APPROVER)
