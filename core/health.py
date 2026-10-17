"""
core/health.py - Lightweight health-check data model.

Each external dependency reports its health; the aggregated result is used
by the /health FastAPI endpoint (Phase 9) and by the Phase 0 smoke test.
This module intentionally has NO live connection logic - that belongs to
the individual client modules (database.py, redis_client.py, neo4j_client.py).
"""

from __future__ import annotations

from enum import Enum
from typing import Any


class ServiceStatus(str, Enum):
    """Canonical status values for a service health check."""

    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"


class ServiceHealth:
    """Health result for a single dependency."""

    __slots__ = ("name", "status", "detail")

    def __init__(
        self,
        name: str,
        status: ServiceStatus,
        detail: str = "",
    ) -> None:
        self.name = name
        self.status = status
        self.detail = detail

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "detail": self.detail,
        }


class SystemHealth:
    """Aggregate health of all monitored services.

    Precedence contract (highest severity wins):
      DOWN > DEGRADED = UNKNOWN > OK

    An empty service list returns UNKNOWN - not OK - because a readiness
    check that has registered no probes cannot assert the system is healthy.
    Callers that depend on this value for traffic-readiness decisions must
    treat UNKNOWN as non-ready.
    """

    def __init__(self, services: list[ServiceHealth]) -> None:
        self._services = services

    @property
    def overall(self) -> ServiceStatus:
        if not self._services:
            # No probes registered: we cannot assert the system is healthy.
            return ServiceStatus.UNKNOWN

        statuses = {s.status for s in self._services}
        if ServiceStatus.DOWN in statuses:
            return ServiceStatus.DOWN
        if ServiceStatus.DEGRADED in statuses or ServiceStatus.UNKNOWN in statuses:
            return ServiceStatus.DEGRADED
        return ServiceStatus.OK

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall": self.overall.value,
            "services": [s.to_dict() for s in self._services],
        }
