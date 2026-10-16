"""
tests/unit/test_health.py — Unit tests for core.health data models.

Verifies the aggregation logic of SystemHealth without any live service connections.
"""

from __future__ import annotations

from core.health import ServiceHealth, ServiceStatus, SystemHealth


class TestServiceStatus:
    def test_string_values(self) -> None:
        assert ServiceStatus.OK.value == "ok"
        assert ServiceStatus.DEGRADED.value == "degraded"
        assert ServiceStatus.DOWN.value == "down"
        assert ServiceStatus.UNKNOWN.value == "unknown"


class TestServiceHealth:
    def test_to_dict_contains_required_keys(self) -> None:
        svc = ServiceHealth("postgres", ServiceStatus.OK, "ping: 2ms")
        d = svc.to_dict()
        assert d["name"] == "postgres"
        assert d["status"] == "ok"
        assert d["detail"] == "ping: 2ms"

    def test_default_detail_is_empty_string(self) -> None:
        svc = ServiceHealth("redis", ServiceStatus.UNKNOWN)
        assert svc.to_dict()["detail"] == ""


class TestSystemHealth:
    def test_all_ok_reports_ok(self) -> None:
        system = SystemHealth([
            ServiceHealth("postgres", ServiceStatus.OK),
            ServiceHealth("redis", ServiceStatus.OK),
            ServiceHealth("neo4j", ServiceStatus.OK),
        ])
        assert system.overall == ServiceStatus.OK

    def test_one_down_reports_down(self) -> None:
        system = SystemHealth([
            ServiceHealth("postgres", ServiceStatus.OK),
            ServiceHealth("redis", ServiceStatus.DOWN, "connection refused"),
            ServiceHealth("neo4j", ServiceStatus.OK),
        ])
        assert system.overall == ServiceStatus.DOWN

    def test_one_unknown_reports_degraded(self) -> None:
        system = SystemHealth([
            ServiceHealth("postgres", ServiceStatus.OK),
            ServiceHealth("neo4j", ServiceStatus.UNKNOWN),
        ])
        assert system.overall == ServiceStatus.DEGRADED

    def test_one_degraded_reports_degraded(self) -> None:
        system = SystemHealth([
            ServiceHealth("postgres", ServiceStatus.DEGRADED),
            ServiceHealth("redis", ServiceStatus.OK),
        ])
        assert system.overall == ServiceStatus.DEGRADED

    def test_down_takes_priority_over_degraded(self) -> None:
        system = SystemHealth([
            ServiceHealth("redis", ServiceStatus.DEGRADED),
            ServiceHealth("neo4j", ServiceStatus.DOWN),
        ])
        assert system.overall == ServiceStatus.DOWN

    def test_to_dict_overall_and_services(self) -> None:
        system = SystemHealth([
            ServiceHealth("postgres", ServiceStatus.OK, ""),
        ])
        d = system.to_dict()
        assert d["overall"] == "ok"
        assert len(d["services"]) == 1
        assert d["services"][0]["name"] == "postgres"

    def test_empty_services_list_returns_ok(self) -> None:
        """Edge case: no monitored services → healthy by default."""
        system = SystemHealth([])
        assert system.overall == ServiceStatus.OK
