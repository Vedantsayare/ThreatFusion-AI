"""
normalization/normalizer.py — Deterministic OCSF normalizer for Wazuh alerts.

Converts raw, untrusted Wazuh alert dictionaries into validated OCSFSecurityFinding
models (project-specific OCSF 1.1.0 subset).
Preserves raw alert data verbatim, handles malformed/missing fields safely,
and enforces deterministic mapping without external/LLM calls.
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from typing import Any

from core.logger import get_logger
from normalization.mitre import lookup_technique
from normalization.models import (
    OCSFAttack,
    OCSFDevice,
    OCSFEndpoint,
    OCSFFindingInfo,
    OCSFMetadata,
    OCSFProcess,
    OCSFProduct,
    OCSFSecurityFinding,
    OCSFTactic,
    OCSFTechnique,
    OCSFUser,
)

logger = get_logger("normalization.normalizer")


class NormalizationError(Exception):
    """Base exception for normalization failures."""


class AlertSchemaError(NormalizationError):
    """Raised when an alert payload is fundamentally malformed or invalid."""


class OCSFNormalizer:
    """Deterministic, robust normalizer converting Wazuh alerts to OCSF Security Findings.

    Conforms to a project-specific subset of OCSF v1.1.0 (Class 2001: Security Finding).
    Treats all incoming alert fields as untrusted input.
    """

    def normalize(self, raw_alert: dict[str, Any]) -> OCSFSecurityFinding:
        """Convert a single raw Wazuh alert dictionary to an OCSFSecurityFinding.

        Args:
            raw_alert: Untrusted dictionary representation of a Wazuh alert.

        Returns:
            OCSFSecurityFinding: Validated, normalized security finding model.

        Raises:
            AlertSchemaError: If raw_alert is not a dictionary.
        """
        if not isinstance(raw_alert, dict):
            raise AlertSchemaError(
                f"Expected raw_alert to be a dictionary, got {type(raw_alert).__name__}"
            )

        unmapped: dict[str, Any] = {}

        # 1. Finding UID (Wazuh alert ID or deterministic composite fallback)
        uid, id_generated = self._extract_finding_uid(raw_alert)
        if id_generated:
            unmapped["id_generated"] = True

        # 2. Timestamp extraction and parsing
        event_time_ms, original_time_str = self._parse_timestamp(raw_alert, unmapped)

        # 3. Severity mapping from Wazuh rule level (0-16) to OCSF severity_id (0-6)
        rule = raw_alert.get("rule")
        rule_dict = rule if isinstance(rule, dict) else {}
        severity_id, severity_name = self._map_severity(rule_dict.get("level"))

        # 4. Finding info
        finding_info = self._extract_finding_info(
            uid=uid,
            raw_alert=raw_alert,
            rule_dict=rule_dict,
            event_time_ms=event_time_ms,
        )

        # 5. Metadata
        metadata = OCSFMetadata(
            version="1.1.0",
            schema_name="project_ocsf_subset",
            product=OCSFProduct(
                name="Wazuh",
                vendor_name="Wazuh",
                version=self._safe_str(raw_alert.get("cluster", {}).get("name") if isinstance(raw_alert.get("cluster"), dict) else None),
            ),
            original_time=original_time_str,
        )

        # 6. Device (Agent or Manager)
        device = self._extract_device(raw_alert)

        # 7. Endpoints (Source and Destination)
        src_endpoint, dst_endpoint = self._extract_endpoints(raw_alert)

        # 8. User entity
        user = self._extract_user(raw_alert)

        # 8b. Process context (Windows eventdata / Linux command fields)
        process = self._extract_process(raw_alert)

        # 9. ATT&CK techniques
        attacks = self._extract_attacks(rule_dict, unmapped)

        # 10. Message
        message = self._extract_message(raw_alert, rule_dict)

        # 11. Preserve unmapped vendor-specific attributes
        self._collect_unmapped_fields(raw_alert, unmapped)

        return OCSFSecurityFinding(
            class_uid=2001,
            class_name="Security Finding",
            category_uid=2,
            category_name="Findings",
            activity_id=1,
            activity_name="Create",
            severity_id=severity_id,
            severity=severity_name,
            status_id=1,
            status="New",
            time=event_time_ms,
            metadata=metadata,
            finding_info=finding_info,
            device=device,
            src_endpoint=src_endpoint,
            dst_endpoint=dst_endpoint,
            user=user,
            process=process,
            attacks=attacks,
            message=message,
            raw_data=raw_alert,
            unmapped=unmapped,
        )

    def normalize_batch(
        self,
        batch: Any,
        skip_malformed: bool = True,
    ) -> list[OCSFSecurityFinding]:
        """Normalize a batch of raw alerts.

        Args:
            batch: Either a list of dictionaries or an object with an .alerts attribute (e.g. RawAlertBatch).
            skip_malformed: When True, logs and omits malformed alerts. When False, raises immediately.

        Returns:
            list[OCSFSecurityFinding]: Normalized events.
        """
        raw_list: list[Any]
        if hasattr(batch, "alerts") and isinstance(batch.alerts, list):
            raw_list = batch.alerts
        elif isinstance(batch, list):
            raw_list = batch
        else:
            raise AlertSchemaError(
                f"Expected batch to be a list or RawAlertBatch, got {type(batch).__name__}"
            )

        results: list[OCSFSecurityFinding] = []
        for index, item in enumerate(raw_list):
            try:
                results.append(self.normalize(item))
            except Exception as err:
                if not skip_malformed:
                    raise
                logger.warning(
                    "normalization_skipped_malformed_alert",
                    index=index,
                    error=str(err),
                )

        return results

    # ── Internal extraction helpers ──────────────────────────────────────────

    def _extract_finding_uid(self, raw_alert: dict[str, Any]) -> tuple[str, bool]:
        """Extract alert ID or synthesize a deterministic composite fallback."""
        raw_id = raw_alert.get("id") or raw_alert.get("_id")
        if raw_id is not None:
            id_str = str(raw_id).strip()
            if id_str:
                return id_str, False

        # Fallback deterministic composite hash
        timestamp = raw_alert.get("timestamp", "")
        rule_id = raw_alert.get("rule", {}).get("id", "") if isinstance(raw_alert.get("rule"), dict) else ""
        agent_id = raw_alert.get("agent", {}).get("id", "") if isinstance(raw_alert.get("agent"), dict) else ""
        seed = f"{timestamp}|{rule_id}|{agent_id}"
        composite = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]
        return f"comp-{composite}", True

    def _parse_timestamp(
        self,
        raw_alert: dict[str, Any],
        unmapped: dict[str, Any],
    ) -> tuple[int, str | None]:
        """Parse raw timestamp into epoch milliseconds and preserve original string."""
        raw_ts = raw_alert.get("timestamp")
        if raw_ts is None:
            unmapped["timestamp_warning"] = "Missing timestamp in raw alert; defaulted to current time"
            return int(time.time() * 1000), None

        # Numeric timestamp
        if isinstance(raw_ts, (int, float)):
            # If > 1e11 it is already in milliseconds; otherwise seconds
            val = int(raw_ts if raw_ts > 1e11 else raw_ts * 1000)
            return val, str(raw_ts)

        # String timestamp
        if isinstance(raw_ts, str):
            ts_str = raw_ts.strip()
            if not ts_str:
                unmapped["timestamp_warning"] = "Empty timestamp in raw alert; defaulted to current time"
                return int(time.time() * 1000), ts_str

            try:
                # Handle ISO 8601 timestamps (including Wazuh format +0000 or Z)
                normalized_ts = ts_str.replace("Z", "+00:00")
                # Format: 2026-10-17T12:00:00.000+0000
                if len(normalized_ts) >= 5 and (normalized_ts[-5] in ("+", "-")) and ":" not in normalized_ts[-5:]:
                    normalized_ts = normalized_ts[:-2] + ":" + normalized_ts[-2:]

                dt = datetime.fromisoformat(normalized_ts)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return int(dt.timestamp() * 1000), ts_str
            except Exception as err:
                unmapped["timestamp_warning"] = f"Unparseable timestamp format ({err}); defaulted to current time"
                return int(time.time() * 1000), ts_str

        # Unsupported type
        unmapped["timestamp_warning"] = f"Unexpected timestamp type ({type(raw_ts).__name__}); defaulted to current time"
        return int(time.time() * 1000), str(raw_ts)

    def _map_severity(self, rule_level: Any) -> tuple[int, str]:
        """Map Wazuh rule level (0-16) to OCSF standard severity."""
        if rule_level is None:
            return 0, "Unknown"

        level_int: int
        try:
            level_int = int(rule_level)
        except (ValueError, TypeError):
            return 0, "Unknown"

        if 0 <= level_int <= 3:
            return 1, "Informational"
        if 4 <= level_int <= 6:
            return 2, "Low"
        if 7 <= level_int <= 9:
            return 3, "Medium"
        if 10 <= level_int <= 12:
            return 4, "High"
        if 13 <= level_int <= 16:
            return 5, "Critical"

        return 0, "Unknown"

    def _extract_finding_info(
        self,
        uid: str,
        raw_alert: dict[str, Any],
        rule_dict: dict[str, Any],
        event_time_ms: int,
    ) -> OCSFFindingInfo:
        """Construct FindingInfo block."""
        title = self._safe_str(rule_dict.get("description")) or "Wazuh Security Alert"
        desc = self._safe_str(raw_alert.get("full_log")) or title

        types: list[str] = []
        raw_groups = rule_dict.get("groups")
        if isinstance(raw_groups, list):
            types = [str(g).strip() for g in raw_groups if g is not None and str(g).strip()]
        elif isinstance(raw_groups, str) and raw_groups.strip():
            types = [raw_groups.strip()]

        src_url = self._safe_str(raw_alert.get("location"))

        return OCSFFindingInfo(
            uid=uid,
            title=title,
            desc=desc,
            types=types,
            created_time=event_time_ms,
            src_url=src_url,
        )

    def _extract_device(self, raw_alert: dict[str, Any]) -> OCSFDevice | None:
        """Extract Device block from agent or manager."""
        agent = raw_alert.get("agent")
        if isinstance(agent, dict) and agent:
            return OCSFDevice(
                name=self._safe_str(agent.get("name")),
                uid=self._safe_str(agent.get("id")),
                ip=self._safe_str(agent.get("ip")),
                type_id=0,
            )

        manager = raw_alert.get("manager")
        if isinstance(manager, dict) and manager:
            return OCSFDevice(
                name=self._safe_str(manager.get("name")),
                uid="000",
                ip=None,
                type_id=0,
            )

        return None

    def _extract_endpoints(
        self,
        raw_alert: dict[str, Any],
    ) -> tuple[OCSFEndpoint | None, OCSFEndpoint | None]:
        """Extract source and destination network endpoints."""
        data = raw_alert.get("data")
        data_dict = data if isinstance(data, dict) else {}

        # Protocol
        protocol = self._safe_str(data_dict.get("protocol") or raw_alert.get("protocol"))

        # Source
        src_ip = self._safe_str(
            data_dict.get("srcip")
            or data_dict.get("src_ip")
            or data_dict.get("src_addr")
            or raw_alert.get("srcip")
        )
        src_port = self._safe_port(
            data_dict.get("srcport")
            or data_dict.get("src_port")
            or raw_alert.get("srcport")
        )
        src_endpoint = (
            OCSFEndpoint(ip=src_ip, port=src_port, protocol_name=protocol)
            if (src_ip or src_port is not None)
            else None
        )

        # Destination
        dst_ip = self._safe_str(
            data_dict.get("dstip")
            or data_dict.get("dst_ip")
            or data_dict.get("dst_addr")
            or raw_alert.get("dstip")
        )
        dst_port = self._safe_port(
            data_dict.get("dstport")
            or data_dict.get("dst_port")
            or raw_alert.get("dstport")
        )
        dst_domain = self._safe_str(
            data_dict.get("dst_domain")
            or data_dict.get("domain")
            or data_dict.get("hostname")
            or raw_alert.get("dst_domain")
        )
        dst_endpoint = (
            OCSFEndpoint(ip=dst_ip, port=dst_port, protocol_name=protocol, domain=dst_domain)
            if (dst_ip or dst_port is not None or dst_domain)
            else None
        )

        return src_endpoint, dst_endpoint

    def _extract_user(self, raw_alert: dict[str, Any]) -> OCSFUser | None:
        """Extract User entity from data or top-level fields."""
        data = raw_alert.get("data")
        data_dict = data if isinstance(data, dict) else {}

        eventdata = self._windows_eventdata(data_dict)

        user_name = self._safe_str(
            data_dict.get("dstuser")
            or data_dict.get("srcuser")
            or data_dict.get("user")
            or eventdata.get("targetUserName")
            or eventdata.get("subjectUserName")
            or raw_alert.get("dstuser")
            or raw_alert.get("srcuser")
            or raw_alert.get("user")
        )

        if user_name:
            return OCSFUser(name=user_name)

        return None

    @staticmethod
    def _windows_eventdata(data_dict: dict[str, Any]) -> dict[str, Any]:
        win = data_dict.get("win")
        if isinstance(win, dict):
            eventdata = win.get("eventdata")
            if isinstance(eventdata, dict):
                return eventdata
        return {}

    def _extract_process(self, raw_alert: dict[str, Any]) -> OCSFProcess | None:
        """Extract process name / command line when the source reports them."""
        data = raw_alert.get("data")
        data_dict = data if isinstance(data, dict) else {}
        eventdata = self._windows_eventdata(data_dict)

        cmd_line = self._safe_str(
            eventdata.get("commandLine") or data_dict.get("command") or data_dict.get("cmdline")
        )
        image = self._safe_str(eventdata.get("image") or data_dict.get("process") or data_dict.get("program_name"))
        name = image
        if name is None and cmd_line:
            name = cmd_line.split()[0]
        if name and ("\\" in name or "/" in name):
            name = name.replace("\\", "/").rsplit("/", 1)[-1]
        if cmd_line is None and name is None:
            return None
        pid_raw = eventdata.get("processId") or data_dict.get("pid")
        try:
            pid = int(str(pid_raw), 0) if pid_raw is not None else None
        except ValueError:
            pid = None
        return OCSFProcess(name=name, cmd_line=cmd_line, pid=pid)

    def _extract_attacks(
        self,
        rule_dict: dict[str, Any],
        unmapped: dict[str, Any] | None = None,
    ) -> list[OCSFAttack]:
        """Extract MITRE ATT&CK tactics and techniques.

        Techniques come only from the alert. When the alert omits a technique's
        name or tactic, the static ATT&CK reference supplies the label and the
        field is recorded in ``unmapped["mitre_reference_labels"]``.
        """
        mitre = rule_dict.get("mitre")
        if not isinstance(mitre, dict):
            return []

        ids: list[str] = self._normalize_to_str_list(mitre.get("id"))
        tactics: list[str] = self._normalize_to_str_list(mitre.get("tactic"))
        techniques: list[str] = self._normalize_to_str_list(mitre.get("technique"))

        attacks: list[OCSFAttack] = []

        # If ids and techniques match in length, pair them
        count = max(len(ids), len(techniques), len(tactics))
        for i in range(count):
            uid_val = ids[i] if i < len(ids) else (ids[0] if ids else "Unknown")
            tech_name = techniques[i] if i < len(techniques) else None
            tactic_name = tactics[i] if i < len(tactics) else (tactics[0] if tactics else None)

            reference = lookup_technique(uid_val) if uid_val != "Unknown" else None
            if reference is not None and (tech_name is None or tactic_name is None):
                ref_name, ref_tactic = reference
                tech_name = tech_name or ref_name
                tactic_name = tactic_name or ref_tactic
                if unmapped is not None:
                    unmapped.setdefault("mitre_reference_labels", []).append(uid_val)
            tactic_name = tactic_name or "Unknown"

            attacks.append(
                OCSFAttack(
                    tactic=OCSFTactic(name=tactic_name) if tactic_name else None,
                    technique=OCSFTechnique(uid=uid_val, name=tech_name),
                )
            )

        return attacks

    def _extract_message(
        self,
        raw_alert: dict[str, Any],
        rule_dict: dict[str, Any],
    ) -> str | None:
        """Extract descriptive message string."""
        return self._safe_str(raw_alert.get("full_log")) or self._safe_str(rule_dict.get("description"))

    def _collect_unmapped_fields(
        self,
        raw_alert: dict[str, Any],
        unmapped: dict[str, Any],
    ) -> None:
        """Record vendor-specific Wazuh attributes in unmapped for investigation."""
        for key in ("decoder", "location", "cluster", "syscheck"):
            val = raw_alert.get(key)
            if val is not None:
                unmapped[key] = val

    @staticmethod
    def _safe_str(val: Any) -> str | None:
        """Sanitize and safely convert value to string or None."""
        if val is None:
            return None
        s = str(val).strip()
        return s if s else None

    @staticmethod
    def _safe_port(val: Any) -> int | None:
        """Validate and convert port value to 1-65535 int or None."""
        if val is None:
            return None
        try:
            port = int(val)
            if 1 <= port <= 65535:
                return port
        except (ValueError, TypeError):
            pass
        return None

    @staticmethod
    def _normalize_to_str_list(val: Any) -> list[str]:
        """Convert a scalar or list into a clean list of non-empty strings."""
        if val is None:
            return []
        if isinstance(val, list):
            return [str(item).strip() for item in val if item is not None and str(item).strip()]
        s = str(val).strip()
        return [s] if s else []
