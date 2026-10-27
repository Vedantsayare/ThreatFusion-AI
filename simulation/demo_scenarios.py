"""
simulation/demo_scenarios.py — Synthetic SOC demo telemetry (defensive, simulated).

Every alert here is fabricated Wazuh-style detection output for demonstration.
It describes what a detection rule *reported*; it contains no working attack
tooling. Network indicators use RFC 5737 documentation ranges and example.*
domains only. Every alert carries a stable ``id`` (``demo-...``) so loading a
scenario twice is idempotent (deduplicated by the API).

Timestamps are anchored to the load time (rounded down to the hour) so the
dashboard trend shows recent activity; ``offset_minutes`` keeps the order.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from simulation.scenarios import SCENARIO_PROMPT_INJECTION_TELEMETRY

WEB = {"id": "001", "name": "web-server-01", "ip": "192.168.1.50"}
DB = {"id": "002", "name": "db-server-01", "ip": "192.168.1.51"}
DEV = {"id": "004", "name": "dev-workstation-09", "ip": "10.0.5.12"}
LAPTOP = {"id": "017", "name": "hr-laptop-17", "ip": "10.0.8.17"}


@dataclass(frozen=True)
class DemoAlert:
    offset_minutes: int
    raw: dict[str, Any]


@dataclass(frozen=True)
class DemoScenario:
    scenario_id: str
    name: str
    description: str
    expected_outcome: str
    alerts: list[DemoAlert] = field(default_factory=list)

    def materialize(self, anchor: datetime | None = None) -> list[dict[str, Any]]:
        base = (anchor or datetime.now(UTC)).replace(minute=0, second=0, microsecond=0) - timedelta(hours=2)
        out: list[dict[str, Any]] = []
        for alert in self.alerts:
            raw = copy.deepcopy(alert.raw)
            raw["timestamp"] = (base + timedelta(minutes=alert.offset_minutes)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
            raw.setdefault("data", {})["synthetic"] = "true"
            out.append(raw)
        return out


def _rule(rule_id: str, level: int, description: str, mitre: list[str], groups: list[str]) -> dict[str, Any]:
    return {"id": rule_id, "level": level, "description": description, "mitre": {"id": mitre}, "groups": groups}


INTRUSION_CHAIN = DemoScenario(
    scenario_id="intrusion-chain",
    name="Multi-stage intrusion: web server to database exfiltration",
    description=(
        "SSH brute force against web-server-01, a successful login with the targeted "
        "account, encoded PowerShell, sudo privilege escalation, lateral movement to "
        "db-server-01, then a large outbound transfer."
    ),
    expected_outcome="One CRITICAL incident correlating 6 alerts across 2 hosts and 6 ATT&CK tactics.",
    alerts=[
        DemoAlert(0, {
            "id": "demo-ic-001",
            "rule": _rule("5712", 10, "SSH brute force: 48 failed logins for 'admin' from one source", ["T1110.001"], ["authentication_failures", "sshd"]),
            "agent": WEB,
            "data": {"srcip": "203.0.113.195", "dstip": WEB["ip"], "dstuser": "admin", "srcport": "51022", "dstport": "22", "protocol": "tcp"},
            "location": "/var/log/auth.log",
            "full_log": "sshd[2211]: Failed password for admin from 203.0.113.195 port 51022 ssh2 (48 occurrences)",
        }),
        DemoAlert(6, {
            "id": "demo-ic-002",
            "rule": _rule("5715", 8, "Successful SSH login for 'admin' after repeated failures", ["T1078.003"], ["authentication_success", "sshd"]),
            "agent": WEB,
            "data": {"srcip": "203.0.113.195", "dstip": WEB["ip"], "dstuser": "admin", "dstport": "22", "protocol": "tcp"},
            "location": "/var/log/auth.log",
            "full_log": "sshd[2290]: Accepted password for admin from 203.0.113.195 port 51544 ssh2",
        }),
        DemoAlert(14, {
            "id": "demo-ic-003",
            "rule": _rule("92057", 12, "Encoded PowerShell command line executed", ["T1059.001"], ["windows", "sysmon_process"]),
            "agent": WEB,
            "data": {"win": {"eventdata": {
                "targetUserName": "admin",
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "commandLine": "powershell.exe -NoProfile -EncodedCommand <redacted-synthetic-base64>",
                "processId": "4412",
            }}},
            "location": "EventChannel",
        }),
        DemoAlert(21, {
            "id": "demo-ic-004",
            "rule": _rule("5402", 12, "User 'admin' escalated to root via sudo outside change window", ["T1548.003"], ["sudo", "privilege_escalation"]),
            "agent": WEB,
            "data": {"srcuser": "admin", "dstuser": "root", "command": "/bin/bash"},
            "location": "/var/log/auth.log",
            "full_log": "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash",
        }),
        DemoAlert(33, {
            "id": "demo-ic-005",
            "rule": _rule("5715", 12, "SSH login to db-server-01 from web-server-01 using 'admin'", ["T1021.004"], ["authentication_success", "lateral_movement"]),
            "agent": DB,
            "data": {"srcip": WEB["ip"], "dstip": DB["ip"], "dstuser": "admin", "dstport": "22", "protocol": "tcp"},
            "location": "/var/log/auth.log",
        }),
        DemoAlert(47, {
            "id": "demo-ic-006",
            "rule": _rule("100510", 13, "Large outbound HTTPS transfer (2.1 GB) to file-sharing host", ["T1567.002"], ["network", "exfiltration"]),
            "agent": DB,
            "data": {"srcip": DB["ip"], "dstip": "203.0.113.50", "dst_domain": "files.example.net", "dstport": "443", "protocol": "tcp", "bytes_out": "2254857830"},
            "location": "netflow",
        }),
    ],
)

C2_BEACON = DemoScenario(
    scenario_id="c2-beacon",
    name="Workstation beaconing to known C2 indicator",
    description="Periodic outbound HTTPS from hr-laptop-17 to an indicator listed MALICIOUS in the synthetic intel feed.",
    expected_outcome="One HIGH/CRITICAL incident; threat-intel factor visible in the score breakdown.",
    alerts=[
        DemoAlert(30, {
            "id": "demo-c2-001",
            "rule": _rule("100305", 11, "Periodic outbound HTTPS beacon (60s interval) to rare destination", ["T1071.001"], ["network", "beaconing"]),
            "agent": LAPTOP,
            "data": {"srcip": LAPTOP["ip"], "dstip": "198.51.100.22", "dstport": "443", "protocol": "tcp", "dstuser": "j.doe"},
            "location": "proxy",
        }),
    ],
)

BENIGN_ACTIVITY = DemoScenario(
    scenario_id="benign-activity",
    name="Benign activity and a likely false positive",
    description=(
        "A routine package update to an allow-listed mirror (stays a LOW alert, no "
        "incident) and an off-hours analyst login that triage flags MEDIUM — a candidate "
        "for analyst closure as FALSE_POSITIVE."
    ),
    expected_outcome="Two alerts: one LOW with no incident, one MEDIUM incident suitable for closing as false positive.",
    alerts=[
        DemoAlert(10, {
            "id": "demo-bn-001",
            "rule": _rule("2902", 3, "Package manager update completed", [], ["package_management"]),
            "agent": DEV,
            "data": {"srcip": DEV["ip"], "dstip": "192.0.2.10", "dst_domain": "updates.example.com", "dstport": "443", "dstuser": "developer_bob"},
            "location": "/var/log/apt/history.log",
        }),
        DemoAlert(55, {
            "id": "demo-bn-002",
            "rule": _rule("100105", 6, "Interactive login outside business hours", ["T1078"], ["authentication_success"]),
            "agent": DEV,
            "data": {"srcip": "10.0.5.100", "dstip": DEV["ip"], "dstuser": "analyst_alice"},
            "location": "/var/log/auth.log",
        }),
    ],
)

_INJECTION = copy.deepcopy(SCENARIO_PROMPT_INJECTION_TELEMETRY)
_INJECTION["id"] = "demo-adv-001"
# Separate host so it does not (correctly) correlate into the intrusion chain.
_INJECTION["agent"] = {"id": "031", "name": "build-agent-03", "ip": "10.0.9.31"}
ADVERSARIAL_TELEMETRY = DemoScenario(
    scenario_id="adversarial-telemetry",
    name="Alert text containing prompt-injection strings",
    description=(
        "Alert fields contain text addressed to an AI system. The pipeline must treat it "
        "as data: triage is deterministic and the narrative must not follow it."
    ),
    expected_outcome=(
        "Scored by rules only (CRITICAL: High-severity rule + privileged account + execution technique); "
        "the injected text appears verbatim as evidence, never as an instruction."
    ),
    alerts=[DemoAlert(70, _INJECTION)],
)

SCENARIOS: dict[str, DemoScenario] = {
    s.scenario_id: s for s in (INTRUSION_CHAIN, C2_BEACON, BENIGN_ACTIVITY, ADVERSARIAL_TELEMETRY)
}
