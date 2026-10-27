"""
api/incidents.py — Incident model and deterministic alert-to-incident correlation.

Correlation keys (only strong, specific attributes — never generic ones):
- asset:agent:<id>       Wazuh agent ID (not the manager "000")        conf 0.9
- asset:host:<name>      Non-generic hostname when no agent ID          conf 0.7
- identity:<user>@<host> Account scoped to a host (generic names stay
                         scoped, so "root" on two hosts never merges)    conf 0.8
- ioc:ip:<ip>            Globally routable IP (private IPs are reused,
                         so they are never used as correlation keys)     conf 0.6

An alert joins the open incident that shares the highest-confidence key and
whose activity window (last_seen) is within CORRELATION_WINDOW of the alert's
event time. Every join records the matched key and confidence as the
correlation basis. Alerts triaged LOW that match nothing do not open an
incident — they remain reviewable alerts.

Incident risk = max(alert scores) + attack-progression bonus when the
correlated alerts span multiple distinct ATT&CK tactics. Alert-level factors
are not re-added at the incident level (no double counting).
"""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from graph.resolver import GENERIC_HOSTNAMES
from normalization.net import is_external_ip
from orchestrator.state import AlertWorkflowOutput

CORRELATION_WINDOW_SECONDS = 24 * 3600
PROGRESSION_BONUS = {2: 5, 3: 10}  # distinct tactics -> bonus (3 means "3 or more")
TERMINAL_STATUSES = frozenset({"RESOLVED", "FALSE_POSITIVE"})


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class CorrelationLink(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alert_id: str
    matched_key: str | None = None
    basis: str
    confidence: float = Field(ge=0.0, le=1.0)
    linked_at: float = Field(default_factory=time.time)


class AnalystNote(BaseModel):
    model_config = ConfigDict(extra="ignore")

    note_id: str = Field(default_factory=lambda: f"note-{uuid.uuid4().hex[:10]}")
    author: str
    text: str
    created_at: float = Field(default_factory=time.time)


class HistoryEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")

    at: float = Field(default_factory=time.time)
    actor: str
    action: str
    detail: str
    from_status: str | None = None
    to_status: str | None = None


class RiskComponent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    factor: str
    points: int
    detail: str


class Incident(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str
    status: IncidentStatus = IncidentStatus.OPEN
    priority: str = "LOW"
    risk_score: int = 0
    risk_breakdown: list[RiskComponent] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    correlation_keys: list[str] = Field(default_factory=list)
    correlation: list[CorrelationLink] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    notes: list[AnalystNote] = Field(default_factory=list)
    history: list[HistoryEntry] = Field(default_factory=list)
    narrative: dict[str, Any] | None = None
    synthetic: bool = False

    @property
    def is_open(self) -> bool:
        return self.status.value not in TERMINAL_STATUSES


def _is_public(ip: str) -> bool:
    return is_external_ip(ip)


def correlation_keys(output: AlertWorkflowOutput) -> list[tuple[str, float, str]]:
    """Strong correlation keys for an alert as (key, confidence, explanation)."""
    finding = output.finding
    if finding is None:
        return []
    keys: list[tuple[str, float, str]] = []
    host_label: str | None = None
    device = finding.device
    if device is not None:
        if device.uid and device.uid.strip() not in ("", "000"):
            keys.append((f"asset:agent:{device.uid.strip()}", 0.9, f"same Wazuh agent ID {device.uid}"))
            host_label = device.name or f"agent-{device.uid}"
        elif device.name and device.name.strip().lower() not in GENERIC_HOSTNAMES:
            keys.append((f"asset:host:{device.name.strip().lower()}", 0.7, f"same hostname {device.name}"))
            host_label = device.name
    if finding.user and finding.user.name and host_label:
        user = finding.user.name.strip().lower()
        keys.append((f"identity:{user}@{host_label.lower()}", 0.8, f"same account '{user}' on {host_label}"))
    # Internal host address: the reporting host's own IP, and private endpoint
    # IPs, share one key space so traffic *from* a compromised host links to
    # alerts *on* that host (lateral movement). Weak (0.5): private addresses
    # can be reassigned, so the 24h window bounds this link.
    internal: list[str] = []
    if device is not None and device.ip and not _is_public(device.ip.strip()):
        internal.append(device.ip.strip())
    for endpoint in (finding.src_endpoint, finding.dst_endpoint):
        if endpoint and endpoint.ip:
            ip = endpoint.ip.strip()
            if _is_public(ip):
                keys.append((f"ioc:ip:{ip}", 0.6, f"same external IP {ip}"))
            elif ip not in internal:
                internal.append(ip)
    for ip in internal:
        keys.append((f"asset:ip:{ip}", 0.5, f"same internal host address {ip}"))
    return keys


def event_time_seconds(output: AlertWorkflowOutput) -> float:
    if output.finding is not None:
        return output.finding.time / 1000.0
    return output.received_at


def find_matching_incident(
    output: AlertWorkflowOutput,
    incidents: list[Incident],
) -> tuple[Incident, CorrelationLink] | None:
    """Pick the best open incident sharing a strong key within the time window."""
    keys = correlation_keys(output)
    if not keys:
        return None
    t = event_time_seconds(output)
    best: tuple[float, float, Incident, CorrelationLink] | None = None
    for incident in incidents:
        if not incident.is_open:
            continue
        lo = (incident.first_seen or incident.created_at) - CORRELATION_WINDOW_SECONDS
        hi = (incident.last_seen or incident.created_at) + CORRELATION_WINDOW_SECONDS
        if not (lo <= t <= hi):
            continue
        for key, confidence, why in keys:
            if key in incident.correlation_keys:
                rank = (confidence, incident.last_seen or 0.0)
                if best is None or rank > (best[0], best[1]):
                    link = CorrelationLink(
                        alert_id=output.alert_id,
                        matched_key=key,
                        basis=f"Correlated by {why} within {CORRELATION_WINDOW_SECONDS // 3600}h window",
                        confidence=confidence,
                    )
                    best = (confidence, incident.last_seen or 0.0, incident, link)
    if best is None:
        return None
    return best[2], best[3]


def priority_for_score(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    return "LOW"


_PRIORITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def recompute(incident: Incident, alerts: list[AlertWorkflowOutput]) -> None:
    """Recompute aggregate fields and the deterministic incident risk score."""
    hosts: list[str] = []
    users: list[str] = []
    indicators: list[str] = []
    techniques: list[str] = []
    tactics: list[str] = []
    keys: list[str] = []
    times: list[float] = []
    top: AlertWorkflowOutput | None = None

    for out in alerts:
        f = out.finding
        if f is None:
            continue
        times.append(event_time_seconds(out))
        if f.device and f.device.name and f.device.name not in hosts:
            hosts.append(f.device.name)
        if f.user and f.user.name and f.user.name not in users:
            users.append(f.user.name)
        for ep in (f.src_endpoint, f.dst_endpoint):
            for value in ((ep.ip, ep.domain) if ep else ()):
                if value and value not in indicators:
                    indicators.append(value)
        for attack in f.attacks:
            if attack.technique and attack.technique.uid not in techniques:
                techniques.append(attack.technique.uid)
            name = attack.tactic.name if attack.tactic else None
            if name and name != "Unknown" and name not in tactics:
                tactics.append(name)
        for key, _, _ in correlation_keys(out):
            if key not in keys:
                keys.append(key)
        if out.triage_result and (top is None or (top.triage_result and out.triage_result.score > top.triage_result.score)):
            top = out

    breakdown: list[RiskComponent] = []
    base = top.triage_result.score if top and top.triage_result else 0
    breakdown.append(
        RiskComponent(
            factor="max_alert_score",
            points=base,
            detail=f"Highest deterministic alert score ({top.alert_id if top else 'n/a'})",
        )
    )
    bonus = 0
    if len(tactics) >= 3:
        bonus = PROGRESSION_BONUS[3]
    elif len(tactics) == 2:
        bonus = PROGRESSION_BONUS[2]
    if bonus:
        breakdown.append(
            RiskComponent(
                factor="attack_progression",
                points=bonus,
                detail=f"Correlated alerts span {len(tactics)} distinct ATT&CK tactics: {', '.join(tactics)}",
            )
        )
    score = max(0, min(100, base + bonus))
    if score != base + bonus:
        breakdown.append(
            RiskComponent(factor="clamp", points=score - (base + bonus), detail="Risk capped at 100")
        )

    # Priority never drops below the highest alert priority (hard rules included).
    priority = priority_for_score(score)
    for out in alerts:
        if out.triage_result:
            alert_priority = out.triage_result.priority.value
            if _PRIORITY_RANK.get(alert_priority, 0) > _PRIORITY_RANK[priority]:
                priority = alert_priority

    incident.hosts = hosts
    incident.users = users
    incident.indicators = indicators
    incident.mitre_techniques = techniques
    incident.tactics = tactics
    incident.correlation_keys = keys
    incident.first_seen = min(times) if times else None
    incident.last_seen = max(times) if times else None
    incident.risk_score = score
    incident.risk_breakdown = breakdown
    incident.priority = priority
    if top and top.finding:
        incident.title = top.finding.finding_info.title
    incident.updated_at = time.time()
