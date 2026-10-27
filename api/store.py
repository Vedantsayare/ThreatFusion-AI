"""
api/store.py — Investigation working set with durable write-through.

Holds alert workflow outputs, incidents, the deduplication index, and queues
writes to the configured repository (api.persistence). Mutating API handlers
call ``await store.flush()`` before responding so the client is only told
something was saved after the database accepted it.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import Counter
from collections.abc import Awaitable, Callable
from typing import Any

from api.incidents import Incident, IncidentStatus, event_time_seconds
from api.persistence import NullRepository, Repository
from core.logger import get_logger
from guardrails.approval import ApprovalRequest
from guardrails.audit import AuditEvent
from orchestrator.state import AlertWorkflowOutput

logger = get_logger("api.store")

PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def alert_fingerprint(raw_alert: dict[str, Any], source: str) -> str:
    """Stable deduplication key: source + upstream ID, else a content hash."""
    upstream = raw_alert.get("id") or raw_alert.get("_id") or raw_alert.get("alert_id")
    if upstream is not None and str(upstream).strip():
        basis = f"{source}|id|{str(upstream).strip()}"
    else:
        basis = f"{source}|content|{json.dumps(raw_alert, sort_keys=True, default=str)}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


class InvestigationStore:
    """Working set of investigations (alerts) and incidents."""

    def __init__(self, max_capacity: int = 1000, repository: Repository | None = None) -> None:
        self.max_capacity = max_capacity
        self.repository: Repository = repository or NullRepository()
        self._outputs: dict[str, AlertWorkflowOutput] = {}
        self._enrichments: dict[str, dict[str, Any]] = {}
        self._insertion_order: list[str] = []
        self._fingerprints: dict[str, str] = {}
        self._alert_fingerprint: dict[str, str] = {}
        self._alert_incident: dict[str, str] = {}
        self.incidents: dict[str, Incident] = {}
        self._pending: list[Callable[[], Awaitable[None]]] = []

    # ── Persistence plumbing ────────────────────────────────────────────────

    def _queue(self, op: Callable[[], Awaitable[None]]) -> None:
        self._pending.append(op)

    async def flush(self) -> None:
        """Write queued mutations in order. Raises if the database rejects them.

        A write is dequeued only after it succeeds. On failure it stays at the
        head of the queue and is retried (in order) by the next flush, so a
        transient database error can never leave a gap in the persisted audit
        chain or apply later writes before an earlier one.
        """
        while self._pending:
            await self._pending[0]()
            self._pending.pop(0)

    @property
    def pending_writes(self) -> int:
        """Mutations accepted in memory but not yet confirmed by the database."""
        return len(self._pending)

    def queue_approval(self, req: ApprovalRequest) -> None:
        payload = req.model_dump(mode="json")
        self._queue(lambda: self.repository.upsert_approval(req.request_id, payload))

    def queue_audit(self, event: AuditEvent) -> None:
        payload = event.model_dump(mode="json")
        self._queue(lambda: self.repository.append_audit(payload))

    def _queue_alert(self, alert_id: str) -> None:
        out = self._outputs.get(alert_id)
        if out is None:
            return
        payload = {
            "output": out.model_dump(mode="json"),
            "enrichment": self._enrichments.get(alert_id),
        }
        fingerprint = self._alert_fingerprint.get(alert_id, alert_id)
        incident_id = self._alert_incident.get(alert_id)
        self._queue(lambda: self.repository.upsert_alert(alert_id, fingerprint, incident_id, payload))

    def save_incident(self, incident: Incident) -> None:
        self.incidents[incident.incident_id] = incident
        payload = incident.model_dump(mode="json")
        self._queue(lambda: self.repository.upsert_incident(incident.incident_id, payload))

    def restore(self, data: dict[str, list[dict[str, Any]]]) -> None:
        """Rebuild the working set from persisted rows (startup only)."""
        for row in data.get("alerts", []):
            try:
                output = AlertWorkflowOutput.model_validate(row["output"])
            except Exception as err:  # keep startup alive; report the bad row
                logger.error("store_restore_alert_failed", error=str(err))
                continue
            alert_id = output.alert_id
            self._outputs[alert_id] = output
            if row.get("enrichment"):
                self._enrichments[alert_id] = row["enrichment"]
            self._insertion_order.append(alert_id)
            fingerprint = row.get("fingerprint") or alert_id
            self._fingerprints[fingerprint] = alert_id
            self._alert_fingerprint[alert_id] = fingerprint
            if row.get("incident_id"):
                self._alert_incident[alert_id] = row["incident_id"]
        for row in data.get("incidents", []):
            incident = Incident.model_validate(row)
            self.incidents[incident.incident_id] = incident
        logger.info("store_restored", alerts=len(self._outputs), incidents=len(self.incidents))

    # ── Alerts ──────────────────────────────────────────────────────────────

    def find_by_fingerprint(self, fingerprint: str) -> str | None:
        return self._fingerprints.get(fingerprint)

    def save(
        self,
        output: AlertWorkflowOutput,
        enrichment: dict[str, Any] | None = None,
        fingerprint: str | None = None,
    ) -> None:
        """Store or update an investigation output."""
        alert_id = output.alert_id
        if alert_id not in self._outputs:
            if len(self._insertion_order) >= self.max_capacity:
                oldest = self._insertion_order.pop(0)
                self._outputs.pop(oldest, None)
                self._enrichments.pop(oldest, None)
            self._insertion_order.append(alert_id)

        self._outputs[alert_id] = output
        if enrichment:
            self._enrichments[alert_id] = enrichment
        if fingerprint:
            self._fingerprints[fingerprint] = alert_id
            self._alert_fingerprint[alert_id] = fingerprint
        self._queue_alert(alert_id)

    def link_alert(self, alert_id: str, incident_id: str | None) -> None:
        if incident_id:
            self._alert_incident[alert_id] = incident_id
        else:
            self._alert_incident.pop(alert_id, None)
        self._queue_alert(alert_id)

    def incident_for(self, alert_id: str) -> str | None:
        return self._alert_incident.get(alert_id)

    def get(self, alert_id: str) -> tuple[AlertWorkflowOutput, dict[str, Any] | None] | None:
        """Retrieve investigation and enrichment by alert_id."""
        out = self._outputs.get(alert_id)
        if not out:
            return None
        return out, self._enrichments.get(alert_id) or out.enrichment

    def all_outputs(self) -> list[AlertWorkflowOutput]:
        """All alerts, newest first."""
        return [self._outputs[a] for a in reversed(self._insertion_order) if a in self._outputs]

    def alerts_for_incident(self, incident_id: str) -> list[AlertWorkflowOutput]:
        incident = self.incidents.get(incident_id)
        if incident is None:
            return []
        return [self._outputs[a] for a in incident.alert_ids if a in self._outputs]

    def list_all(
        self,
        page: int = 1,
        page_size: int = 20,
        priority: str | None = None,
        status: str | None = None,
        search: str | None = None,
        incident_id: str | None = None,
        host: str | None = None,
    ) -> tuple[list[AlertWorkflowOutput], int]:
        """List investigations with bounded pagination and filtering."""
        filtered: list[AlertWorkflowOutput] = []

        for out in self.all_outputs():
            if priority:
                triage = out.triage_result
                if not triage or triage.priority.value.upper() != priority.upper():
                    continue

            if status and out.workflow_status.value.upper() != status.upper():
                continue

            if incident_id and self._alert_incident.get(out.alert_id) != incident_id:
                continue

            f = out.finding
            if host and not (f and f.device and f.device.name and f.device.name.lower() == host.lower()):
                continue

            if search:
                term = search.lower()
                haystack = [out.alert_id.lower()]
                if f:
                    haystack.append(f.finding_info.title.lower())
                    if f.device and f.device.name:
                        haystack.append(f.device.name.lower())
                    if f.user and f.user.name:
                        haystack.append(f.user.name.lower())
                    for ep in (f.src_endpoint, f.dst_endpoint):
                        if ep and ep.ip:
                            haystack.append(ep.ip.lower())
                        if ep and ep.domain:
                            haystack.append(ep.domain.lower())
                    haystack.extend(a.technique.uid.lower() for a in f.attacks if a.technique)
                if not any(term in h for h in haystack):
                    continue

            filtered.append(out)

        total = len(filtered)
        start_idx = (max(1, page) - 1) * max(1, page_size)
        end_idx = start_idx + max(1, page_size)
        return filtered[start_idx:end_idx], total

    # ── Statistics ──────────────────────────────────────────────────────────

    def get_stats(self) -> dict[str, int]:
        """Counts by triage priority, workflow status, and incident status.

        Triage emits CRITICAL/HIGH/MEDIUM/LOW. The legacy priority_p1..p4 keys
        are kept as aliases (P1=CRITICAL ... P4=LOW) for older clients.
        """
        stats: dict[str, int] = {
            "total": len(self._outputs),
            "total_alerts": len(self._outputs),
            "total_investigations": len(self._outputs),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "unscored": 0,
            "priority_p1": 0,
            "priority_p2": 0,
            "priority_p3": 0,
            "priority_p4": 0,
            "critical_threats": 0,
            "pending_approvals": 0,
            "completed": 0,
            "partial": 0,
            "failed": 0,
            "total_incidents": len(self.incidents),
        }
        alias = {"CRITICAL": "priority_p1", "HIGH": "priority_p2", "MEDIUM": "priority_p3", "LOW": "priority_p4"}
        for out in self._outputs.values():
            if out.triage_result:
                p = out.triage_result.priority.value.upper()
                stats[p.lower()] += 1
                stats[alias[p]] += 1
                if p == "CRITICAL":
                    stats["critical_threats"] += 1
            else:
                stats["unscored"] += 1

            s = out.workflow_status.value.lower()
            if s in stats:
                stats[s] += 1

        for status in IncidentStatus:
            stats[f"incidents_{status.value.lower()}"] = sum(
                1 for i in self.incidents.values() if i.status == status
            )
        return stats

    def dashboard(self, bucket_hours: int = 1, top_n: int = 5) -> dict[str, Any]:
        """Aggregates for the SOC overview, derived only from stored records."""
        outputs = self.all_outputs()
        hosts: Counter[str] = Counter()
        users: Counter[str] = Counter()
        tactics: Counter[str] = Counter()
        trend: dict[int, dict[str, int]] = {}
        bucket = bucket_hours * 3600

        for out in outputs:
            f = out.finding
            if f is None:
                continue
            if f.device and f.device.name:
                hosts[f.device.name] += 1
            if f.user and f.user.name:
                users[f.user.name] += 1
            for attack in f.attacks:
                if attack.tactic and attack.tactic.name and attack.tactic.name != "Unknown":
                    tactics[attack.tactic.name] += 1
            ts = int(event_time_seconds(out) // bucket * bucket)
            slot = trend.setdefault(ts, dict.fromkeys(PRIORITIES, 0))
            if out.triage_result:
                slot[out.triage_result.priority.value] += 1

        open_incidents = sorted(
            (i for i in self.incidents.values() if i.is_open),
            key=lambda i: (-i.risk_score, -(i.last_seen or 0)),
        )
        return {
            "stats": self.get_stats(),
            "top_hosts": [{"name": n, "count": c} for n, c in hosts.most_common(top_n)],
            "top_users": [{"name": n, "count": c} for n, c in users.most_common(top_n)],
            "top_tactics": [{"name": n, "count": c} for n, c in tactics.most_common(top_n)],
            "alert_trend": [
                {"bucket_start": ts, **counts} for ts, counts in sorted(trend.items())
            ],
            "trend_bucket_hours": bucket_hours,
            "priority_incidents": [i.incident_id for i in open_incidents[:top_n]],
            "generated_at": time.time(),
        }


def default_store_factory() -> InvestigationStore:
    """Fresh in-memory store (the app replaces it with a persistent one at startup)."""
    return InvestigationStore()


# Backward-compatible module-level instance.
default_investigation_store = default_store_factory()
