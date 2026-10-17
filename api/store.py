"""
api/store.py — In-memory investigation repository and store for FastAPI backend.
"""

from __future__ import annotations

from typing import Any

from orchestrator.state import AlertWorkflowOutput


class InvestigationStore:
    """In-memory storage for workflow outputs and enrichment results."""

    def __init__(self, max_capacity: int = 1000) -> None:
        self.max_capacity = max_capacity
        self._outputs: dict[str, AlertWorkflowOutput] = {}
        self._enrichments: dict[str, dict[str, Any]] = {}
        self._insertion_order: list[str] = []

    def save(
        self,
        output: AlertWorkflowOutput,
        enrichment: dict[str, Any] | None = None,
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

    def get(self, alert_id: str) -> tuple[AlertWorkflowOutput, dict[str, Any] | None] | None:
        """Retrieve investigation and enrichment by alert_id."""
        out = self._outputs.get(alert_id)
        if not out:
            return None
        return out, self._enrichments.get(alert_id)

    def list_all(
        self,
        page: int = 1,
        page_size: int = 20,
        priority: str | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> tuple[list[AlertWorkflowOutput], int]:
        """List investigations with bounded pagination and filtering."""
        filtered: list[AlertWorkflowOutput] = []

        # Iterate in reverse chronological order (newest first)
        for alert_id in reversed(self._insertion_order):
            out = self._outputs[alert_id]

            if priority:
                triage = out.triage_result
                if not triage or triage.priority.value.upper() != priority.upper():
                    continue

            if status and out.workflow_status.value.upper() != status.upper():
                continue

            if search:
                term = search.lower()
                title = (out.finding.finding_info.title.lower() if out.finding else "")
                host = (
                    out.finding.device.name.lower()
                    if out.finding and out.finding.device and out.finding.device.name
                    else ""
                )
                ip = (
                    out.finding.src_endpoint.ip.lower()
                    if out.finding and out.finding.src_endpoint and out.finding.src_endpoint.ip
                    else ""
                )
                if term not in title and term not in host and term not in ip and term not in alert_id.lower():
                    continue

            filtered.append(out)

        total = len(filtered)
        start_idx = (max(1, page) - 1) * max(1, page_size)
        end_idx = start_idx + max(1, page_size)
        return filtered[start_idx:end_idx], total

    def get_stats(self) -> dict[str, int]:
        """Return counts by priority, approval status, and overall workflow status."""
        stats = {
            "total": len(self._outputs),
            "total_investigations": len(self._outputs),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "priority_p1": 0,
            "priority_p2": 0,
            "priority_p3": 0,
            "priority_p4": 0,
            "critical_threats": 0,
            "pending_approvals": 0,
            "completed": 0,
            "partial": 0,
            "failed": 0,
        }
        for out in self._outputs.values():
            if out.triage_result:
                p = out.triage_result.priority.value.upper()
                if p == "P1":
                    stats["critical"] += 1
                    stats["priority_p1"] += 1
                    stats["critical_threats"] += 1
                elif p == "P2":
                    stats["high"] += 1
                    stats["priority_p2"] += 1
                elif p == "P3":
                    stats["medium"] += 1
                    stats["priority_p3"] += 1
                elif p == "P4":
                    stats["low"] += 1
                    stats["priority_p4"] += 1

            stats["pending_approvals"] += len(out.pending_approvals)
            s = out.workflow_status.value.lower()
            if s in stats:
                stats[s] += 1
        return stats


# Global in-memory singleton
default_investigation_store = InvestigationStore()
