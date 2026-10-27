"""
api/service.py — SOC application service: the one ingest → investigate → approve path.

Used by the REST routes, the demo-scenario loader, and the Wazuh poller so every
alert, regardless of origin, goes through identical validation, deterministic
triage, correlation, guardrails, and auditing.
"""

from __future__ import annotations

import time
from typing import Any

from agents.narrative import NarrativeGenerator
from api.incidents import (
    AnalystNote,
    CorrelationLink,
    HistoryEntry,
    Incident,
    IncidentStatus,
    find_matching_incident,
    recompute,
)
from api.store import InvestigationStore, alert_fingerprint
from core.logger import get_logger
from graph.client import Neo4jClient
from guardrails.actions import RESPONSE_ACTIONS, SIMULATION_NOTICE
from guardrails.approval import ApprovalRequest, ApprovalService, ApprovalStatus
from guardrails.audit import HashChainAuditStore
from guardrails.engine import GuardrailEngine
from guardrails.models import ActionProposal, DecisionType, GuardrailResult
from ingestion.enrichment import EnrichmentService
from orchestrator.state import AlertWorkflowOutput
from orchestrator.workflow import AlertWorkflowRunner

logger = get_logger("api.service")


class ServiceError(Exception):
    """Domain error mapped to an HTTP status by the routes."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class SOCService:
    def __init__(
        self,
        runner: AlertWorkflowRunner,
        store: InvestigationStore,
        guardrail_engine: GuardrailEngine,
        enrichment: EnrichmentService | None,
        narrative: NarrativeGenerator,
        graph_client: Neo4jClient | None = None,
    ) -> None:
        self.runner = runner
        self.store = store
        self.engine = guardrail_engine
        self.enrichment = enrichment
        self.narrative = narrative
        self.graph_client = graph_client

    @property
    def audit(self) -> HashChainAuditStore:
        return self.engine.audit_store

    @property
    def approvals(self) -> ApprovalService:
        return self.engine.approval_service

    def _audit(self, actor: str, operation: str, decision: str, outcome: str, **kwargs: Any) -> str:
        event = self.audit.log_event(
            actor=actor,
            operation=operation,
            decision=decision,
            policy_id=self.engine.policy.policy_id,
            outcome=outcome,
            **kwargs,
        )
        return str(event.event_id)

    # ── Ingestion ────────────────────────────────────────────────────────────

    async def ingest(
        self,
        raw_alert: dict[str, Any],
        source: str,
        provenance: dict[str, Any],
        actor: str,
    ) -> tuple[AlertWorkflowOutput, bool, str | None]:
        """Run one alert through the pipeline. Returns (output, deduplicated, incident_id)."""
        fingerprint = alert_fingerprint(raw_alert, source)
        existing = self.store.find_by_fingerprint(fingerprint)
        if existing is not None:
            found = self.store.get(existing)
            if found is not None:
                self._audit(
                    actor, "alert_deduplicated", "SKIP",
                    f"Duplicate alert from '{source}' matched existing alert '{existing}'",
                    metadata={"alert_id": existing, "fingerprint": fingerprint[:16]},
                )
                await self.store.flush()
                return found[0], True, self.store.incident_for(existing)

        alert_id = f"alert-{fingerprint[:16]}"
        prov = {**provenance, "ingested_by": actor, "fingerprint": fingerprint}
        output = await self.runner.process_alert(raw_alert, source=source, provenance=prov, alert_id=alert_id)
        self.store.save(output, enrichment=output.enrichment, fingerprint=fingerprint)
        incident_id = self._correlate(output, actor, synthetic=bool(provenance.get("synthetic")))
        await self.store.flush()
        return output, False, incident_id

    def _correlate(self, output: AlertWorkflowOutput, actor: str, synthetic: bool) -> str | None:
        """Attach the alert to an incident (or open one) using deterministic rules."""
        if output.finding is None or output.triage_result is None:
            return None

        match = find_matching_incident(output, list(self.store.incidents.values()))
        if match is not None:
            incident, link = match
            incident.alert_ids.append(output.alert_id)
            incident.correlation.append(link)
            incident.history.append(
                HistoryEntry(actor="correlator", action="alert_linked", detail=f"{output.alert_id}: {link.basis}")
            )
            action = "incident_alert_linked"
        elif output.triage_result.priority.value == "LOW":
            # LOW alerts with no correlation stay as reviewable alerts.
            return None
        else:
            incident = Incident(title=output.finding.finding_info.title, synthetic=synthetic)
            incident.alert_ids.append(output.alert_id)
            incident.correlation.append(
                CorrelationLink(
                    alert_id=output.alert_id,
                    basis=f"Seed alert (triaged {output.triage_result.priority.value}); no open incident shared a strong entity",
                    confidence=1.0,
                )
            )
            incident.history.append(
                HistoryEntry(actor="correlator", action="incident_created", detail=f"Opened from {output.alert_id}", to_status="OPEN")
            )
            action = "incident_created"

        incident.synthetic = incident.synthetic or synthetic
        before = incident.priority
        recompute(incident, self.store.alerts_for_incident(incident.incident_id) or [output])
        if action == "incident_alert_linked" and before != incident.priority:
            incident.history.append(
                HistoryEntry(actor="correlator", action="priority_changed", detail=f"{before} → {incident.priority}")
            )
        self.store.save_incident(incident)
        self.store.link_alert(output.alert_id, incident.incident_id)

        # Bind workflow-created approval requests to their incident for navigation.
        for request_id in output.pending_approvals:
            req = self.approvals.get_request(request_id)
            if req is not None and "incident_id" not in req.context:
                req.context["incident_id"] = incident.incident_id
                self.store.queue_approval(req)

        self._audit(
            actor, action, "RECORD",
            f"Alert '{output.alert_id}' → incident '{incident.incident_id}' (risk {incident.risk_score}, {incident.priority})",
            evidence_refs=[f"alert:{output.alert_id}"],
            metadata={"incident_id": incident.incident_id, "alert_id": output.alert_id},
        )
        return incident.incident_id

    # ── Incidents ────────────────────────────────────────────────────────────

    def get_incident(self, incident_id: str) -> Incident:
        incident = self.store.incidents.get(incident_id)
        if incident is None:
            raise ServiceError(404, f"Incident '{incident_id}' not found")
        return incident

    async def set_status(self, incident_id: str, status: IncidentStatus, actor: str, reason: str) -> Incident:
        incident = self.get_incident(incident_id)
        if incident.status == status:
            raise ServiceError(409, f"Incident already {status.value}")
        before = incident.status.value
        incident.status = status
        incident.updated_at = time.time()
        incident.history.append(
            HistoryEntry(actor=actor, action="status_changed", detail=reason, from_status=before, to_status=status.value)
        )
        self.store.save_incident(incident)
        self._audit(
            actor, "incident_status_changed", "RECORD",
            f"Incident '{incident_id}' {before} → {status.value}: {reason}",
            metadata={"incident_id": incident_id},
        )
        await self.store.flush()
        return incident

    async def add_note(self, incident_id: str, actor: str, text: str) -> AnalystNote:
        incident = self.get_incident(incident_id)
        note = AnalystNote(author=actor, text=text)
        incident.notes.append(note)
        incident.updated_at = time.time()
        incident.history.append(HistoryEntry(actor=actor, action="note_added", detail=note.note_id))
        self.store.save_incident(incident)
        self._audit(actor, "incident_note_added", "RECORD", f"Note {note.note_id} on '{incident_id}'",
                    metadata={"incident_id": incident_id})
        await self.store.flush()
        return note

    def incident_approvals(self, incident_id: str) -> list[ApprovalRequest]:
        incident = self.get_incident(incident_id)
        alert_ids = set(incident.alert_ids)
        return [
            r for r in self.approvals.list_all()
            if r.context.get("incident_id") == incident_id or r.context.get("alert_id") in alert_ids
        ]

    # ── Response actions & approvals ─────────────────────────────────────────

    async def propose_action(
        self, incident_id: str, action_name: str, target: str, rationale: str, actor: str
    ) -> GuardrailResult:
        incident = self.get_incident(incident_id)
        spec = RESPONSE_ACTIONS.get(action_name)
        if spec is None:
            raise ServiceError(422, f"Unknown action '{action_name}'. Allowed: {sorted(RESPONSE_ACTIONS)}")

        allowed_targets = {
            "host": incident.hosts,
            "ip": incident.indicators,
            "user": incident.users,
            "incident": [incident.incident_id],
        }[spec.target_kind]
        if target not in allowed_targets:
            raise ServiceError(
                422,
                f"Target '{target}' is not a {spec.target_kind} observed in incident {incident_id}: {allowed_targets}",
            )

        proposal = ActionProposal(
            action_name=spec.action_name,
            category=spec.category,
            target_entities=[f"{spec.target_kind}:{target}"],
            parameters={
                "incident_id": incident_id,
                "target": target,
                "username": target if spec.target_kind == "user" else None,
                "simulated": True,
            },
            rationale=rationale,
            evidence_refs=[f"incident:{incident_id}"] + [f"alert:{a}" for a in incident.alert_ids[:10]],
            proposed_by=actor,
        )
        result = self.engine.evaluate(proposal, context={"incident_id": incident_id})
        incident.history.append(
            HistoryEntry(actor=actor, action="action_proposed", detail=f"{action_name} → {target}: {result.decision.value}")
        )
        self.store.save_incident(incident)
        await self.store.flush()
        return result

    def get_approval(self, request_id: str) -> ApprovalRequest:
        req = self.approvals.get_request(request_id)
        if req is None:
            raise ServiceError(404, f"Approval request '{request_id}' not found")
        return req

    async def decide(self, request_id: str, decision: str, reviewer: str, reason: str | None) -> ApprovalRequest:
        req = self.get_approval(request_id)
        # Separation of duties: the proposer cannot approve their own action.
        if decision == "APPROVE" and req.proposed_by == reviewer:
            self._audit(reviewer, "human_approval_decision", "DENY",
                        f"Self-approval refused for '{request_id}'", approval_id=request_id)
            await self.store.flush()
            raise ServiceError(403, "Separation of duties: you cannot approve an action you proposed")
        try:
            if decision == "APPROVE":
                updated = self.approvals.approve(request_id, reviewer_id=reviewer, reason=reason)
            else:
                updated = self.approvals.reject(request_id, reviewer_id=reviewer, reason=reason)
        except ValueError as err:
            self._audit(reviewer, "human_approval_decision", "DENY", f"{decision} refused: {err}", approval_id=request_id)
            await self.store.flush()
            raise ServiceError(409, str(err)) from err

        self._audit(
            reviewer, "human_approval_decision", decision,
            f"Request '{request_id}' {updated.status.value} by '{reviewer}'",
            approval_id=request_id,
            metadata={"reason": reason or "", "action": updated.action_name},
        )
        self._note_on_incident(updated, reviewer, f"{decision} {updated.action_name}: {reason or 'no reason given'}")
        await self.store.flush()
        return updated

    async def execute(self, request_id: str, actor: str) -> tuple[ApprovalRequest, GuardrailResult]:
        """Re-validate an APPROVED request through the guardrail, then simulate it once."""
        req = self.get_approval(request_id)
        if req.proposal is None:
            raise ServiceError(409, "Approval has no bound proposal and cannot be executed")
        if req.status != ApprovalStatus.APPROVED:
            self._audit(actor, "execute_action", "DENY",
                        f"Execution refused: status {req.status.value}", approval_id=request_id)
            await self.store.flush()
            raise ServiceError(409, f"Request '{request_id}' is {req.status.value}; only APPROVED requests execute (once)")

        result = self.engine.evaluate(req.proposal, approval=req, actor=actor)
        if result.decision != DecisionType.ALLOW:
            await self.store.flush()
            raise ServiceError(409, f"Guardrail refused execution: {result.reason}")

        outcome = f"{req.action_name} on {req.target_entities}: {SIMULATION_NOTICE}"
        try:
            updated = self.approvals.mark_executed(request_id, executed_by=actor, outcome=outcome)
        except ValueError as err:
            raise ServiceError(409, str(err)) from err
        self._audit(actor, "simulated_action_executed", "EXECUTED_SIMULATED", outcome, approval_id=request_id,
                    metadata={"action_hash": req.action_hash})
        self._note_on_incident(updated, actor, f"Executed {updated.action_name} — {SIMULATION_NOTICE}")
        await self.store.flush()
        return updated, result

    def _note_on_incident(self, req: ApprovalRequest, actor: str, detail: str) -> None:
        incident_id = req.context.get("incident_id")
        incident = self.store.incidents.get(str(incident_id)) if incident_id else None
        if incident is not None:
            incident.history.append(HistoryEntry(actor=actor, action="response_action", detail=detail))
            incident.updated_at = time.time()
            self.store.save_incident(incident)

    # ── Graph ────────────────────────────────────────────────────────────────

    def _finding_index(self) -> dict[str, str]:
        return {
            f"finding:{o.finding.finding_info.uid}": o.alert_id
            for o in self.store.all_outputs() if o.finding is not None
        }

    def _decorate(self, nodes: dict[str, dict[str, Any]]) -> None:
        index = self._finding_index()
        for node_id, node in nodes.items():
            alert_id = index.get(node_id)
            if alert_id:
                node["alert_id"] = alert_id
                node["incident_id"] = self.store.incident_for(alert_id)

    @staticmethod
    def _edge(rel: dict[str, Any]) -> dict[str, Any]:
        props = rel.get("properties") or {}
        return {
            "id": f"{rel['source']}|{rel['type']}|{rel['target']}",
            "source": rel["source"],
            "target": rel["target"],
            "type": rel["type"],
            "confidence": props.get("confidence"),
            "provenance": props.get("source"),
            "valid_from": props.get("valid_from"),
            "last_seen": props.get("last_seen"),
        }

    def _resolution_graph(self, outputs: list[AlertWorkflowOutput]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        for out in outputs:
            if out.resolution is None:
                continue
            for entity in out.resolution.entities.values():
                nodes.setdefault(entity.canonical_id, {
                    "id": entity.canonical_id,
                    "label": entity.entity_type.value,
                    "name": entity.name,
                    "confidence": entity.confidence,
                })
            for rel in out.resolution.relationships:
                edge_id = f"{rel.source_id}|{rel.rel_type.value}|{rel.target_id}"
                edge: dict[str, Any] = {
                    "id": edge_id,
                    "source": rel.source_id,
                    "target": rel.target_id,
                    "type": rel.rel_type.value,
                    "confidence": rel.confidence,
                    "provenance": rel.source,
                    "valid_from": rel.valid_from,
                    "last_seen": rel.valid_from,
                }
                edges[edge_id] = edge
        return nodes, edges

    async def _neo4j_neighborhood(self, center_ids: list[str], depth: int) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
        assert self.graph_client is not None
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        for center in center_ids:
            hood = await self.graph_client.get_entity_neighborhood(center, depth=depth)
            if hood.get("center") is None:
                continue
            c = hood["center"]
            props = c.get("properties") or {}
            nodes[c["id"]] = {"id": c["id"], "label": (c.get("labels") or ["?"])[0], "name": props.get("name", c["id"]),
                              "confidence": props.get("confidence")}
            for n in hood.get("neighbors", []):
                if n.get("id"):
                    nprops = n.get("properties") or {}
                    nodes[n["id"]] = {"id": n["id"], "label": (n.get("labels") or ["?"])[0],
                                      "name": n.get("name") or n["id"], "confidence": nprops.get("confidence")}
            for rel in hood.get("relationships", []):
                edge = self._edge(rel)
                edges[edge["id"]] = edge
        return nodes, edges

    async def incident_graph(self, incident_id: str) -> dict[str, Any]:
        self.get_incident(incident_id)
        outputs = self.store.alerts_for_incident(incident_id)
        centers = [f"finding:{o.finding.finding_info.uid}" for o in outputs if o.finding]
        return await self._graph(centers, outputs, depth=1)

    async def entity_graph(self, entity_id: str, depth: int) -> dict[str, Any]:
        outputs = [
            o for o in self.store.all_outputs()
            if o.resolution and entity_id in o.resolution.entities
        ]
        result = await self._graph([entity_id], outputs, depth=depth)
        if not result["nodes"]:
            raise ServiceError(404, f"Entity '{entity_id}' not found")
        return result

    async def _graph(self, centers: list[str], outputs: list[AlertWorkflowOutput], depth: int) -> dict[str, Any]:
        source = "workflow_resolution"
        note = "Neo4j unavailable: graph built from per-alert entity resolution (not persisted)."
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        if self.graph_client is not None:
            try:
                nodes, edges = await self._neo4j_neighborhood(centers, depth)
                source = "neo4j"
                note = "Temporal knowledge graph (Neo4j). Edges carry valid_from, confidence, and source."
            except Exception as err:
                logger.warning("graph_query_failed", error=str(err))
                note = f"Neo4j query failed ({type(err).__name__}); showing per-alert resolution instead."
        if source != "neo4j":
            nodes, edges = self._resolution_graph(outputs)
            if depth == 1 and len(centers) == 1 and centers[0] in nodes:
                keep = {centers[0]} | {e["source"] for e in edges.values() if e["target"] == centers[0]} | {
                    e["target"] for e in edges.values() if e["source"] == centers[0]}
                nodes = {k: v for k, v in nodes.items() if k in keep}
                edges = {k: e for k, e in edges.items() if e["source"] in keep and e["target"] in keep}
        self._decorate(nodes)
        return {
            "source": source,
            "persisted": source == "neo4j",
            "note": note,
            "centers": centers,
            "nodes": list(nodes.values()),
            "edges": [e for e in edges.values() if e["source"] in nodes and e["target"] in nodes],
        }

    # ── Narrative & report ───────────────────────────────────────────────────

    async def generate_narrative(self, incident_id: str, use_llm: bool, actor: str) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        alerts = [o.model_dump(mode="json") for o in self.store.alerts_for_incident(incident_id)]
        narrative = await self.narrative.generate(incident.model_dump(mode="json"), alerts, use_llm=use_llm)
        incident.narrative = narrative
        self.store.save_incident(incident)
        self._audit(actor, "narrative_generated", "RECORD", f"{narrative['mode']} narrative for '{incident_id}'",
                    metadata={"incident_id": incident_id, "warnings": len(narrative.get("warnings", []))})
        await self.store.flush()
        return narrative

    def report(self, incident_id: str) -> dict[str, Any]:
        incident = self.get_incident(incident_id)
        alerts = self.store.alerts_for_incident(incident_id)
        approvals = self.incident_approvals(incident_id)
        related_ids = {f"incident:{incident_id}"} | {f"alert:{a}" for a in incident.alert_ids}
        audit = [
            e.model_dump(mode="json") for e in self.audit.get_events()
            if e.metadata.get("incident_id") == incident_id
            or e.metadata.get("alert_id") in incident.alert_ids
            or e.approval_id in {r.request_id for r in approvals}
            or related_ids.intersection(e.evidence_refs)
        ]
        ok, err = self.audit.verify_chain_integrity()
        return {
            "report_type": "threatfusion.incident.v1",
            "generated_at": time.time(),
            "synthetic_data": incident.synthetic,
            "incident": incident.model_dump(mode="json"),
            "alerts": [
                {
                    "alert_id": o.alert_id,
                    "source": o.source,
                    "finding": o.finding.model_dump(mode="json") if o.finding else None,
                    "triage": o.triage_result.model_dump(mode="json") if o.triage_result else None,
                    "enrichment": o.enrichment,
                    "uncertainties": o.uncertainties,
                }
                for o in alerts
            ],
            "approvals": [r.model_dump(mode="json") for r in approvals],
            "audit_events": audit,
            "audit_chain": {"verified": ok, "error": err, "events_total": self.audit.event_count},
            "disclaimer": "Scores and priorities are deterministic rule outputs. Narrative text is advisory. "
            "All response actions in this release are simulated.",
        }
