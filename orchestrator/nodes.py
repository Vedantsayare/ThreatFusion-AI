"""
orchestrator/nodes.py — Discrete, testable node handlers for the LangGraph alert workflow.

Each node handler is a focused, decoupled unit that takes the typed workflow state,
interacts with the relevant Phase 0-6 service, and returns updated state fields.
Telemetry is treated strictly as passive data, never as executable instructions.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from agents.investigation import InvestigationService
from agents.triage import AlertTriageEngine
from core.logger import get_logger
from graph.client import GraphConnectionError, Neo4jClient
from graph.resolver import EntityResolver
from guardrails import (
    ActionCategory,
    ActionProposal,
    GuardrailEngine,
    GuardrailResult,
)
from normalization.normalizer import AlertSchemaError, NormalizationError, OCSFNormalizer
from orchestrator.state import (
    AlertWorkflowOutput,
    AlertWorkflowState,
    StageRecord,
    StageStatus,
    WorkflowStatus,
)

logger = get_logger("orchestrator.nodes")


class AlertWorkflowNodes:
    """Encapsulates node execution logic and dependencies for the alert workflow."""

    def __init__(
        self,
        normalizer: OCSFNormalizer | None = None,
        resolver: EntityResolver | None = None,
        graph_client: Neo4jClient | None = None,
        investigation_service: InvestigationService | None = None,
        triage_engine: AlertTriageEngine | None = None,
        guardrail_engine: GuardrailEngine | None = None,
        enable_graph_persistence: bool = True,
        max_retries: int = 2,
        persistence_timeout_seconds: float = 5.0,
    ) -> None:
        self.normalizer = normalizer or OCSFNormalizer()
        self.resolver = resolver or EntityResolver()
        self.graph_client = graph_client
        self.investigation_service = (
            investigation_service or InvestigationService(graph_client=graph_client)
        )
        self.triage_engine = triage_engine or AlertTriageEngine()
        self.guardrail_engine = guardrail_engine or GuardrailEngine()
        self.enable_graph_persistence = enable_graph_persistence
        self.max_retries = max(0, max_retries)
        self.persistence_timeout_seconds = max(0.5, persistence_timeout_seconds)

    # ── Helper: Record Stage Metadata ────────────────────────────────────────

    def _record_stage(
        self,
        state: AlertWorkflowState,
        stage_name: str,
        status: StageStatus,
        started_at: float,
        error: str | None = None,
        message: str | None = None,
        retry_count: int = 0,
    ) -> tuple[dict[str, dict[str, Any]], list[str]]:
        """Construct updated stage records and completed stage list."""
        now = time.time()
        record = StageRecord(
            stage_name=stage_name,
            status=status,
            started_at=started_at,
            completed_at=now,
            duration_ms=(now - started_at) * 1000.0,
            error=error,
            message=message,
            retry_count=retry_count,
        )

        stage_records = dict(state.get("stage_records", {}))
        stage_records[stage_name] = record.model_dump()

        completed_stages = list(state.get("completed_stages", []))
        if stage_name not in completed_stages:
            completed_stages.append(stage_name)

        return stage_records, completed_stages

    # ── Node 1: Receive Alert ────────────────────────────────────────────────

    def receive_alert(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Receive ingested alert, extract provenance, and initialize execution state."""
        start_time = time.time()
        raw_alert = state.get("raw_alert")
        raw_dict = raw_alert if isinstance(raw_alert, dict) else {}

        # Derive or extract alert_id safely
        alert_id = state.get("alert_id")
        if not alert_id:
            alert_id = str(
                raw_dict.get("id")
                or raw_dict.get("_id")
                or raw_dict.get("alert_id")
                or f"alert-{uuid.uuid4().hex[:12]}"
            )

        source = state.get("source", "wazuh")
        provenance = dict(state.get("source_provenance", {}))
        provenance.setdefault("source", source)
        provenance.setdefault("received_at", start_time)
        provenance.setdefault("raw_alert_keys", list(raw_dict.keys()))

        stage_records, completed_stages = self._record_stage(
            state,
            stage_name="receive_alert",
            status=StageStatus.SUCCESS,
            started_at=start_time,
            message=f"Received alert '{alert_id}' from source '{source}'",
        )

        return {
            "alert_id": alert_id,
            "raw_alert": raw_alert,
            "source": source,
            "source_provenance": provenance,
            "received_at": state.get("received_at", start_time),
            "started_at": state.get("started_at", start_time),
            "workflow_status": WorkflowStatus.RUNNING.value,
            "current_stage": "receive_alert",
            "completed_stages": completed_stages,
            "stage_records": stage_records,
            "errors": list(state.get("errors", [])),
            "guardrail_results": list(state.get("guardrail_results", [])),
            "pending_approvals": list(state.get("pending_approvals", [])),
            "audit_event_ids": list(state.get("audit_event_ids", [])),
            "retry_counts": dict(state.get("retry_counts", {})),
            "max_retries": state.get("max_retries", self.max_retries),
            "retry_needed": False,
        }

    # ── Node 2: Validate Input ───────────────────────────────────────────────

    def validate_input(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Validate input alert structure before normalization; fails fast on invalid data."""
        start_time = time.time()
        raw_alert = state.get("raw_alert")
        validation_errors: list[str] = []
        errors = list(state.get("errors", []))

        # Check dictionary structure
        if not isinstance(raw_alert, dict):
            validation_errors.append(
                f"Alert payload must be a dictionary, got {type(raw_alert).__name__}"
            )
        elif not raw_alert:
            validation_errors.append("Alert payload dictionary is empty")
        elif all(v is None for v in raw_alert.values()):
            validation_errors.append("Alert payload contains only null values")

        if validation_errors:
            for err in validation_errors:
                errors.append(f"Validation error: {err}")
            logger.warning(
                "workflow_validation_failed",
                alert_id=state.get("alert_id"),
                errors=validation_errors,
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="validate_input",
                status=StageStatus.FAILED,
                started_at=start_time,
                error="; ".join(validation_errors),
            )
            return {
                "is_valid": False,
                "validation_errors": validation_errors,
                "errors": errors,
                "workflow_status": WorkflowStatus.FAILED.value,
                "current_stage": "validate_input",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        stage_records, completed_stages = self._record_stage(
            state,
            stage_name="validate_input",
            status=StageStatus.SUCCESS,
            started_at=start_time,
            message="Input alert structure validated successfully",
        )
        return {
            "is_valid": True,
            "validation_errors": [],
            "current_stage": "validate_input",
            "completed_stages": completed_stages,
            "stage_records": stage_records,
        }

    # ── Node 3: Normalize Alert ──────────────────────────────────────────────

    def normalize_alert(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Normalize raw alert into a typed OCSFSecurityFinding model."""
        start_time = time.time()
        raw_alert = state.get("raw_alert", {})
        errors = list(state.get("errors", []))

        try:
            finding = self.normalizer.normalize(raw_alert)
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="normalize_alert",
                status=StageStatus.SUCCESS,
                started_at=start_time,
                message=f"Normalized finding UID '{finding.finding_info.uid}' with severity '{finding.severity}'",
            )
            return {
                "finding": finding,
                "normalization_error": None,
                "current_stage": "normalize_alert",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }
        except (AlertSchemaError, NormalizationError, Exception) as err:
            err_msg = f"Normalization failed: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_normalization_failed",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="normalize_alert",
                status=StageStatus.FAILED,
                started_at=start_time,
                error=str(err),
            )
            return {
                "finding": None,
                "normalization_error": str(err),
                "errors": errors,
                "workflow_status": WorkflowStatus.FAILED.value,
                "current_stage": "normalize_alert",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

    # ── Node 4: Resolve Entities ─────────────────────────────────────────────

    def resolve_entities(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Resolve canonical entity identifiers and relationships from normalized finding."""
        start_time = time.time()
        finding = state.get("finding")
        errors = list(state.get("errors", []))

        if finding is None:
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="resolve_entities",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Skipped entity resolution: finding is missing",
            )
            return {
                "resolution": None,
                "current_stage": "resolve_entities",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        try:
            resolution = self.resolver.resolve_finding(finding)
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="resolve_entities",
                status=StageStatus.SUCCESS,
                started_at=start_time,
                message=(
                    f"Resolved {len(resolution.entities)} entities, "
                    f"{len(resolution.relationships)} edges, "
                    f"{len(resolution.conflicts)} conflicts"
                ),
            )
            return {
                "resolution": resolution,
                "resolution_error": None,
                "current_stage": "resolve_entities",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }
        except Exception as err:
            err_msg = f"Entity resolution failed: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_entity_resolution_failed",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="resolve_entities",
                status=StageStatus.PARTIAL,
                started_at=start_time,
                error=str(err),
            )
            return {
                "resolution": None,
                "resolution_error": str(err),
                "errors": errors,
                "current_stage": "resolve_entities",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

    # ── Node 5: Persist to Graph ─────────────────────────────────────────────

    async def persist_to_graph(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Persist resolved entities and edges into Neo4j knowledge graph with bounded retry."""
        start_time = time.time()
        resolution = state.get("resolution")
        errors = list(state.get("errors", []))
        retry_counts = dict(state.get("retry_counts", {}))
        current_retries = retry_counts.get("persist_to_graph", 0)

        # 1. Idempotency guard: prevent duplicate write if already persisted
        if state.get("graph_persisted", False):
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Graph persistence skipped: entities already persisted",
                retry_count=current_retries,
            )
            return {
                "retry_needed": False,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        # 2. Check if persistence is enabled and client configured
        if not self.enable_graph_persistence or self.graph_client is None:
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Graph persistence disabled or Neo4j client not configured",
                retry_count=current_retries,
            )
            return {
                "graph_persistence_enabled": False,
                "graph_persisted": False,
                "persisted_nodes_count": 0,
                "persisted_edges_count": 0,
                "retry_needed": False,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        # 3. Check if resolution exists
        if resolution is None:
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Graph persistence skipped: no resolution result available",
                retry_count=current_retries,
            )
            return {
                "graph_persisted": False,
                "retry_needed": False,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        # 4. Attempt bounded persistence
        try:
            persisted_info = await asyncio.wait_for(
                self.graph_client.persist_resolution_result(resolution),
                timeout=self.persistence_timeout_seconds,
            )
            nodes_count = persisted_info.get("nodes_persisted", 0)
            edges_count = persisted_info.get("relationships_persisted", 0)

            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.SUCCESS,
                started_at=start_time,
                message=f"Persisted {nodes_count} nodes and {edges_count} edges into Neo4j",
                retry_count=current_retries,
            )
            return {
                "graph_persistence_enabled": True,
                "graph_persisted": True,
                "persisted_nodes_count": nodes_count,
                "persisted_edges_count": edges_count,
                "persistence_error": None,
                "retry_needed": False,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        except (GraphConnectionError, TimeoutError) as err:
            max_r = state.get("max_retries", self.max_retries)
            if current_retries < max_r:
                next_retry = current_retries + 1
                retry_counts["persist_to_graph"] = next_retry
                logger.warning(
                    "workflow_graph_persistence_retry",
                    alert_id=state.get("alert_id"),
                    attempt=next_retry,
                    max_retries=max_r,
                    error=str(err),
                )
                return {
                    "retry_counts": retry_counts,
                    "retry_needed": True,
                    "current_stage": "persist_to_graph",
                }

            # Retries exhausted
            err_msg = f"Graph persistence failed after {current_retries} retries: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_graph_persistence_retries_exhausted",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.PARTIAL,
                started_at=start_time,
                error=err_msg,
                retry_count=current_retries,
            )
            return {
                "graph_persistence_enabled": True,
                "graph_persisted": False,
                "persisted_nodes_count": 0,
                "persisted_edges_count": 0,
                "persistence_error": err_msg,
                "retry_needed": False,
                "errors": errors,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        except Exception as err:
            err_msg = f"Graph persistence unrecoverable error: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_graph_persistence_unrecoverable",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="persist_to_graph",
                status=StageStatus.PARTIAL,
                started_at=start_time,
                error=err_msg,
                retry_count=current_retries,
            )
            return {
                "graph_persistence_enabled": True,
                "graph_persisted": False,
                "persisted_nodes_count": 0,
                "persisted_edges_count": 0,
                "persistence_error": err_msg,
                "retry_needed": False,
                "errors": errors,
                "current_stage": "persist_to_graph",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

    # ── Node 6: Gather Investigation Context ─────────────────────────────────

    async def gather_investigation_context(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Retrieve temporal context, neighborhood, and historical facts from Neo4j/telemetry."""
        start_time = time.time()
        finding = state.get("finding")
        resolution = state.get("resolution")
        errors = list(state.get("errors", []))

        if finding is None:
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="gather_investigation_context",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Skipped investigation: finding is missing",
            )
            return {
                "investigation_context": None,
                "current_stage": "gather_investigation_context",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        try:
            context = await self.investigation_service.build_context(
                finding,
                resolution=resolution,
            )
            status = StageStatus.SUCCESS if context.graph_available else StageStatus.PARTIAL
            msg = (
                f"Gathered {len(context.observed_facts)} facts, "
                f"{len(context.inferences)} inferences (graph_available={context.graph_available})"
            )

            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="gather_investigation_context",
                status=status,
                started_at=start_time,
                message=msg,
                error=context.lookup_error,
            )
            return {
                "investigation_context": context,
                "investigation_error": context.lookup_error,
                "current_stage": "gather_investigation_context",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }
        except Exception as err:
            err_msg = f"Investigation context gathering failed: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_investigation_failed",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="gather_investigation_context",
                status=StageStatus.PARTIAL,
                started_at=start_time,
                error=str(err),
            )
            return {
                "investigation_context": None,
                "investigation_error": str(err),
                "errors": errors,
                "current_stage": "gather_investigation_context",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

    # ── Node 7: Perform Triage ───────────────────────────────────────────────

    def perform_triage(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Perform deterministic triage evaluation and assign incident priority."""
        start_time = time.time()
        finding = state.get("finding")
        resolution = state.get("resolution")
        context = state.get("investigation_context")
        errors = list(state.get("errors", []))

        if finding is None:
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="perform_triage",
                status=StageStatus.SKIPPED,
                started_at=start_time,
                message="Skipped triage: finding is missing",
            )
            return {
                "triage_result": None,
                "current_stage": "perform_triage",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

        try:
            triage_result = self.triage_engine.triage(
                finding,
                resolution=resolution,
                context=context,
            )

            # Evaluate advisory containment steps through GuardrailEngine
            guardrail_results = list(state.get("guardrail_results", []))
            pending_approvals = list(state.get("pending_approvals", []))
            audit_event_ids = list(state.get("audit_event_ids", []))

            target_entities: list[str] = []
            if finding.device and finding.device.name:
                target_entities.append(f"asset:host:{finding.device.name}")
            elif finding.device and finding.device.uid:
                target_entities.append(f"asset:agent:{finding.device.uid}")
            if finding.src_endpoint and finding.src_endpoint.ip:
                target_entities.append(f"ioc:ip:{finding.src_endpoint.ip}")

            for step in triage_result.recommended_steps:
                step_lower = step.lower()
                action_name = None
                category = ActionCategory.READ_ONLY

                if "isolate" in step_lower:
                    action_name = "isolate_host"
                    category = ActionCategory.CONTAINMENT
                elif "block" in step_lower:
                    action_name = "block_ip"
                    category = ActionCategory.CONTAINMENT
                elif "disable" in step_lower or "revoke" in step_lower:
                    action_name = "revoke_access"
                    category = ActionCategory.REMEDIATION
                elif "containment" in step_lower:
                    action_name = "contain_incident"
                    category = ActionCategory.CONTAINMENT

                if action_name:
                    proposal = ActionProposal(
                        action_name=action_name,
                        category=category,
                        target_entities=target_entities,
                        parameters={
                            "finding_id": finding.finding_info.uid,
                            "severity": finding.severity,
                            "recommendation": step,
                            "username": finding.user.name if finding.user else None,
                        },
                        rationale=step,
                        evidence_refs=[f"finding:{finding.finding_info.uid}"],
                        proposed_by="triage_engine",
                    )
                    guardrail_res = self.guardrail_engine.evaluate(proposal)
                    guardrail_results.append(guardrail_res.model_dump())
                    if guardrail_res.required_approvals:
                        pending_approvals.extend(guardrail_res.required_approvals)
                    if guardrail_res.audit_event_id:
                        audit_event_ids.append(guardrail_res.audit_event_id)

            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="perform_triage",
                status=StageStatus.SUCCESS,
                started_at=start_time,
                message=(
                    f"Triaged priority '{triage_result.priority.value}' "
                    f"with score {triage_result.score}/100"
                ),
            )
            return {
                "triage_result": triage_result,
                "triage_error": None,
                "guardrail_results": guardrail_results,
                "pending_approvals": pending_approvals,
                "audit_event_ids": audit_event_ids,
                "current_stage": "perform_triage",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }
        except Exception as err:
            err_msg = f"Alert triage failed: {err}"
            errors.append(err_msg)
            logger.error(
                "workflow_triage_failed",
                alert_id=state.get("alert_id"),
                error=str(err),
            )
            stage_records, completed_stages = self._record_stage(
                state,
                stage_name="perform_triage",
                status=StageStatus.FAILED,
                started_at=start_time,
                error=str(err),
            )
            return {
                "triage_result": None,
                "triage_error": str(err),
                "errors": errors,
                "workflow_status": WorkflowStatus.FAILED.value,
                "current_stage": "perform_triage",
                "completed_stages": completed_stages,
                "stage_records": stage_records,
            }

    # ── Node 8: Synthesize Final Result ──────────────────────────────────────

    def synthesize_final_result(self, state: AlertWorkflowState) -> dict[str, Any]:
        """Aggregate execution records, determine overall status, and build immutable output."""
        start_time = time.time()
        started_at = state.get("started_at", start_time)
        completed_at = time.time()
        duration_ms = (completed_at - started_at) * 1000.0

        # Determine overall workflow status
        is_valid = state.get("is_valid", False)
        finding = state.get("finding")
        stage_records_dict = state.get("stage_records", {})

        has_failed_stage = any(
            rec.get("status") == StageStatus.FAILED.value
            for rec in stage_records_dict.values()
        )
        has_partial_stage = any(
            rec.get("status") == StageStatus.PARTIAL.value
            for rec in stage_records_dict.values()
        )

        if not is_valid or finding is None or has_failed_stage:
            overall_status = WorkflowStatus.FAILED
        elif has_partial_stage:
            overall_status = WorkflowStatus.PARTIAL
        else:
            overall_status = WorkflowStatus.COMPLETED

        stage_records, completed_stages = self._record_stage(
            state,
            stage_name="synthesize_final_result",
            status=StageStatus.SUCCESS,
            started_at=start_time,
            message=f"Workflow finalized with overall status '{overall_status.value}' in {duration_ms:.1f}ms",
        )

        # Parse stage records into typed model dicts
        parsed_stage_records: dict[str, StageRecord] = {}
        for name, rec in stage_records.items():
            parsed_stage_records[name] = StageRecord.model_validate(rec)

        # Collect uncertainties
        triage_res = state.get("triage_result")
        uncertainties = list(triage_res.uncertainties) if triage_res else []
        if state.get("investigation_error"):
            uncertainties.append(f"Investigation degraded: {state.get('investigation_error')}")
        if state.get("persistence_error"):
            uncertainties.append(f"Graph persistence incomplete: {state.get('persistence_error')}")

        # Log tamper-evident audit event for finalized alert processing
        audit_store = self.guardrail_engine.audit_store
        final_audit_event = audit_store.log_event(
            actor="orchestrator",
            operation="synthesize_final_result",
            decision=overall_status.value,
            policy_id=self.guardrail_engine.policy.policy_id,
            outcome=f"Alert '{state.get('alert_id')}' finalized with status '{overall_status.value}'",
            evidence_refs=[f"finding:{finding.finding_info.uid}"] if finding else [],
            metadata={
                "alert_id": state.get("alert_id"),
                "priority": triage_res.priority.value if triage_res else None,
                "score": triage_res.score if triage_res else None,
                "duration_ms": duration_ms,
            },
        )
        audit_event_ids = list(state.get("audit_event_ids", []))
        audit_event_ids.append(final_audit_event.event_id)

        # Parse guardrail results
        raw_guardrail_results = state.get("guardrail_results", [])
        parsed_guardrail_results = [
            GuardrailResult.model_validate(r) for r in raw_guardrail_results
        ]

        output = AlertWorkflowOutput(
            alert_id=state.get("alert_id", "unknown"),
            workflow_status=overall_status,
            is_valid=is_valid,
            source=state.get("source", "wazuh"),
            received_at=state.get("received_at", started_at),
            completed_at=completed_at,
            duration_ms=duration_ms,
            completed_stages=completed_stages,
            stage_records=parsed_stage_records,
            finding=finding,
            resolution=state.get("resolution"),
            graph_persisted=state.get("graph_persisted", False),
            persisted_nodes_count=state.get("persisted_nodes_count", 0),
            persisted_edges_count=state.get("persisted_edges_count", 0),
            investigation_context=state.get("investigation_context"),
            triage_result=triage_res,
            errors=state.get("errors", []),
            uncertainties=uncertainties,
            guardrail_results=parsed_guardrail_results,
            pending_approvals=state.get("pending_approvals", []),
            audit_event_ids=audit_event_ids,
            raw_alert_preserved=bool(state.get("raw_alert")),
            source_provenance=state.get("source_provenance", {}),
        )

        return {
            "workflow_status": overall_status.value,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
            "current_stage": "synthesize_final_result",
            "completed_stages": completed_stages,
            "stage_records": stage_records,
            "final_output": output.model_dump(),
        }
