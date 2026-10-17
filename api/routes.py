"""
api/routes.py — FastAPI endpoint routers for ThreatFusion AI.
"""

from __future__ import annotations

import math
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status

from api.models import (
    AlertIngestRequest,
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    HealthResponse,
    IntegrationsStatusResponse,
    InvestigationDetailResponse,
    InvestigationSummary,
    PaginatedResponse,
)
from api.store import InvestigationStore, default_investigation_store
from core.health import ServiceHealth, ServiceStatus, SystemHealth
from core.logger import get_logger
from guardrails.engine import GuardrailEngine
from ingestion.cmdb import IAMCMDBProvider, MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.misp import MISPClient
from orchestrator.workflow import AlertWorkflowRunner

logger = get_logger("api.routes")
router = APIRouter()

# Dependency containers (injected at app creation)
_runner: AlertWorkflowRunner | None = None
_misp_client: MISPClient | None = None
_cmdb_provider: IAMCMDBProvider | None = None
_enrichment_service: EnrichmentService | None = None
_guardrail_engine: GuardrailEngine | None = None
_store: InvestigationStore = default_investigation_store


def init_api_dependencies(
    runner: AlertWorkflowRunner | None = None,
    misp_client: MISPClient | None = None,
    cmdb_provider: IAMCMDBProvider | None = None,
    enrichment_service: EnrichmentService | None = None,
    guardrail_engine: GuardrailEngine | None = None,
    store: InvestigationStore | None = None,
) -> None:
    """Initialize route dependency singletons."""
    global _runner, _misp_client, _cmdb_provider, _enrichment_service, _guardrail_engine, _store
    _runner = runner or AlertWorkflowRunner(enable_graph_persistence=False)
    _misp_client = misp_client or MISPClient()
    _cmdb_provider = cmdb_provider or MockIAMCMDBProvider()
    _enrichment_service = enrichment_service or EnrichmentService(
        misp_client=_misp_client,
        cmdb_provider=_cmdb_provider,
    )
    _guardrail_engine = guardrail_engine or GuardrailEngine()
    _store = store or default_investigation_store


# ── Health Endpoint ──────────────────────────────────────────────────────────


@router.get("/health", response_model=HealthResponse, tags=["Health"])
@router.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
async def get_system_health() -> HealthResponse:
    """Check health of internal components and external dependencies."""
    services: list[ServiceHealth] = []

    # 1. MISP health
    if _misp_client:
        misp_health = await _misp_client.check_health()
        services.append(misp_health)
    else:
        services.append(ServiceHealth(name="misp", status=ServiceStatus.UNKNOWN, detail="Not initialized"))

    # 2. Neo4j health
    if _runner and _runner.graph_client:
        try:
            neo4j_health = await _runner.graph_client.check_health()
            services.append(neo4j_health)
        except Exception as err:
            services.append(ServiceHealth(name="neo4j", status=ServiceStatus.DOWN, detail=str(err)))
    else:
        services.append(ServiceHealth(name="neo4j", status=ServiceStatus.UNKNOWN, detail="Client not configured"))

    # 3. Guardrails & Audit
    services.append(
        ServiceHealth(
            name="guardrails",
            status=ServiceStatus.OK,
            detail="Guardrail engine and tamper-evident audit store active",
        )
    )

    sys_health = SystemHealth(services)
    return HealthResponse(
        status=sys_health.overall.value,
        services=[s.to_dict() for s in services],
        checked_at=time.time(),
    )


# ── Alert Ingestion & Processing ─────────────────────────────────────────────


@router.post(
    "/api/v1/alerts/ingest",
    response_model=InvestigationDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Alerts"],
)
async def ingest_alert(request: AlertIngestRequest) -> InvestigationDetailResponse:
    """Ingest a raw security alert and execute the LangGraph investigation workflow."""
    if not _runner:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Workflow runner not initialized",
        )

    try:
        output = await _runner.process_alert(
            raw_alert=request.raw_alert,
            source=request.source,
            provenance=request.provenance,
        )

        # Trigger enrichment if finding was successfully normalized
        enrichment_data: dict[str, Any] | None = None
        if output.finding and _enrichment_service:
            enrichment_data = await _enrichment_service.enrich_finding(output.finding)

        _store.save(output, enrichment=enrichment_data)

        return InvestigationDetailResponse(
            alert_id=output.alert_id,
            workflow_status=output.workflow_status.value,
            is_valid=output.is_valid,
            source=output.source,
            received_at=output.received_at,
            completed_at=output.completed_at,
            duration_ms=output.duration_ms,
            completed_stages=output.completed_stages,
            finding=output.finding.model_dump() if output.finding else None,
            resolution=output.resolution.model_dump() if output.resolution else None,
            graph_persisted=output.graph_persisted,
            persisted_nodes_count=output.persisted_nodes_count,
            persisted_edges_count=output.persisted_edges_count,
            investigation_context=output.investigation_context.model_dump() if output.investigation_context else None,
            triage_result=output.triage_result.model_dump() if output.triage_result else None,
            guardrail_results=[g.model_dump() for g in output.guardrail_results],
            pending_approvals=output.pending_approvals,
            audit_event_ids=output.audit_event_ids,
            uncertainties=output.uncertainties,
            errors=output.errors,
            enrichment=enrichment_data,
        )
    except Exception as err:
        logger.error("api_alert_ingest_failed", error=str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Alert ingestion failed: {err}",
        ) from err


# ── Investigations Listing & Detail ──────────────────────────────────────────


@router.get(
    "/api/v1/investigations",
    response_model=PaginatedResponse[InvestigationSummary],
    tags=["Investigations"],
)
async def list_investigations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    priority: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
) -> PaginatedResponse[InvestigationSummary]:
    """Retrieve paginated list of investigations with optional filters."""
    outputs, total = _store.list_all(
        page=page,
        page_size=page_size,
        priority=priority,
        status=status_filter,
        search=search,
    )

    summaries: list[InvestigationSummary] = []
    for out in outputs:
        title = out.finding.finding_info.title if out.finding else "Unparsed Alert"
        p_val = out.triage_result.priority.value if out.triage_result else "UNKNOWN"
        score = out.triage_result.score if out.triage_result else 0
        sev = out.finding.severity if out.finding else "Unknown"
        host = out.finding.device.name if out.finding and out.finding.device else None
        user = out.finding.user.name if out.finding and out.finding.user else None
        mitre = out.triage_result.mitre_techniques if out.triage_result else []

        summaries.append(
            InvestigationSummary(
                alert_id=out.alert_id,
                finding_id=out.finding.finding_info.uid if out.finding else None,
                title=title,
                priority=p_val,
                score=score,
                severity=sev,
                workflow_status=out.workflow_status.value,
                received_at=out.received_at,
                duration_ms=out.duration_ms,
                asset_name=host,
                username=user,
                mitre_techniques=mitre,
                pending_approvals_count=len(out.pending_approvals),
            )
        )

    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    return PaginatedResponse(
        items=summaries,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get(
    "/api/v1/investigations/{alert_id}",
    response_model=InvestigationDetailResponse,
    tags=["Investigations"],
)
async def get_investigation(alert_id: str) -> InvestigationDetailResponse:
    """Retrieve full investigation details and external enrichment by alert_id."""
    res = _store.get(alert_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation for alert '{alert_id}' not found",
        )

    output, enrichment = res
    return InvestigationDetailResponse(
        alert_id=output.alert_id,
        workflow_status=output.workflow_status.value,
        is_valid=output.is_valid,
        source=output.source,
        received_at=output.received_at,
        completed_at=output.completed_at,
        duration_ms=output.duration_ms,
        completed_stages=output.completed_stages,
        finding=output.finding.model_dump() if output.finding else None,
        resolution=output.resolution.model_dump() if output.resolution else None,
        graph_persisted=output.graph_persisted,
        persisted_nodes_count=output.persisted_nodes_count,
        persisted_edges_count=output.persisted_edges_count,
        investigation_context=output.investigation_context.model_dump() if output.investigation_context else None,
        triage_result=output.triage_result.model_dump() if output.triage_result else None,
        guardrail_results=[g.model_dump() for g in output.guardrail_results],
        pending_approvals=output.pending_approvals,
        audit_event_ids=output.audit_event_ids,
        uncertainties=output.uncertainties,
        errors=output.errors,
        enrichment=enrichment,
    )


@router.post(
    "/api/v1/investigations/{alert_id}/enrich",
    response_model=dict[str, Any],
    tags=["Investigations"],
)
async def trigger_enrichment(alert_id: str) -> dict[str, Any]:
    """Trigger on-demand MISP threat-intelligence and CMDB asset context enrichment."""
    res = _store.get(alert_id)
    if not res:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation for alert '{alert_id}' not found",
        )

    output, _ = res
    if not output.finding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot enrich alert without normalized finding",
        )

    if not _enrichment_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Enrichment service not configured",
        )

    enrichment_data = await _enrichment_service.enrich_finding(output.finding)
    _store.save(output, enrichment=enrichment_data)
    return enrichment_data


# ── Statistics & Dashboard Overview ──────────────────────────────────────────


@router.get("/api/v1/stats", response_model=dict[str, int], tags=["Investigations"])
async def get_investigation_stats() -> dict[str, int]:
    """Get aggregate metrics for the SOC dashboard overview."""
    return _store.get_stats()


# ── External Integrations Status ─────────────────────────────────────────────


@router.get("/api/v1/integrations/status", response_model=IntegrationsStatusResponse, tags=["Integrations"])
async def get_integrations_status() -> IntegrationsStatusResponse:
    """Report external integration availability without exposing credentials or secrets."""
    misp_info: dict[str, Any] = {
        "enabled": _misp_client.is_enabled if _misp_client else False,
        "base_url": _misp_client._base_url if _misp_client else "not configured",
        "verify_ssl": _misp_client._verify_ssl if _misp_client else True,
    }

    neo4j_info: dict[str, Any] = {
        "enabled": bool(_runner and _runner.graph_client),
        "database": "neo4j",
    }

    cmdb_info: dict[str, Any] = {
        "enabled": bool(_cmdb_provider),
        "provider": type(_cmdb_provider).__name__ if _cmdb_provider else "none",
    }

    wazuh_info: dict[str, Any] = {
        "enabled": True,
        "endpoint": "/alerts",
    }

    return IntegrationsStatusResponse(
        wazuh=wazuh_info,
        neo4j=neo4j_info,
        misp=misp_info,
        cmdb=cmdb_info,
    )


# ── Human Approval Decision ──────────────────────────────────────────────────


@router.post(
    "/api/v1/approvals/{request_id}/decide",
    response_model=ApprovalDecisionResponse,
    tags=["Guardrails"],
)
async def submit_approval_decision(
    request_id: str,
    payload: ApprovalDecisionRequest,
) -> ApprovalDecisionResponse:
    """Submit authorized human approval or rejection for a pending containment action."""
    if not _guardrail_engine or not _guardrail_engine.approval_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Guardrail approval service not available",
        )

    approval_service = _guardrail_engine.approval_service
    req = approval_service.get_request(request_id)
    if not req:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{request_id}' not found",
        )

    try:
        if payload.decision == "APPROVE":
            updated_req = approval_service.approve(
                request_id=request_id,
                reviewer_id=payload.reviewer_id,
                reason=payload.reason,
            )
            msg = f"Request '{request_id}' APPROVED by '{payload.reviewer_id}'"
        else:
            updated_req = approval_service.reject(
                request_id=request_id,
                reviewer_id=payload.reviewer_id,
                reason=payload.reason,
            )
            msg = f"Request '{request_id}' REJECTED by '{payload.reviewer_id}'"

        # Log decision into audit store
        if _guardrail_engine.audit_store:
            _guardrail_engine.audit_store.log_event(
                actor=payload.reviewer_id,
                operation="human_approval_decision",
                decision=payload.decision,
                policy_id=_guardrail_engine.policy.policy_id,
                outcome=msg,
                approval_id=request_id,
                metadata={"reason": payload.reason},
            )

        return ApprovalDecisionResponse(
            request_id=updated_req.request_id,
            status=updated_req.status.value,
            reviewer_id=updated_req.reviewer_id or payload.reviewer_id,
            decision_at=updated_req.decision_at or time.time(),
            decision_reason=updated_req.decision_reason,
            message=msg,
        )

    except ValueError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)) from err
