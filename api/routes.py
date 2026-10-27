"""
api/routes.py — FastAPI endpoint routers for ThreatFusion AI.

Authorization: every endpoint except liveness/readiness/health requires an API
key. GET endpoints need role ``viewer``; ingest, notes, status changes and
action proposals need ``analyst``; approval decisions and execution need
``approver``. The authenticated principal — never a request field — is the
actor recorded in the audit log.
"""

from __future__ import annotations

import math
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from agents.narrative import NarrativeGenerator
from api.auth import Principal, get_registry, require_analyst, require_approver, require_viewer
from api.incidents import Incident, IncidentStatus
from api.models import (
    ActionProposalRequest,
    AlertBatchIngestRequest,
    AlertIngestRequest,
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    HealthResponse,
    IncidentStatusRequest,
    IncidentSummary,
    IntegrationsStatusResponse,
    InvestigationDetailResponse,
    InvestigationSummary,
    NarrativeRequest,
    NoteRequest,
    PaginatedResponse,
)
from api.service import ServiceError, SOCService
from api.store import InvestigationStore, default_store_factory
from core.health import ServiceHealth, ServiceStatus, SystemHealth
from core.logger import get_logger
from guardrails.actions import RESPONSE_ACTIONS, SIMULATION_NOTICE
from guardrails.approval import ApprovalRequest, ApprovalStatus
from guardrails.engine import GuardrailEngine
from ingestion.cmdb import IAMCMDBProvider, MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.intel import DemoIntelFeed
from ingestion.misp import MISPClient
from orchestrator.state import AlertWorkflowOutput
from orchestrator.workflow import AlertWorkflowRunner
from simulation.demo_scenarios import SCENARIOS

logger = get_logger("api.routes")
router = APIRouter()

# Dependency containers (injected at app creation)
_runner: AlertWorkflowRunner | None = None
_misp_client: MISPClient | None = None
_cmdb_provider: IAMCMDBProvider | None = None
_enrichment_service: EnrichmentService | None = None
_guardrail_engine: GuardrailEngine | None = None
_store: InvestigationStore = default_store_factory()
_service: SOCService | None = None
_runtime: dict[str, Any] = {}


def init_api_dependencies(
    runner: AlertWorkflowRunner | None = None,
    misp_client: MISPClient | None = None,
    cmdb_provider: IAMCMDBProvider | None = None,
    enrichment_service: EnrichmentService | None = None,
    guardrail_engine: GuardrailEngine | None = None,
    store: InvestigationStore | None = None,
    narrative: NarrativeGenerator | None = None,
    runtime: dict[str, Any] | None = None,
) -> SOCService:
    """Initialize route dependency singletons.

    The approval endpoints and the workflow MUST share one GuardrailEngine so
    that approval requests created during triage can be decided via the API.
    """
    global _runner, _misp_client, _cmdb_provider, _enrichment_service, _guardrail_engine, _store, _service, _runtime
    _store = store or default_store_factory()
    _misp_client = misp_client or MISPClient()
    _cmdb_provider = cmdb_provider or MockIAMCMDBProvider()
    _enrichment_service = enrichment_service or EnrichmentService(
        misp_client=_misp_client,
        cmdb_provider=_cmdb_provider,
    )
    if runner is not None:
        _guardrail_engine = guardrail_engine or runner.nodes.guardrail_engine
        _runner = runner
        if runner.nodes.guardrail_engine is not _guardrail_engine:
            raise ValueError("runner and API must share the same GuardrailEngine instance")
    else:
        _guardrail_engine = guardrail_engine or GuardrailEngine()
        _runner = AlertWorkflowRunner(
            enable_graph_persistence=False,
            guardrail_engine=_guardrail_engine,
            enrichment_service=_enrichment_service,
        )
    _runtime = runtime or {}
    _service = SOCService(
        runner=_runner,
        store=_store,
        guardrail_engine=_guardrail_engine,
        enrichment=_enrichment_service,
        narrative=narrative or NarrativeGenerator(),
        graph_client=_runner.graph_client,
    )
    return _service


def service() -> SOCService:
    if _service is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Service not initialized")
    return _service


def _raise(err: ServiceError) -> HTTPException:
    return HTTPException(status_code=err.status_code, detail=err.detail)


# ── Serializers ──────────────────────────────────────────────────────────────


def _summary(out: AlertWorkflowOutput) -> InvestigationSummary:
    f = out.finding
    return InvestigationSummary(
        alert_id=out.alert_id,
        finding_id=f.finding_info.uid if f else None,
        title=f.finding_info.title if f else "Unparsed Alert",
        priority=out.triage_result.priority.value if out.triage_result else "UNKNOWN",
        score=out.triage_result.score if out.triage_result else 0,
        severity=f.severity if f else "Unknown",
        workflow_status=out.workflow_status.value,
        received_at=out.received_at,
        event_time=f.time / 1000.0 if f else None,
        duration_ms=out.duration_ms,
        asset_name=f.device.name if f and f.device else None,
        username=f.user.name if f and f.user else None,
        src_ip=f.src_endpoint.ip if f and f.src_endpoint else None,
        dst_ip=f.dst_endpoint.ip if f and f.dst_endpoint else None,
        mitre_techniques=out.triage_result.mitre_techniques if out.triage_result else [],
        pending_approvals_count=len(out.pending_approvals),
        incident_id=_store.incident_for(out.alert_id),
        source=out.source,
        synthetic=bool(out.source_provenance.get("synthetic")),
    )


def _detail(out: AlertWorkflowOutput, enrichment: dict[str, Any] | None, deduplicated: bool = False) -> InvestigationDetailResponse:
    return InvestigationDetailResponse(
        alert_id=out.alert_id,
        workflow_status=out.workflow_status.value,
        is_valid=out.is_valid,
        source=out.source,
        received_at=out.received_at,
        completed_at=out.completed_at,
        duration_ms=out.duration_ms,
        completed_stages=out.completed_stages,
        stage_records={k: v.model_dump(mode="json") for k, v in out.stage_records.items()},
        finding=out.finding.model_dump(mode="json") if out.finding else None,
        resolution=out.resolution.model_dump(mode="json") if out.resolution else None,
        graph_persisted=out.graph_persisted,
        persisted_nodes_count=out.persisted_nodes_count,
        persisted_edges_count=out.persisted_edges_count,
        investigation_context=out.investigation_context.model_dump(mode="json") if out.investigation_context else None,
        triage_result=out.triage_result.model_dump(mode="json") if out.triage_result else None,
        guardrail_results=[g.model_dump(mode="json") for g in out.guardrail_results],
        pending_approvals=out.pending_approvals,
        audit_event_ids=out.audit_event_ids,
        uncertainties=out.uncertainties,
        errors=out.errors,
        enrichment=enrichment,
        incident_id=_store.incident_for(out.alert_id),
        source_provenance=out.source_provenance,
        deduplicated=deduplicated,
    )


def _incident_summary(incident: Incident) -> IncidentSummary:
    return IncidentSummary(
        incident_id=incident.incident_id,
        title=incident.title,
        status=incident.status.value,
        priority=incident.priority,
        risk_score=incident.risk_score,
        alert_count=len(incident.alert_ids),
        hosts=incident.hosts,
        users=incident.users,
        tactics=incident.tactics,
        first_seen=incident.first_seen,
        last_seen=incident.last_seen,
        updated_at=incident.updated_at,
        synthetic=incident.synthetic,
    )


def _approval_view(req: ApprovalRequest) -> dict[str, Any]:
    data = req.model_dump(mode="json")
    data["expires_in_seconds"] = max(0.0, req.expires_at - time.time())
    data["simulated"] = True
    return data


# ── Health ───────────────────────────────────────────────────────────────────


@router.get("/health/live", tags=["Health"])
async def liveness() -> dict[str, Any]:
    """Process is up. Performs no dependency checks."""
    return {"status": "ok", "checked_at": time.time()}


async def _collect_health() -> list[ServiceHealth]:
    services: list[ServiceHealth] = []
    svc = _service

    repo = _store.repository
    services.append(await repo.check_health())

    if _runner and _runner.graph_client:
        try:
            services.append(await _runner.graph_client.check_health())
        except Exception as err:
            services.append(ServiceHealth(name="neo4j", status=ServiceStatus.DOWN, detail=type(err).__name__))
    else:
        reason = _runtime.get("neo4j_reason", "Neo4j client not configured")
        services.append(ServiceHealth(name="neo4j", status=ServiceStatus.DEGRADED, detail=reason))

    if _misp_client and _misp_client.is_enabled:
        services.append(await _misp_client.check_health())
    else:
        services.append(ServiceHealth(name="misp", status=ServiceStatus.UNKNOWN, detail="Not configured (optional)"))

    wazuh = _runtime.get("wazuh_status", "disabled (WAZUH_ENABLED=false)")
    services.append(
        ServiceHealth(
            name="wazuh",
            status=ServiceStatus.OK if wazuh == "polling" else ServiceStatus.UNKNOWN,
            detail=f"Poller {wazuh} (optional)",
        )
    )

    if svc is not None:
        chain_ok, chain_err = svc.audit.verify_chain_integrity()
        services.append(
            ServiceHealth(
                name="audit_chain",
                status=ServiceStatus.OK if chain_ok else ServiceStatus.DOWN,
                detail=f"{svc.audit.event_count} events, chain verified" if chain_ok else f"Integrity failure: {chain_err}",
            )
        )
    return services


@router.get("/health/ready", response_model=HealthResponse, tags=["Health"])
@router.get("/health", response_model=HealthResponse, tags=["Health"])
@router.get("/api/v1/health", response_model=HealthResponse, tags=["Health"])
async def get_system_health(response: Response) -> HealthResponse:
    """Readiness: real checks of persistence, Neo4j, MISP, Wazuh poller, and audit chain.

    Optional integrations that are not configured report ``unknown``; the
    endpoint returns 503 only when a required component (persistence, audit
    chain) is down.
    """
    services = await _collect_health()
    required = {"persistence", "audit_chain"}
    if any(s.name in required and s.status == ServiceStatus.DOWN for s in services):
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    sys_health = SystemHealth(services)
    return HealthResponse(
        status=sys_health.overall.value,
        services=[s.to_dict() for s in services],
        checked_at=time.time(),
    )


# ── Session ──────────────────────────────────────────────────────────────────


@router.get("/api/v1/auth/me", tags=["Auth"])
async def whoami(principal: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Return the authenticated principal (used by the dashboard sign-in)."""
    return {"name": principal.name, "role": principal.role_name}


# ── Alert Ingestion & Processing ─────────────────────────────────────────────


@router.post(
    "/api/v1/alerts/ingest",
    response_model=InvestigationDetailResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Alerts"],
)
async def ingest_alert(
    request: AlertIngestRequest,
    response: Response,
    principal: Principal = Depends(require_analyst),
) -> InvestigationDetailResponse:
    """Ingest one raw alert and run the LangGraph investigation workflow.

    Duplicate alerts (same source + upstream ID, or identical content) return
    the existing investigation with HTTP 200 and ``deduplicated: true``.
    """
    try:
        output, deduplicated, _ = await service().ingest(
            request.raw_alert, request.source, request.provenance, actor=principal.name
        )
    except ServiceError as err:
        raise _raise(err) from err
    except Exception as err:
        logger.error("api_alert_ingest_failed", error=type(err).__name__, detail=str(err))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Alert ingestion failed ({type(err).__name__})",
        ) from err
    if deduplicated:
        response.status_code = status.HTTP_200_OK
    found = _store.get(output.alert_id)
    return _detail(output, found[1] if found else output.enrichment, deduplicated=deduplicated)


@router.post("/api/v1/alerts/ingest/batch", tags=["Alerts"])
async def ingest_batch(
    request: AlertBatchIngestRequest,
    principal: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Ingest up to 100 alerts; each result reports created / deduplicated / failed."""
    results: list[dict[str, Any]] = []
    for raw in request.alerts:
        try:
            output, dedup, incident_id = await service().ingest(raw, request.source, request.provenance, principal.name)
            results.append({
                "alert_id": output.alert_id,
                "result": "deduplicated" if dedup else "created",
                "workflow_status": output.workflow_status.value,
                "priority": output.triage_result.priority.value if output.triage_result else None,
                "incident_id": incident_id,
            })
        except Exception as err:
            results.append({"alert_id": None, "result": "failed", "error": type(err).__name__})
    return {"count": len(results), "results": results}


@router.get("/api/v1/alerts", response_model=PaginatedResponse[InvestigationSummary], tags=["Alerts"])
@router.get("/api/v1/investigations", response_model=PaginatedResponse[InvestigationSummary], tags=["Investigations"])
async def list_investigations(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    priority: str | None = Query(default=None, max_length=16),
    status_filter: str | None = Query(default=None, alias="status", max_length=16),
    search: str | None = Query(default=None, max_length=200),
    incident_id: str | None = Query(default=None, max_length=64),
    host: str | None = Query(default=None, max_length=255),
    _: Principal = Depends(require_viewer),
) -> PaginatedResponse[InvestigationSummary]:
    """Paginated alerts (investigations) with filters."""
    outputs, total = _store.list_all(
        page=page, page_size=page_size, priority=priority, status=status_filter,
        search=search, incident_id=incident_id, host=host,
    )
    total_pages = max(1, math.ceil(total / page_size)) if total > 0 else 1
    return PaginatedResponse(
        items=[_summary(o) for o in outputs], total=total, page=page, page_size=page_size, total_pages=total_pages
    )


@router.get("/api/v1/alerts/{alert_id}", response_model=InvestigationDetailResponse, tags=["Alerts"])
@router.get("/api/v1/investigations/{alert_id}", response_model=InvestigationDetailResponse, tags=["Investigations"])
async def get_investigation(alert_id: str, _: Principal = Depends(require_viewer)) -> InvestigationDetailResponse:
    """Full investigation detail for one alert, including raw alert and enrichment."""
    res = _store.get(alert_id)
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation for alert '{alert_id}' not found")
    output, enrichment = res
    return _detail(output, enrichment)


@router.post("/api/v1/investigations/{alert_id}/enrich", response_model=dict[str, Any], tags=["Investigations"])
async def trigger_enrichment(alert_id: str, principal: Principal = Depends(require_analyst)) -> dict[str, Any]:
    """Re-run threat-intel and CMDB/IAM enrichment. Does not change the stored triage score."""
    res = _store.get(alert_id)
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Investigation for alert '{alert_id}' not found")
    output, _ = res
    if not output.finding:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot enrich alert without normalized finding")
    if not _enrichment_service:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Enrichment service not configured")
    enrichment_data = await _enrichment_service.enrich_finding(output.finding)
    _store.save(output, enrichment=enrichment_data)
    await _store.flush()
    return enrichment_data


# ── Demo scenarios ───────────────────────────────────────────────────────────


@router.get("/api/v1/demo/scenarios", tags=["Demo"])
async def list_scenarios(_: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Synthetic scenarios available for loading (all data is simulated)."""
    return {
        "demo_mode": bool(_runtime.get("demo_mode", True)),
        "scenarios": [
            {
                "scenario_id": s.scenario_id,
                "name": s.name,
                "description": s.description,
                "expected_outcome": s.expected_outcome,
                "alert_count": len(s.alerts),
                "synthetic": True,
            }
            for s in SCENARIOS.values()
        ],
    }


@router.post("/api/v1/demo/scenarios/{scenario_id}/load", tags=["Demo"])
async def load_scenario(scenario_id: str, principal: Principal = Depends(require_analyst)) -> dict[str, Any]:
    """Ingest a synthetic scenario through the normal pipeline (idempotent)."""
    if not _runtime.get("demo_mode", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Demo mode disabled (DEMO_MODE=false)")
    scenario = SCENARIOS.get(scenario_id)
    if scenario is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Unknown scenario '{scenario_id}'")
    results: list[dict[str, Any]] = []
    for raw in scenario.materialize():
        output, dedup, incident_id = await service().ingest(
            raw, "demo", {"synthetic": True, "scenario_id": scenario_id}, principal.name
        )
        results.append({
            "alert_id": output.alert_id,
            "result": "deduplicated" if dedup else "created",
            "title": output.finding.finding_info.title if output.finding else None,
            "priority": output.triage_result.priority.value if output.triage_result else None,
            "score": output.triage_result.score if output.triage_result else None,
            "incident_id": incident_id,
        })
    return {"scenario_id": scenario_id, "synthetic": True, "results": results}


# ── Incidents ────────────────────────────────────────────────────────────────


@router.get("/api/v1/incidents", response_model=PaginatedResponse[IncidentSummary], tags=["Incidents"])
async def list_incidents(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status_filter: str | None = Query(default=None, alias="status", max_length=32),
    priority: str | None = Query(default=None, max_length=16),
    search: str | None = Query(default=None, max_length=200),
    _: Principal = Depends(require_viewer),
) -> PaginatedResponse[IncidentSummary]:
    """Incidents ordered by open-first, then risk, then recency."""
    items = list(_store.incidents.values())
    if status_filter:
        items = [i for i in items if i.status.value == status_filter.upper()]
    if priority:
        items = [i for i in items if i.priority == priority.upper()]
    if search:
        term = search.lower()
        items = [
            i for i in items
            if term in i.title.lower() or term in i.incident_id.lower()
            or any(term in h.lower() for h in i.hosts + i.users + i.indicators)
        ]
    items.sort(key=lambda i: (not i.is_open, -i.risk_score, -(i.last_seen or 0)))
    total = len(items)
    start = (page - 1) * page_size
    return PaginatedResponse(
        items=[_incident_summary(i) for i in items[start : start + page_size]],
        total=total, page=page, page_size=page_size,
        total_pages=max(1, math.ceil(total / page_size)) if total else 1,
    )


@router.get("/api/v1/incidents/{incident_id}", tags=["Incidents"])
async def get_incident(incident_id: str, _: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Incident with its alerts, approvals, and related audit events."""
    svc = service()
    try:
        incident = svc.get_incident(incident_id)
        approvals = svc.incident_approvals(incident_id)
    except ServiceError as err:
        raise _raise(err) from err
    alerts = _store.alerts_for_incident(incident_id)
    alert_ids = set(incident.alert_ids)
    audit = [
        e.model_dump(mode="json") for e in svc.audit.get_events()
        if e.metadata.get("incident_id") == incident_id or e.metadata.get("alert_id") in alert_ids
        or e.approval_id in {a.request_id for a in approvals}
    ][-50:]
    return {
        "incident": incident.model_dump(mode="json"),
        "alerts": [_summary(o).model_dump() for o in sorted(alerts, key=lambda o: o.finding.time if o.finding else 0)],
        "approvals": [_approval_view(a) for a in approvals],
        "audit_events": audit,
        "available_actions": [
            {"action_name": s.action_name, "label": s.label, "category": s.category.value,
             "target_kind": s.target_kind, "description": s.description}
            for s in RESPONSE_ACTIONS.values()
        ],
        "narrative_mode": svc.narrative.describe(),
    }


@router.patch("/api/v1/incidents/{incident_id}/status", tags=["Incidents"])
async def update_incident_status(
    incident_id: str, payload: IncidentStatusRequest, principal: Principal = Depends(require_analyst)
) -> dict[str, Any]:
    try:
        incident = await service().set_status(incident_id, IncidentStatus(payload.status), principal.name, payload.reason)
    except ServiceError as err:
        raise _raise(err) from err
    return incident.model_dump(mode="json")


@router.post("/api/v1/incidents/{incident_id}/notes", status_code=status.HTTP_201_CREATED, tags=["Incidents"])
async def add_incident_note(
    incident_id: str, payload: NoteRequest, principal: Principal = Depends(require_analyst)
) -> dict[str, Any]:
    try:
        note = await service().add_note(incident_id, principal.name, payload.text)
    except ServiceError as err:
        raise _raise(err) from err
    return note.model_dump(mode="json")


@router.post("/api/v1/incidents/{incident_id}/actions", status_code=status.HTTP_201_CREATED, tags=["Guardrails"])
async def propose_action(
    incident_id: str, payload: ActionProposalRequest, principal: Principal = Depends(require_analyst)
) -> dict[str, Any]:
    """Propose a (simulated) response action; the guardrail decides ALLOW/REQUIRE_APPROVAL/DENY."""
    try:
        result = await service().propose_action(
            incident_id, payload.action_name, payload.target, payload.rationale, principal.name
        )
    except ServiceError as err:
        raise _raise(err) from err
    return {"guardrail": result.model_dump(mode="json"), "simulated": True, "notice": SIMULATION_NOTICE}


@router.post("/api/v1/incidents/{incident_id}/narrative", tags=["Incidents"])
async def generate_narrative(
    incident_id: str, payload: NarrativeRequest, principal: Principal = Depends(require_analyst)
) -> dict[str, Any]:
    """Generate the evidence-cited narrative (template, or LLM when configured and requested)."""
    try:
        return await service().generate_narrative(incident_id, payload.use_llm, principal.name)
    except ServiceError as err:
        raise _raise(err) from err


@router.get("/api/v1/incidents/{incident_id}/report", tags=["Incidents"])
async def export_report(incident_id: str, _: Principal = Depends(require_viewer)) -> Response:
    """Downloadable JSON incident report."""
    import json

    try:
        report = service().report(incident_id)
    except ServiceError as err:
        raise _raise(err) from err
    return Response(
        content=json.dumps(report, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{incident_id}-report.json"'},
    )


@router.get("/api/v1/incidents/{incident_id}/graph", tags=["Graph"])
async def incident_graph(incident_id: str, _: Principal = Depends(require_viewer)) -> dict[str, Any]:
    try:
        return await service().incident_graph(incident_id)
    except ServiceError as err:
        raise _raise(err) from err


@router.get("/api/v1/graph/entities/{entity_id:path}", tags=["Graph"])
async def entity_graph(
    entity_id: str,
    depth: int = Query(default=1, ge=1, le=2),
    _: Principal = Depends(require_viewer),
) -> dict[str, Any]:
    """Neighborhood of one canonical entity (e.g. ``asset:agent:001``)."""
    try:
        return await service().entity_graph(entity_id, depth)
    except ServiceError as err:
        raise _raise(err) from err


# ── Threat intelligence ─────────────────────────────────────────────────────


@router.get("/api/v1/intel/indicators", tags=["Threat Intel"])
async def observed_indicators(_: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Every indicator observed in stored alerts with its most recent verdict."""
    rows: dict[str, dict[str, Any]] = {}
    for out in reversed(_store.all_outputs()):
        enrichment = out.enrichment or {}
        for indicator, record in (enrichment.get("indicator_verdicts") or {}).items():
            row = rows.setdefault(indicator, {
                "indicator": indicator, "indicator_type": record.get("indicator_type"),
                "alert_ids": [], "incident_ids": [], "first_seen": out.received_at,
            })
            row.update({
                "verdict": record.get("verdict"), "rationale": record.get("rationale"),
                "synthetic": record.get("synthetic", False), "sources": record.get("sources", []),
                "last_seen": out.received_at,
            })
            row["alert_ids"].append(out.alert_id)
            inc = _store.incident_for(out.alert_id)
            if inc and inc not in row["incident_ids"]:
                row["incident_ids"].append(inc)
    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "UNKNOWN": 2, "BENIGN": 3}
    items = sorted(rows.values(), key=lambda r: (order.get(str(r.get("verdict")), 9), r["indicator"]))
    return {
        "items": items,
        "sources": {
            "misp": "enabled" if (_misp_client and _misp_client.is_enabled) else "not configured",
            "demo_intel_feed": "enabled (synthetic)" if _runtime.get("demo_mode", True) else "disabled",
        },
    }


@router.get("/api/v1/intel/lookup", tags=["Threat Intel"])
async def intel_lookup(
    indicator: str = Query(..., min_length=3, max_length=255),
    _: Principal = Depends(require_analyst),
) -> dict[str, Any]:
    """Look up an IP or domain across configured intel sources."""
    import ipaddress

    if not _enrichment_service:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Enrichment not configured")
    value = indicator.strip().lower()
    try:
        ipaddress.ip_address(value)
        kind = "ip"
    except ValueError:
        if not all(c.isalnum() or c in ".-" for c in value) or "." not in value:
            raise HTTPException(status_code=422, detail="Indicator must be an IP address or domain name") from None
        kind = "domain"
    assessment, _misp = await _enrichment_service.lookup_indicator(value, kind)
    return assessment.model_dump(mode="json")


@router.get("/api/v1/intel/demo-feed", tags=["Threat Intel"])
async def demo_feed(_: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Contents of the synthetic demo feed (for transparency)."""
    return {"synthetic": True, "entries": DemoIntelFeed.entries()}


# ── Statistics & Dashboard Overview ──────────────────────────────────────────


@router.get("/api/v1/stats", response_model=dict[str, int], tags=["Dashboard"])
async def get_investigation_stats(_: Principal = Depends(require_viewer)) -> dict[str, int]:
    """Aggregate counts (legacy endpoint; see /api/v1/dashboard)."""
    return _store.get_stats()


@router.get("/api/v1/dashboard", tags=["Dashboard"])
async def get_dashboard(
    bucket_hours: int = Query(default=1, ge=1, le=24),
    _: Principal = Depends(require_viewer),
) -> dict[str, Any]:
    """SOC overview: counts, trend, top entities, priority incidents, recent activity."""
    svc = service()
    data = _store.dashboard(bucket_hours=bucket_hours)
    data["priority_incidents"] = [
        _incident_summary(_store.incidents[i]).model_dump() for i in data["priority_incidents"]
    ]
    data["recent_alerts"] = [_summary(o).model_dump() for o in _store.all_outputs()[:8]]
    pending = svc.approvals.list_all(ApprovalStatus.PENDING)
    data["pending_approvals"] = [_approval_view(a) for a in pending[:8]]
    data["stats"]["pending_approvals"] = len(pending)
    data["recent_audit"] = [e.model_dump(mode="json") for e in svc.audit.get_events()[-8:]][::-1]
    data["services"] = [s.to_dict() for s in await _collect_health()]
    data["synthetic_data_present"] = any(i.synthetic for i in _store.incidents.values()) or any(
        o.source_provenance.get("synthetic") for o in _store.all_outputs()
    )
    return data


# ── External Integrations Status ─────────────────────────────────────────────


@router.get("/api/v1/integrations/status", response_model=IntegrationsStatusResponse, tags=["Integrations"])
async def get_integrations_status(_: Principal = Depends(require_viewer)) -> IntegrationsStatusResponse:
    """Integration configuration and state; never includes credentials."""
    misp_info: dict[str, Any] = {
        "enabled": _misp_client.is_enabled if _misp_client else False,
        "base_url": _misp_client._base_url if _misp_client and _misp_client.is_enabled else "not configured",
        "verify_ssl": _misp_client._verify_ssl if _misp_client else True,
    }
    neo4j_info: dict[str, Any] = {
        "enabled": bool(_runner and _runner.graph_client),
        "database": "neo4j",
        "detail": _runtime.get("neo4j_reason", "connected" if _runner and _runner.graph_client else "not configured"),
    }
    cmdb_info: dict[str, Any] = {
        "enabled": bool(_cmdb_provider),
        "provider": type(_cmdb_provider).__name__ if _cmdb_provider else "none",
        "synthetic": isinstance(_cmdb_provider, MockIAMCMDBProvider),
    }
    wazuh_info: dict[str, Any] = {
        "enabled": _runtime.get("wazuh_status") == "polling",
        "status": _runtime.get("wazuh_status", "disabled (WAZUH_ENABLED=false)"),
        "endpoint": _runtime.get("wazuh_endpoint", "/alerts"),
    }
    return IntegrationsStatusResponse(
        wazuh=wazuh_info,
        neo4j=neo4j_info,
        misp=misp_info,
        cmdb=cmdb_info,
        persistence={"backend": _store.repository.backend},
        llm=service().narrative.describe(),
        auth={"configured": get_registry().configured, "mode": "api_key"},
        demo_mode=bool(_runtime.get("demo_mode", True)),
    )


# ── Approvals ────────────────────────────────────────────────────────────────


@router.get("/api/v1/approvals", tags=["Guardrails"])
async def list_approvals(
    status_filter: str | None = Query(default=None, alias="status", max_length=16),
    _: Principal = Depends(require_viewer),
) -> dict[str, Any]:
    st: ApprovalStatus | None = None
    if status_filter:
        try:
            st = ApprovalStatus(status_filter.upper())
        except ValueError as err:
            raise HTTPException(status_code=422, detail=f"Unknown status '{status_filter}'") from err
    return {"items": [_approval_view(r) for r in service().approvals.list_all(st)]}


@router.get("/api/v1/approvals/{request_id}", tags=["Guardrails"])
async def get_approval(request_id: str, _: Principal = Depends(require_viewer)) -> dict[str, Any]:
    try:
        return _approval_view(service().get_approval(request_id))
    except ServiceError as err:
        raise _raise(err) from err


@router.post(
    "/api/v1/approvals/{request_id}/decide",
    response_model=ApprovalDecisionResponse,
    tags=["Guardrails"],
)
async def submit_approval_decision(
    request_id: str,
    payload: ApprovalDecisionRequest,
    principal: Principal = Depends(require_approver),
) -> ApprovalDecisionResponse:
    """Approve or reject a pending action. The reviewer is the authenticated principal."""
    try:
        updated = await service().decide(request_id, payload.decision, principal.name, payload.reason)
    except ServiceError as err:
        raise _raise(err) from err
    return ApprovalDecisionResponse(
        request_id=updated.request_id,
        status=updated.status.value,
        reviewer_id=updated.reviewer_id or principal.name,
        decision_at=updated.decision_at or time.time(),
        decision_reason=updated.decision_reason,
        message=f"Request '{request_id}' {updated.status.value} by '{principal.name}'",
    )


@router.post("/api/v1/approvals/{request_id}/execute", tags=["Guardrails"])
async def execute_approval(request_id: str, principal: Principal = Depends(require_approver)) -> dict[str, Any]:
    """Execute an APPROVED action exactly once after guardrail re-validation (simulated)."""
    try:
        updated, result = await service().execute(request_id, principal.name)
    except ServiceError as err:
        raise _raise(err) from err
    return {
        "approval": _approval_view(updated),
        "guardrail": result.model_dump(mode="json"),
        "simulated": True,
        "notice": SIMULATION_NOTICE,
    }


# ── Audit ────────────────────────────────────────────────────────────────────


@router.get("/api/v1/audit", tags=["Audit"])
async def list_audit(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    actor: str | None = Query(default=None, max_length=100),
    operation: str | None = Query(default=None, max_length=100),
    _: Principal = Depends(require_viewer),
) -> dict[str, Any]:
    """Audit events, newest first."""
    events = service().audit.get_events()[::-1]
    if actor:
        events = [e for e in events if e.actor == actor]
    if operation:
        events = [e for e in events if operation.lower() in e.operation.lower()]
    total = len(events)
    start = (page - 1) * page_size
    return {
        "items": [e.model_dump(mode="json") for e in events[start : start + page_size]],
        "total": total, "page": page, "page_size": page_size,
        "total_pages": max(1, math.ceil(total / page_size)) if total else 1,
    }


@router.get("/api/v1/audit/verify", tags=["Audit"])
async def verify_audit(_: Principal = Depends(require_viewer)) -> dict[str, Any]:
    """Recompute the SHA-256 hash chain. Tamper-evident, not tamper-proof."""
    audit = service().audit
    ok, err = audit.verify_chain_integrity()
    events = audit.get_events()
    return {
        "verified": ok,
        "error": err,
        "event_count": len(events),
        "head_hash": events[-1].event_hash if events else None,
        "checked_at": time.time(),
        "note": "A valid chain shows no event was altered, removed, or reordered relative to the stored chain. "
        "An attacker able to rewrite the entire chain and its storage can produce a new valid chain; "
        "anchor the head hash externally for stronger guarantees.",
    }


@router.get("/api/v1/actions/catalog", tags=["Guardrails"])
async def action_catalog(_: Principal = Depends(require_viewer)) -> dict[str, Any]:
    return {
        "simulated": True,
        "notice": SIMULATION_NOTICE,
        "actions": [
            {"action_name": s.action_name, "label": s.label, "category": s.category.value,
             "target_kind": s.target_kind, "description": s.description}
            for s in RESPONSE_ACTIONS.values()
        ],
    }
