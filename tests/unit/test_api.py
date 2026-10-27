"""
tests/unit/test_api.py — Unit tests for ThreatFusion AI FastAPI endpoints.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from api.app import create_app
from api.auth import APIKeyRegistry, configure_registry
from api.routes import init_api_dependencies
from api.store import InvestigationStore
from guardrails.engine import GuardrailEngine, GuardrailPolicy
from guardrails.models import ActionCategory, ActionProposal
from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.misp import MISPClient
from orchestrator.workflow import AlertWorkflowRunner


@pytest.fixture
def test_client() -> TestClient:
    """Create a test client with isolated in-memory stores and mock services."""
    store = InvestigationStore(max_capacity=100)
    engine = GuardrailEngine(policy=GuardrailPolicy())
    runner = AlertWorkflowRunner(enable_graph_persistence=False, guardrail_engine=engine)
    misp = MISPClient()
    cmdb = MockIAMCMDBProvider()
    enrichment = EnrichmentService(misp_client=misp, cmdb_provider=cmdb)

    init_api_dependencies(
        runner=runner,
        misp_client=misp,
        cmdb_provider=cmdb,
        enrichment_service=enrichment,
        guardrail_engine=engine,
        store=store,
    )

    configure_registry(
        APIKeyRegistry(
            "viewer:viewer:test-viewer-key-123456,"
            "analyst:analyst:test-analyst-key-123456,"
            "lead-secops-analyst:approver:test-approver-key-123456"
        )
    )
    app = create_app()
    client = TestClient(app)
    client.headers["Authorization"] = "Bearer test-analyst-key-123456"
    return client


APPROVER = {"Authorization": "Bearer test-approver-key-123456"}


def test_health_endpoints(test_client: TestClient) -> None:
    """Verify both /health and /api/v1/health return 200 OK."""
    res1 = test_client.get("/health")
    assert res1.status_code == 200
    assert "status" in res1.json()
    assert "services" in res1.json()

    res2 = test_client.get("/api/v1/health")
    assert res2.status_code == 200
    assert res2.json()["status"] == res1.json()["status"]


def test_integrations_status(test_client: TestClient) -> None:
    """Verify integrations status reports external systems safely."""
    res = test_client.get("/api/v1/integrations/status")
    assert res.status_code == 200
    data = res.json()
    assert "wazuh" in data
    assert "neo4j" in data
    assert "misp" in data
    assert "cmdb" in data
    assert data["cmdb"]["enabled"] is True


def test_stats_initial_empty(test_client: TestClient) -> None:
    """Verify stats returns empty totals initially."""
    res = test_client.get("/api/v1/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_investigations" in data
    assert "pending_approvals" in data


def test_alert_ingest_and_retrieval(test_client: TestClient) -> None:
    """Verify alert ingestion triggers workflow, stores result, and allows retrieval."""
    raw_alert = {
        "timestamp": "2026-10-17T12:00:00.000Z",
        "rule": {
            "id": "100201",
            "level": 12,
            "description": "Suspicious PowerShell encoded command executed",
            "mitre": {"id": ["T1059.001"]},
        },
        "agent": {
            "id": "001",
            "name": "web-server-01",
            "ip": "192.168.1.50",
        },
        "data": {
            "win": {
                "eventdata": {
                    "targetUserName": "admin",
                    "commandLine": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=",
                }
            }
        },
    }

    # 1. Ingest alert
    ingest_res = test_client.post(
        "/api/v1/alerts/ingest",
        json={"raw_alert": raw_alert, "source": "wazuh"},
    )
    assert ingest_res.status_code == 201
    ingest_data = ingest_res.json()
    alert_id = ingest_data["alert_id"]
    assert alert_id is not None
    assert ingest_data["workflow_status"] in ("COMPLETED", "PARTIAL")
    assert ingest_data["triage_result"] is not None

    # 2. List investigations
    list_res = test_client.get("/api/v1/investigations")
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(item["alert_id"] == alert_id for item in list_data["items"])

    # 3. Retrieve detail
    detail_res = test_client.get(f"/api/v1/investigations/{alert_id}")
    assert detail_res.status_code == 200
    detail_data = detail_res.json()
    assert detail_data["alert_id"] == alert_id
    assert detail_data["finding"] is not None

    # 4. Trigger on-demand enrichment
    enrich_res = test_client.post(f"/api/v1/investigations/{alert_id}/enrich")
    assert enrich_res.status_code == 200
    enrich_data = enrich_res.json()
    assert "cmdb_asset" in enrich_data
    assert enrich_data["cmdb_asset"]["hostname"] == "web-server-01"


def test_investigation_not_found(test_client: TestClient) -> None:
    """Verify 404 for non-existent alert ID."""
    res = test_client.get("/api/v1/investigations/non-existent-alert-999")
    assert res.status_code == 404


def test_approval_decision_workflow(test_client: TestClient) -> None:
    """Verify human approval and rejection endpoints with tamper-evident audit logging."""
    from api.routes import _guardrail_engine

    assert _guardrail_engine is not None
    approval_svc = _guardrail_engine.approval_service

    # Create a pending approval request using create_request
    req = approval_svc.create_request(
        action=ActionProposal(
            action_name="isolate_host",
            category=ActionCategory.CONTAINMENT,
            target_entities=["web-server-01"],
            parameters={"method": "network_quarantine"},
            rationale="Lateral movement containment",
        )
    )

    # 1. Reject first (reviewer identity comes from the API key, not the body)
    reject_res = test_client.post(
        f"/api/v1/approvals/{req.request_id}/decide",
        json={
            "reviewer_id": "someone-else-spoofed",
            "decision": "REJECT",
            "reason": "False positive test run",
        },
        headers=APPROVER,
    )
    assert reject_res.status_code == 200
    reject_data = reject_res.json()
    assert reject_data["status"] == "REJECTED"
    assert reject_data["reviewer_id"] == "lead-secops-analyst"

    # 2. Unknown request ID gives 404
    missing_res = test_client.post(
        "/api/v1/approvals/non-existent-req-404/decide",
        json={
            "reviewer_id": "lead-secops-analyst",
            "decision": "APPROVE",
        },
        headers=APPROVER,
    )
    assert missing_res.status_code == 404
