"""
tests/unit/test_resilience.py — Comprehensive resilience, evaluation, and security hardening tests.

Validates:
- Quantitative pipeline evaluation against ground-truth labeled benchmark.
- Adversarial prompt-injection resilience in telemetry strings.
- Graceful degradation under Neo4j and MISP connection failures.
- Tamper-evident audit store cryptographic hash chain verification.
- Cryptographic binding of human approvals to exact action parameters.
- Idempotency and replay protection.
- HTTP security response headers and defensive API middleware.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from starlette.testclient import TestClient

from api.app import create_app
from api.routes import init_api_dependencies
from api.store import InvestigationStore
from guardrails.approval import ApprovalService
from guardrails.audit import HashChainAuditStore
from guardrails.engine import GuardrailEngine, GuardrailPolicy
from guardrails.models import ActionCategory, ActionProposal
from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.misp import MISPClient
from orchestrator.state import WorkflowStatus
from orchestrator.workflow import AlertWorkflowRunner
from simulation.evaluation import evaluate_pipeline
from simulation.scenarios import (
    SCENARIO_CONFLICTING_EVIDENCE,
    SCENARIO_CRITICAL_LATERAL_MOVEMENT,
    SCENARIO_PROMPT_INJECTION_TELEMETRY,
)


@pytest.fixture
def mock_runner() -> AlertWorkflowRunner:
    """Create test workflow runner with graph persistence disabled."""
    return AlertWorkflowRunner(enable_graph_persistence=False)


@pytest.mark.asyncio
async def test_end_to_end_pipeline_evaluation(mock_runner: AlertWorkflowRunner) -> None:
    """Evaluate pipeline against 20 ground-truth labeled benchmark alerts."""
    report = await evaluate_pipeline(runner=mock_runner)

    assert report.total_samples == 20
    assert report.overall_accuracy >= 0.85
    assert report.macro_f1 >= 0.80
    assert report.guardrail_accuracy >= 0.70
    assert report.mitre_extraction_recall >= 0.80

    # Verify 4x4 confusion matrix completeness
    for prio in ["P1", "P2", "P3", "P4"]:
        assert prio in report.confusion_matrix
        assert prio in report.class_metrics
        assert report.class_metrics[prio].support > 0


@pytest.mark.asyncio
async def test_tamper_evident_audit_store_integrity() -> None:
    """Verify SHA-256 hash chaining and tamper detection in audit store."""
    audit_store = HashChainAuditStore()

    audit_store.log_event(
        actor="secops-1",
        operation="triage_completed",
        decision="EVALUATED",
        policy_id="pol-01",
        outcome="P1 assigned",
    )
    e2 = audit_store.log_event(
        actor="guardrail-engine",
        operation="action_evaluated",
        decision="REQUIRE_APPROVAL",
        policy_id="pol-01",
        outcome="Blocked host isolation",
    )
    audit_store.log_event(
        actor="secops-lead",
        operation="human_approval_decision",
        decision="APPROVE",
        policy_id="pol-01",
        outcome="Isolation authorized",
    )

    # 1. Unmodified chain must pass cryptographic verification
    is_valid, _ = audit_store.verify_chain_integrity()
    assert is_valid is True
    assert len(audit_store.get_events()) == 3

    # 2. Tampering with any historical event must break chain verification
    original_outcome = e2.outcome
    e2.outcome = "Forged approval outcome"
    is_valid_tampered, _ = audit_store.verify_chain_integrity()
    assert is_valid_tampered is False

    # Restore
    e2.outcome = original_outcome
    is_valid_restored, _ = audit_store.verify_chain_integrity()
    assert is_valid_restored is True


@pytest.mark.asyncio
async def test_guardrail_approval_cryptographic_binding() -> None:
    """Verify that action approvals are cryptographically bound to exact parameters."""
    service = ApprovalService()

    action = ActionProposal(
        action_name="isolate_host",
        category=ActionCategory.CONTAINMENT,
        target_entities=["srv-dc-01"],
        parameters={"quarantine_vlan": 99, "duration_hours": 4},
        rationale="Active lateral movement",
    )

    req = service.create_request(action=action)
    assert req.action_hash == action.compute_action_hash()

    # Approving with correct reviewer succeeds
    approved_req = service.approve(
        request_id=req.request_id,
        reviewer_id="lead-analyst",
        reason="Verified C2 callback",
    )
    assert approved_req.reviewer_id == "lead-analyst"

    # Verifying action matches approved request
    is_valid, _ = approved_req.is_valid_for(action)
    assert is_valid is True

    # Tampering with action parameters invalidates the approval
    tampered_action = ActionProposal(
        action_name="isolate_host",
        category=ActionCategory.CONTAINMENT,
        target_entities=["srv-dc-01"],
        parameters={"quarantine_vlan": 1, "duration_hours": 999},  # Altered!
        rationale="Active lateral movement",
    )
    is_valid_tampered, _ = approved_req.is_valid_for(tampered_action)
    assert is_valid_tampered is False


@pytest.mark.asyncio
async def test_adversarial_prompt_injection_telemetry_isolation(mock_runner: AlertWorkflowRunner) -> None:
    """Verify that malicious instructions embedded in telemetry strings are treated as passive data."""
    output = await mock_runner.process_alert(
        raw_alert=SCENARIO_PROMPT_INJECTION_TELEMETRY,
        source="wazuh",
    )

    # Telemetry must NOT trick the engine into downgrading to LOW
    assert output.triage_result is not None
    assert output.triage_result.priority.value in ("HIGH", "CRITICAL")
    assert "T1059" in output.triage_result.mitre_techniques

    # Raw description is preserved passively without interpretation
    assert output.finding is not None
    assert output.finding.finding_info.desc is not None
    assert "SYSTEM OVERRIDE" in output.finding.finding_info.desc


@pytest.mark.asyncio
async def test_conflicting_evidence_and_missing_data_resilience(mock_runner: AlertWorkflowRunner) -> None:
    """Verify graceful handling of incomplete, conflicting telemetry without crashing."""
    output = await mock_runner.process_alert(
        raw_alert=SCENARIO_CONFLICTING_EVIDENCE,
        source="wazuh",
    )

    assert output.is_valid is True
    assert output.workflow_status in (WorkflowStatus.COMPLETED, WorkflowStatus.PARTIAL)
    assert output.triage_result is not None

    # Missing evidence must be flagged in uncertainties, never treated as proof of safety
    assert len(output.uncertainties) > 0
    assert any("graph" in u.lower() or "missing" in u.lower() or "skipped" in u.lower() for u in output.uncertainties)


@pytest.mark.asyncio
async def test_misp_resilience_and_graceful_degradation(mock_runner: AlertWorkflowRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that MISP timeout or failure does not crash the enrichment or investigation pipeline."""
    # Mock httpx client in MISP to simulate connection timeout
    async def mock_post(self: Any, url: str, **kwargs: Any) -> httpx.Response:
        req = httpx.Request("POST", url)
        raise httpx.TimeoutException("MISP gateway timed out", request=req)

    monkeypatch.setattr(httpx.AsyncClient, "post", mock_post)

    misp = MISPClient(timeout_seconds=1.0)
    cmdb = MockIAMCMDBProvider()
    enrichment = EnrichmentService(misp_client=misp, cmdb_provider=cmdb)

    output = await mock_runner.process_alert(
        raw_alert=SCENARIO_CRITICAL_LATERAL_MOVEMENT,
        source="wazuh",
    )
    assert output.finding is not None

    enrichment_result = await enrichment.enrich_finding(output.finding)
    assert "misp" in enrichment_result
    # Crucial principle: Absence of response is UNKNOWN, not confirmed safe
    for match in enrichment_result["misp"]:
        assert match["is_confirmed_safe"] is False


@pytest.mark.asyncio
async def test_event_replay_idempotency(mock_runner: AlertWorkflowRunner) -> None:
    """Verify that replaying the identical alert produces deterministic, idempotent findings."""
    res1 = await mock_runner.process_alert(
        raw_alert=SCENARIO_CRITICAL_LATERAL_MOVEMENT,
        source="wazuh",
    )
    res2 = await mock_runner.process_alert(
        raw_alert=SCENARIO_CRITICAL_LATERAL_MOVEMENT,
        source="wazuh",
    )

    assert res1.finding is not None
    assert res2.finding is not None
    # Identical alert producing consistent finding title and severity
    assert res1.finding.finding_info.title == res2.finding.finding_info.title
    assert res1.finding.severity == res2.finding.severity
    assert res1.triage_result is not None
    assert res2.triage_result is not None
    assert res1.triage_result.priority == res2.triage_result.priority
    assert res1.triage_result.score == res2.triage_result.score


def test_api_security_response_headers() -> None:
    """Verify that FastAPI responses include defense-in-depth HTTP security headers."""
    store = InvestigationStore(max_capacity=10)
    engine = GuardrailEngine(policy=GuardrailPolicy())
    runner = AlertWorkflowRunner(enable_graph_persistence=False, guardrail_engine=engine)

    init_api_dependencies(
        runner=runner,
        guardrail_engine=engine,
        store=store,
    )
    app = create_app()
    client = TestClient(app)

    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "DENY"
    # OWASP recommends disabling the legacy XSS auditor ("0"); "1; mode=block"
    # can itself introduce cross-site leaks in browsers that still implement it.
    assert res.headers.get("X-XSS-Protection") == "0"
    assert "strict-origin" in (res.headers.get("Referrer-Policy") or "")
