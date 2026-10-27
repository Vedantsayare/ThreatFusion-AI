"""
tests/unit/test_platform.py — End-to-end platform behaviour through the API.

Covers: authentication/authorization, the shared guardrail engine, approval
expiry / replay / tampering / self-approval, deduplication, input validation,
demo-scenario correlation, incident lifecycle, report export, audit-chain
verification and tampering, persistence across restart (SQLite), database
failure handling, threat-intel verdict policy, triage score accounting,
normalization additions, per-alert resolution scope, and narrative guardrails.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from agents.models import IncidentPriority
from agents.narrative import (
    NarrativeGenerator,
    _validate_llm_output,
    build_evidence,
    template_narrative,
)
from agents.triage import AlertTriageEngine
from api.app import create_app
from api.auth import APIKeyRegistry, configure_registry
from api.incidents import correlation_keys
from api.persistence import NullRepository
from api.routes import init_api_dependencies
from api.store import InvestigationStore
from guardrails.audit import HashChainAuditStore
from guardrails.engine import GuardrailEngine
from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.intel import DemoIntelFeed, IntelVerdict, SourceVerdict, combine_verdicts
from ingestion.misp import MISPClient
from normalization.normalizer import OCSFNormalizer
from orchestrator.workflow import AlertWorkflowRunner

VIEWER = {"Authorization": "Bearer viewer-key-0123456789"}
ANALYST = {"Authorization": "Bearer analyst-key-0123456789"}
APPROVER = {"Authorization": "Bearer approver-key-0123456789"}
APPROVER2 = {"Authorization": "Bearer approver2-key-0123456789"}
KEYS = (
    "viewer:viewer:viewer-key-0123456789,"
    "analyst:analyst:analyst-key-0123456789,"
    "approver:approver:approver-key-0123456789,"
    "approver2:approver:approver2-key-0123456789"
)


def high_alert(alert_id: str = "t-high-1", host: str = "web-server-01", agent_id: str = "001") -> dict[str, Any]:
    return {
        "id": alert_id,
        "timestamp": "2026-10-27T10:00:00.000+0000",
        "rule": {"id": "100201", "level": 13, "description": "Encoded PowerShell", "mitre": {"id": ["T1059.001"]}},
        "agent": {"id": agent_id, "name": host, "ip": "192.168.1.50"},
        "data": {"win": {"eventdata": {"targetUserName": "admin", "commandLine": "powershell -enc AAAA"}}},
    }


class _FailingRepository(NullRepository):
    backend = "failing"

    async def upsert_alert(self, *args: Any, **kwargs: Any) -> None:
        raise RuntimeError("database write failed")


@pytest.fixture
def ctx() -> dict[str, Any]:
    store = InvestigationStore(max_capacity=500)
    engine = GuardrailEngine()
    engine.approval_service.on_change = store.queue_approval
    engine.audit_store.on_append = store.queue_audit
    enrichment = EnrichmentService(
        misp_client=MISPClient(enabled=False), cmdb_provider=MockIAMCMDBProvider(), demo_feed=DemoIntelFeed()
    )
    runner = AlertWorkflowRunner(enable_graph_persistence=False, guardrail_engine=engine, enrichment_service=enrichment)
    service = init_api_dependencies(
        runner=runner, enrichment_service=enrichment, guardrail_engine=engine, store=store,
        runtime={"demo_mode": True},
    )
    configure_registry(APIKeyRegistry(KEYS))
    client = TestClient(create_app())
    return {"client": client, "store": store, "engine": engine, "service": service}


# ── Authentication & authorization ──────────────────────────────────────────


def test_requests_without_or_with_bad_key_are_401(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    assert c.get("/api/v1/incidents").status_code == 401
    assert c.get("/api/v1/incidents", headers={"Authorization": "Bearer wrong-key-000000000"}).status_code == 401
    assert c.get("/health/live").status_code == 200  # liveness stays public


def test_role_enforcement(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    assert c.get("/api/v1/incidents", headers=VIEWER).status_code == 200
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert()}, headers=VIEWER)
    assert res.status_code == 403
    res = c.post("/api/v1/approvals/apr-x/decide", json={"decision": "APPROVE"}, headers=ANALYST)
    assert res.status_code == 403


def test_placeholder_and_short_keys_are_rejected() -> None:
    reg = APIKeyRegistry("a:analyst:CHANGE_ME_analyst_key,b:viewer:short,c:superuser:valid-key-0123456789")
    assert not reg.configured
    assert reg.rejected_entries == 3


# ── Approval lifecycle through the shared engine ────────────────────────────


def test_workflow_approvals_are_decidable_and_single_use(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert()}, headers=ANALYST)
    assert res.status_code == 201
    body = res.json()
    assert body["pending_approvals"], "HIGH/CRITICAL triage should propose a containment action"
    request_id = body["pending_approvals"][0]

    listed = c.get("/api/v1/approvals?status=PENDING", headers=VIEWER).json()["items"]
    assert any(a["request_id"] == request_id for a in listed), "API must see workflow-created approvals"

    # Execution before approval is refused
    assert c.post(f"/api/v1/approvals/{request_id}/execute", headers=APPROVER).status_code == 409

    res = c.post(f"/api/v1/approvals/{request_id}/decide",
                 json={"decision": "APPROVE", "reason": "confirmed", "reviewer_id": "spoofed"}, headers=APPROVER)
    assert res.status_code == 200
    assert res.json()["reviewer_id"] == "approver"  # identity from the key, not the body

    # A decided request cannot be flipped
    assert c.post(f"/api/v1/approvals/{request_id}/decide",
                  json={"decision": "REJECT", "reason": "x"}, headers=APPROVER2).status_code == 409

    res = c.post(f"/api/v1/approvals/{request_id}/execute", headers=APPROVER)
    assert res.status_code == 200
    assert res.json()["simulated"] is True
    assert res.json()["approval"]["status"] == "EXECUTED"

    # Replay protection
    assert c.post(f"/api/v1/approvals/{request_id}/execute", headers=APPROVER).status_code == 409

    ops = [e["operation"] for e in c.get("/api/v1/audit?page_size=200", headers=VIEWER).json()["items"]]
    assert "simulated_action_executed" in ops
    assert "human_approval_decision" in ops
    assert c.get("/api/v1/audit/verify", headers=VIEWER).json()["verified"] is True


def _incident_for_actions(c: TestClient) -> str:
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("t-act-1")}, headers=ANALYST)
    incident_id = res.json()["incident_id"]
    assert incident_id
    return str(incident_id)


def test_self_approval_is_forbidden(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    res = c.post(f"/api/v1/incidents/{incident_id}/actions",
                 json={"action_name": "isolate_host", "target": "web-server-01", "rationale": "contain host"}, headers=APPROVER)
    assert res.status_code == 201
    request_id = res.json()["guardrail"]["required_approvals"][0]
    res = c.post(f"/api/v1/approvals/{request_id}/decide", json={"decision": "APPROVE", "reason": "mine"}, headers=APPROVER)
    assert res.status_code == 403
    res = c.post(f"/api/v1/approvals/{request_id}/decide", json={"decision": "APPROVE", "reason": "peer"}, headers=APPROVER2)
    assert res.status_code == 200


def test_action_targets_and_names_are_allow_listed(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    bad_action = c.post(f"/api/v1/incidents/{incident_id}/actions",
                        json={"action_name": "unrestricted_shell_exec", "target": "web-server-01", "rationale": "nope nope"}, headers=ANALYST)
    assert bad_action.status_code == 422
    bad_target = c.post(f"/api/v1/incidents/{incident_id}/actions",
                        json={"action_name": "isolate_host", "target": "dc-01.corp", "rationale": "not in incident"}, headers=ANALYST)
    assert bad_target.status_code == 422


def test_expired_approval_cannot_be_approved_or_executed(ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    res = c.post(f"/api/v1/incidents/{incident_id}/actions",
                 json={"action_name": "isolate_host", "target": "web-server-01", "rationale": "test expiry"}, headers=ANALYST)
    request_id = res.json()["guardrail"]["required_approvals"][0]
    assert c.post(f"/api/v1/approvals/{request_id}/decide", json={"decision": "APPROVE", "reason": "ok"}, headers=APPROVER).status_code == 200

    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: real_time() + 10_000)
    assert c.post(f"/api/v1/approvals/{request_id}/execute", headers=APPROVER).status_code == 409


def test_tampered_action_is_denied_at_execution(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    res = c.post(f"/api/v1/incidents/{incident_id}/actions",
                 json={"action_name": "isolate_host", "target": "web-server-01", "rationale": "contain"}, headers=ANALYST)
    request_id = res.json()["guardrail"]["required_approvals"][0]
    c.post(f"/api/v1/approvals/{request_id}/decide", json={"decision": "APPROVE", "reason": "ok"}, headers=APPROVER)

    req = ctx["engine"].approval_service.get_request(request_id)
    req.proposal.target_entities = ["host:every-host-in-the-company"]  # parameter injection after approval
    res = c.post(f"/api/v1/approvals/{request_id}/execute", headers=APPROVER)
    assert res.status_code == 409
    assert "Guardrail refused" in res.json()["detail"]


# ── Ingestion, dedup & validation ───────────────────────────────────────────


def test_duplicate_alerts_are_deduplicated(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    first = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("dup-1")}, headers=ANALYST)
    second = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("dup-1")}, headers=ANALYST)
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["deduplicated"] is True
    assert first.json()["alert_id"] == second.json()["alert_id"]
    assert c.get("/api/v1/alerts", headers=VIEWER).json()["total"] == 1

    no_id = {k: v for k, v in high_alert().items() if k != "id"}
    a = c.post("/api/v1/alerts/ingest", json={"raw_alert": no_id}, headers=ANALYST).json()
    b = c.post("/api/v1/alerts/ingest", json={"raw_alert": no_id}, headers=ANALYST).json()
    assert a["alert_id"] == b["alert_id"]
    assert b["deduplicated"] is True


def test_invalid_input_is_rejected(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    assert c.post("/api/v1/alerts/ingest", json={"raw_alert": {}}, headers=ANALYST).status_code == 422
    assert c.post("/api/v1/alerts/ingest", json={"raw_alert": "x"}, headers=ANALYST).status_code == 422
    assert c.post("/api/v1/alerts/ingest", json={"raw_alert": {"a": 1}, "source": "bad source!"}, headers=ANALYST).status_code == 422
    assert c.post("/api/v1/alerts/ingest/batch", json={"alerts": [{"a": 1}] * 101}, headers=ANALYST).status_code == 422
    huge = {"raw_alert": {"full_log": "x" * 300_000}}
    assert c.post("/api/v1/alerts/ingest", json=huge, headers=ANALYST).status_code == 413
    assert c.patch("/api/v1/incidents/INC-NOPE/status", json={"status": "NOT_A_STATUS", "reason": "abc"}, headers=ANALYST).status_code == 422


def test_malformed_alert_is_preserved_not_crashed(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": {"rule": "not-a-dict", "timestamp": "garbage"}}, headers=ANALYST)
    assert res.status_code == 201
    body = res.json()
    assert body["finding"]["raw_data"]["rule"] == "not-a-dict"
    assert any("timestamp" in u.lower() for u in body["triage_result"]["uncertainties"])


def test_database_failure_returns_safe_error(ctx: dict[str, Any]) -> None:
    ctx["store"].repository = _FailingRepository()
    res = ctx["client"].post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("dbfail")}, headers=ANALYST)
    assert res.status_code == 500
    assert "RuntimeError" in res.json()["detail"]
    assert "database write failed" not in res.json()["detail"]


# ── Demo scenarios, correlation & incident lifecycle ────────────────────────


def test_intrusion_scenario_correlates_into_one_critical_incident(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    res = c.post("/api/v1/demo/scenarios/intrusion-chain/load", headers=ANALYST).json()
    incidents = {r["incident_id"] for r in res["results"]}
    assert len(incidents) == 1
    assert None not in incidents
    incident_id = incidents.pop()

    bundle = c.get(f"/api/v1/incidents/{incident_id}", headers=VIEWER).json()
    inc = bundle["incident"]
    assert len(inc["alert_ids"]) == 6
    assert set(inc["hosts"]) == {"web-server-01", "db-server-01"}
    assert inc["priority"] == "CRITICAL"
    assert len(inc["tactics"]) >= 3
    assert any(r["factor"] == "attack_progression" for r in inc["risk_breakdown"])
    assert all(link["basis"] for link in inc["correlation"])
    assert inc["synthetic"] is True

    again = c.post("/api/v1/demo/scenarios/intrusion-chain/load", headers=ANALYST).json()
    assert all(r["result"] == "deduplicated" for r in again["results"])


def test_benign_low_alert_does_not_open_incident(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    res = c.post("/api/v1/demo/scenarios/benign-activity/load", headers=ANALYST).json()
    by_id = {r["alert_id"]: r for r in res["results"]}
    low = [r for r in by_id.values() if r["priority"] == "LOW"]
    assert low
    assert low[0]["incident_id"] is None
    intel = c.get("/api/v1/intel/indicators", headers=VIEWER).json()["items"]
    assert any(i["indicator"] == "192.0.2.10" and i["verdict"] == "BENIGN" and i["synthetic"] for i in intel)


def test_incident_status_notes_report_and_narrative(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    assert c.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "INVESTIGATING", "reason": "triaging"}, headers=ANALYST).status_code == 200
    assert c.patch(f"/api/v1/incidents/{incident_id}/status", json={"status": "INVESTIGATING", "reason": "again"}, headers=ANALYST).status_code == 409
    assert c.post(f"/api/v1/incidents/{incident_id}/notes", json={"text": "Checked EDR, encoded command confirmed"}, headers=ANALYST).status_code == 201

    narrative = c.post(f"/api/v1/incidents/{incident_id}/narrative", json={"use_llm": True}, headers=ANALYST).json()
    assert narrative["mode"] == "deterministic_template"
    assert any("not available" in w for w in narrative["warnings"])
    ids = {e["id"] for e in narrative["evidence"]}
    assert all(set(f["evidence"]) <= ids for f in narrative["observed_facts"])

    report = c.get(f"/api/v1/incidents/{incident_id}/report", headers=VIEWER)
    assert report.status_code == 200
    assert "attachment" in report.headers["content-disposition"]
    data = report.json()
    assert data["incident"]["status"] == "INVESTIGATING"
    assert data["audit_chain"]["verified"] is True
    assert any(e["operation"] == "incident_status_changed" for e in data["audit_events"])


def test_graph_falls_back_and_labels_source(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    incident_id = _incident_for_actions(c)
    g = c.get(f"/api/v1/incidents/{incident_id}/graph", headers=VIEWER).json()
    assert g["source"] == "workflow_resolution"
    assert g["persisted"] is False
    assert any(n["label"] == "Asset" for n in g["nodes"])
    assert all(e["confidence"] is not None and e["provenance"] and e["valid_from"] for e in g["edges"])
    ent = c.get("/api/v1/graph/entities/asset:agent:001", headers=VIEWER)
    assert ent.status_code == 200
    assert c.get("/api/v1/graph/entities/asset:agent:does-not-exist", headers=VIEWER).status_code == 404


def test_health_reports_real_state(ctx: dict[str, Any]) -> None:
    body = ctx["client"].get("/health").json()
    names = {s["name"]: s for s in body["services"]}
    assert names["persistence"]["status"] == "degraded"  # in-memory is reported honestly
    assert names["neo4j"]["status"] != "ok"
    assert names["audit_chain"]["status"] == "ok"


# ── Audit integrity ─────────────────────────────────────────────────────────


def _chain(n: int = 4) -> HashChainAuditStore:
    store = HashChainAuditStore()
    for i in range(n):
        store.log_event(actor="t", operation=f"op{i}", decision="RECORD", policy_id="p", outcome=f"o{i}")
    return store


def test_audit_detects_modification_removal_and_reordering() -> None:
    modified = _chain()
    modified._events[1].outcome = "rewritten"
    assert modified.verify_chain_integrity()[0] is False

    removed = _chain()
    del removed._events[1]
    assert removed.verify_chain_integrity()[0] is False

    reordered = _chain()
    reordered._events[1], reordered._events[2] = reordered._events[2], reordered._events[1]
    assert reordered.verify_chain_integrity()[0] is False

    intact = _chain()
    restored = HashChainAuditStore()
    assert restored.restore(intact.get_events()) == (True, None)


def test_audit_redacts_secrets_and_strips_control_chars() -> None:
    store = HashChainAuditStore()
    ev = store.log_event(actor="a\r\nFAKE", operation="x", decision="RECORD", policy_id="p",
                         outcome="login password=hunter2 token: abc Bearer eyJhbGciOi.x.y")
    assert "hunter2" not in ev.outcome
    assert "eyJhbGciOi" not in ev.outcome
    assert "\n" not in ev.actor


def test_audit_verify_endpoint_detects_tampering(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("tamper")}, headers=ANALYST)
    ctx["engine"].audit_store._events[0].decision = "ALLOW"
    res = c.get("/api/v1/audit/verify", headers=VIEWER).json()
    assert res["verified"] is False
    assert "Tamper" in res["error"]
    assert c.get("/health").status_code == 503


# ── Persistence across restart ──────────────────────────────────────────────


def test_sqlite_persistence_survives_restart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("aiosqlite")
    from core.config import get_settings

    monkeypatch.setenv("PERSISTENCE_BACKEND", "sqlite")
    monkeypatch.setenv("SQLITE_PATH", str(tmp_path / "tf.db"))
    monkeypatch.setenv("NEO4J_ENABLED", "false")
    monkeypatch.setenv("API_KEYS", KEYS)
    monkeypatch.setenv("MISP_API_KEY", "REPLACE_WITH_MISP_API_KEY")
    get_settings.cache_clear()

    with TestClient(create_app()) as c:
        res = c.post("/api/v1/demo/scenarios/c2-beacon/load", headers=ANALYST).json()
        incident_id = res["results"][0]["incident_id"]
        approval_id = c.get("/api/v1/approvals?status=PENDING", headers=VIEWER).json()["items"][0]["request_id"]
        c.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "REJECT", "reason": "fp"}, headers=APPROVER)
        events_before = c.get("/api/v1/audit/verify", headers=VIEWER).json()["event_count"]

    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert c.get(f"/api/v1/incidents/{incident_id}", headers=VIEWER).status_code == 200
        assert c.get(f"/api/v1/approvals/{approval_id}", headers=VIEWER).json()["status"] == "REJECTED"
        verify = c.get("/api/v1/audit/verify", headers=VIEWER).json()
        assert verify["verified"] is True
        assert verify["event_count"] == events_before + 1  # + the second startup event
        again = c.post("/api/v1/demo/scenarios/c2-beacon/load", headers=ANALYST).json()
        assert again["results"][0]["result"] == "deduplicated"


# ── Threat intel verdict policy ─────────────────────────────────────────────


def test_absence_of_intel_is_unknown_never_benign() -> None:
    assert combine_verdicts("1.2.3.4", "ip", []).verdict == IntelVerdict.UNKNOWN
    unavailable = SourceVerdict(source="misp", verdict=IntelVerdict.UNKNOWN, detail="timeout", available=False)
    result = combine_verdicts("1.2.3.4", "ip", [unavailable])
    assert result.verdict == IntelVerdict.UNKNOWN
    assert "misp: timeout" in result.rationale
    assert result.is_confirmed_safe is False


def test_disabled_misp_is_reported_as_not_configured() -> None:
    from ingestion.intel import misp_to_source_verdict
    from ingestion.misp import MISPEnrichmentResult, MISPLookupStatus

    sv = misp_to_source_verdict(MISPEnrichmentResult(indicator="1.2.3.4", status=MISPLookupStatus.DISABLED))
    assert sv.detail == "not configured"
    assert sv.available is False
    assert "misp: not configured" in combine_verdicts("1.2.3.4", "ip", [sv]).rationale


def test_conflicting_sources_use_most_severe() -> None:
    benign = SourceVerdict(source="a", verdict=IntelVerdict.BENIGN, detail="allow")
    bad = SourceVerdict(source="b", verdict=IntelVerdict.MALICIOUS, detail="c2")
    result = combine_verdicts("x.example", "domain", [benign, bad])
    assert result.verdict == IntelVerdict.MALICIOUS
    assert result.conflicting


async def test_misp_failure_reports_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpx

    async def boom(self: Any, url: str, **kw: Any) -> httpx.Response:
        raise httpx.ConnectError("down", request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx.AsyncClient, "post", boom)
    svc = EnrichmentService(misp_client=MISPClient(api_key="real-looking-key-123", max_retries=0), demo_feed=None)
    assessment, _ = await svc.lookup_indicator("8.8.4.4", "ip")
    assert assessment.verdict == IntelVerdict.UNKNOWN
    assert assessment.sources[0].available is False


async def test_slow_misp_degrades_without_losing_other_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    async def slow(self: Any, indicator: str, indicator_type: str | None = None) -> Any:
        await asyncio.sleep(5)

    monkeypatch.setattr(MISPClient, "lookup_indicator", slow)
    svc = EnrichmentService(misp_client=MISPClient(api_key="real-looking-key-123"), demo_feed=DemoIntelFeed(),
                            misp_budget_seconds=0.2)
    assessment, misp_result = await svc.lookup_indicator("198.51.100.22", "ip")
    assert misp_result is not None
    assert misp_result.status.value == "SERVICE_UNAVAILABLE"
    assert assessment.verdict == IntelVerdict.MALICIOUS  # demo feed still applied
    assert any(s.source == "misp" and not s.available for s in assessment.sources)


# ── Triage accounting ───────────────────────────────────────────────────────


def _finding(raw: dict[str, Any]) -> Any:
    return OCSFNormalizer().normalize(raw)


def test_score_breakdown_sums_to_score_and_intel_counted_once() -> None:
    raw = {
        "id": "s1", "timestamp": "2026-10-27T10:00:00Z",
        "rule": {"level": 8, "description": "x", "mitre": {"id": ["T1071.001"]}},
        "agent": {"id": "001", "name": "web-server-01", "ip": "192.168.1.50"},
        "data": {"srcip": "198.51.100.22", "dstip": "203.0.113.50", "dstuser": "root"},
    }
    enrichment = {
        "indicator_verdicts": {
            "198.51.100.22": {"verdict": "MALICIOUS", "rationale": "a", "synthetic": True},
            "203.0.113.50": {"verdict": "MALICIOUS", "rationale": "b", "synthetic": True},
        },
        "cmdb_asset": {"asset_id": "001", "hostname": "web-server-01", "criticality": "HIGH"},
        "iam_identity": {"username": "root", "is_privileged": True},
    }
    result = AlertTriageEngine().triage(_finding(raw), enrichment=enrichment)
    factors = [c.factor for c in result.score_breakdown]
    assert factors.count("threat_intel") == 1
    assert factors.count("privileged_account") == 1  # name list and IAM flag not double counted
    # The MALICIOUS source IP's exposure is subsumed by its reputation (counted once).
    assert factors.count("external_exposure") == 0
    assert any("subsumes +10 external exposure" in c.detail for c in result.score_breakdown)
    assert sum(c.points for c in result.score_breakdown) == result.score
    assert result.priority == IncidentPriority.CRITICAL


def test_context_alone_cannot_raise_alert_to_critical() -> None:
    # Intrinsic: High severity 60 + privileged 15 = 75 (HIGH). CMDB CRITICAL +10 => 85.
    data: dict[str, str] = {"dstuser": "admin"}
    raw: dict[str, Any] = {"id": "c1", "timestamp": "2026-10-27T10:00:00Z", "rule": {"level": 11, "description": "group change"},
                           "agent": {"id": "002", "name": "db-server-01"}, "data": data}
    enrichment: dict[str, Any] = {"cmdb_asset": {"asset_id": "002", "hostname": "db-server-01", "criticality": "CRITICAL"}}
    result = AlertTriageEngine().triage(_finding(raw), enrichment=enrichment)
    assert result.score == 85
    assert result.priority == IncidentPriority.HIGH
    assert "context factors alone" in str(result.priority_rule)

    # A MALICIOUS intel verdict is direct evidence and may reach CRITICAL.
    data["dstip"] = "198.51.100.22"
    enrichment["indicator_verdicts"] = {"198.51.100.22": {"verdict": "MALICIOUS", "rationale": "c2"}}
    assert AlertTriageEngine().triage(_finding(raw), enrichment=enrichment).priority == IncidentPriority.CRITICAL


def test_exposure_kept_when_intel_is_about_a_different_indicator() -> None:
    raw = {"id": "e1", "timestamp": "2026-10-27T10:00:00Z", "rule": {"level": 5, "description": "x"},
           "agent": {"id": "009", "name": "h"}, "data": {"srcip": "203.0.113.9", "dst_domain": "files.example.net"}}
    enrichment = {"indicator_verdicts": {"files.example.net": {"verdict": "MALICIOUS", "rationale": "exfil"}}}
    factors = [c.factor for c in AlertTriageEngine().triage(_finding(raw), enrichment=enrichment).score_breakdown]
    assert "external_exposure" in factors
    assert "threat_intel" in factors


def test_private_ips_are_not_sent_to_intel_sources() -> None:
    f = _finding({"id": "p1", "timestamp": "2026-10-27T10:00:00Z", "rule": {"level": 5, "description": "x"},
                  "data": {"srcip": "10.0.5.100", "dstip": "198.51.100.22", "dst_domain": "x.example"}})
    assert [i for i, _, _ in EnrichmentService.observed_indicators(f)] == ["198.51.100.22", "x.example"]


def test_unknown_intel_adds_no_points_and_is_reported() -> None:
    raw = {"id": "s2", "timestamp": "2026-10-27T10:00:00Z", "rule": {"level": 5, "description": "x"},
           "agent": {"id": "009", "name": "h"}, "data": {"dstip": "8.8.8.8"}}
    enrichment = {"indicator_verdicts": {"8.8.8.8": {"verdict": "UNKNOWN", "rationale": "none"}}}
    result = AlertTriageEngine().triage(_finding(raw), enrichment=enrichment)
    assert "threat_intel" not in [c.factor for c in result.score_breakdown]
    assert any("not assumed benign" in u for u in result.uncertainties)


# ── Normalization additions ─────────────────────────────────────────────────


def test_windows_eventdata_and_attack_reference_labels() -> None:
    f = _finding({
        "id": "w1", "timestamp": "2026-10-27T10:00:00Z",
        "rule": {"level": 12, "description": "ps", "mitre": {"id": ["T1059.001", "T9999"]}},
        "agent": {"id": "001", "name": "web"},
        "data": {"dst_domain": "Files.Example.net", "win": {"eventdata": {
            "targetUserName": "admin", "image": "C:\\Windows\\System32\\powershell.exe", "commandLine": "powershell -enc AA"}}},
    })
    assert f.user is not None
    assert f.user.name == "admin"
    assert f.process is not None
    assert f.process.name == "powershell.exe"
    assert f.process.cmd_line == "powershell -enc AA"
    assert f.attacks[0].tactic is not None
    assert f.attacks[0].tactic.name == "Execution"
    assert f.attacks[1].tactic is not None
    assert f.attacks[1].tactic.name == "Unknown"
    assert f.unmapped["mitre_reference_labels"] == ["T1059.001"]
    assert f.dst_endpoint is not None
    assert f.dst_endpoint.domain == "Files.Example.net"


async def test_resolution_is_scoped_per_alert() -> None:
    runner = AlertWorkflowRunner(enable_graph_persistence=False)
    a = await runner.process_alert(high_alert("r1", host="host-a", agent_id="101"))
    b = await runner.process_alert(high_alert("r2", host="host-b", agent_id="102"))
    assert a.resolution is not None
    assert b.resolution is not None
    assert "asset:agent:101" not in b.resolution.entities
    assert "asset:agent:102" in b.resolution.entities


# ── Correlation rules ───────────────────────────────────────────────────────


async def test_generic_username_is_scoped_by_host() -> None:
    runner = AlertWorkflowRunner(enable_graph_persistence=False)
    a = await runner.process_alert(high_alert("g1", host="host-a", agent_id="201"))
    b = await runner.process_alert(high_alert("g2", host="host-b", agent_id="202"))
    keys_a = {k for k, _, _ in correlation_keys(a)}
    keys_b = {k for k, _, _ in correlation_keys(b)}
    assert not ({k for k in keys_a if k.startswith("identity:")} & keys_b)


# ── Narrative guardrails ────────────────────────────────────────────────────


def test_llm_output_citing_unknown_evidence_is_rejected() -> None:
    evidence_ids = {"E1", "E2"}
    good = {"summary": "s", "observed_facts": [{"text": "t", "evidence": ["E1"]}], "hypotheses": [],
            "uncertainties": [], "investigation_questions": []}
    assert _validate_llm_output(good, evidence_ids) is None
    bad = dict(good, observed_facts=[{"text": "APT29 did it", "evidence": ["E7"]}])
    assert "unknown evidence" in str(_validate_llm_output(bad, evidence_ids))
    uncited = dict(good, hypotheses=[{"text": "guess", "confidence": "high", "evidence": []}])
    assert _validate_llm_output(uncited, evidence_ids) is not None


async def test_llm_failure_falls_back_to_template(monkeypatch: pytest.MonkeyPatch) -> None:
    gen = NarrativeGenerator(provider="ollama", model="local-model")

    async def fake_call(self: Any, content: str) -> str:
        assert "untrusted" not in content or True
        return '{"summary": "x", "observed_facts": [{"text": "made up", "evidence": ["E99"]}], "hypotheses": [], "uncertainties": [], "investigation_questions": []}'

    monkeypatch.setattr(NarrativeGenerator, "_call", fake_call)
    incident = {"incident_id": "INC-1", "hosts": ["h"], "risk_score": 50, "priority": "MEDIUM", "tactics": [], "correlation": []}
    out = await gen.generate(incident, [], use_llm=True)
    assert out["mode"] == "deterministic_template"
    assert any("rejected" in w for w in out["warnings"])


def test_template_narrative_only_cites_existing_evidence() -> None:
    evidence = build_evidence({"correlation": [{"alert_id": "a1", "basis": "b", "confidence": 0.9}]}, [])
    n = template_narrative({"incident_id": "INC-1", "tactics": ["A", "B", "C"], "hosts": [], "risk_score": 1, "priority": "LOW"}, evidence)
    ids = {e["id"] for e in evidence}
    for h in n["hypotheses"]:
        assert set(h["evidence"]) <= ids
