"""
tests/unit/test_security_hardening.py — Release-readiness security checks.

Covers: a role matrix over EVERY registered route, credential handling, brute-
force lockout, rate limiting, streaming body limits, CORS, concurrent approval
decisions and executions, ordered write retry after database failure, audit
attribution, fail-closed guardrail errors, non-leaking 500s, and health under
dependency outages.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.routing import APIRoute
from starlette.testclient import TestClient

from api.app import create_app
from api.auth import APIKeyRegistry, configure_registry
from api.persistence import NullRepository
from api.routes import init_api_dependencies
from api.store import InvestigationStore
from core.health import ServiceHealth, ServiceStatus
from guardrails.approval import ApprovalService, ApprovalStatus
from guardrails.engine import GuardrailEngine
from guardrails.models import ActionCategory, ActionProposal, DecisionType
from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.intel import DemoIntelFeed
from ingestion.misp import MISPClient
from orchestrator.workflow import AlertWorkflowRunner

KEYS = {
    "viewer": "sec-viewer-key-0123456789",
    "analyst": "sec-analyst-key-0123456789",
    "approver": "sec-approver-key-0123456789",
    "approver2": "sec-approver2-key-0123456789",
}
ROLE_OF = {"viewer": "viewer", "analyst": "analyst", "approver": "approver", "approver2": "approver"}
H = {name: {"Authorization": f"Bearer {key}"} for name, key in KEYS.items()}

# Minimum role per route. Every registered route MUST appear here; adding a
# route without declaring its role fails test_every_route_declares_a_role.
PUBLIC = "public"
ROUTE_ROLES: dict[tuple[str, str], str] = {
    ("GET", "/health/live"): PUBLIC,
    ("GET", "/health/ready"): PUBLIC,
    ("GET", "/health"): PUBLIC,
    ("GET", "/api/v1/health"): PUBLIC,
    ("GET", "/api/v1/auth/me"): "viewer",
    ("POST", "/api/v1/alerts/ingest"): "analyst",
    ("POST", "/api/v1/alerts/ingest/batch"): "analyst",
    ("GET", "/api/v1/alerts"): "viewer",
    ("GET", "/api/v1/investigations"): "viewer",
    ("GET", "/api/v1/alerts/{alert_id}"): "viewer",
    ("GET", "/api/v1/investigations/{alert_id}"): "viewer",
    ("POST", "/api/v1/investigations/{alert_id}/enrich"): "analyst",
    ("GET", "/api/v1/demo/scenarios"): "viewer",
    ("POST", "/api/v1/demo/scenarios/{scenario_id}/load"): "analyst",
    ("GET", "/api/v1/incidents"): "viewer",
    ("GET", "/api/v1/incidents/{incident_id}"): "viewer",
    ("PATCH", "/api/v1/incidents/{incident_id}/status"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/notes"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/actions"): "analyst",
    ("POST", "/api/v1/incidents/{incident_id}/narrative"): "analyst",
    ("GET", "/api/v1/incidents/{incident_id}/report"): "viewer",
    ("GET", "/api/v1/incidents/{incident_id}/graph"): "viewer",
    ("GET", "/api/v1/graph/entities/{entity_id}"): "viewer",
    ("GET", "/api/v1/intel/indicators"): "viewer",
    ("GET", "/api/v1/intel/lookup"): "analyst",
    ("GET", "/api/v1/intel/demo-feed"): "viewer",
    ("GET", "/api/v1/stats"): "viewer",
    ("GET", "/api/v1/dashboard"): "viewer",
    ("GET", "/api/v1/integrations/status"): "viewer",
    ("GET", "/api/v1/approvals"): "viewer",
    ("GET", "/api/v1/approvals/{request_id}"): "viewer",
    ("POST", "/api/v1/approvals/{request_id}/decide"): "approver",
    ("POST", "/api/v1/approvals/{request_id}/execute"): "approver",
    ("GET", "/api/v1/audit"): "viewer",
    ("GET", "/api/v1/audit/verify"): "viewer",
    ("GET", "/api/v1/actions/catalog"): "viewer",
}
RANK = {PUBLIC: 0, "viewer": 1, "analyst": 2, "approver": 3}


def _keys_spec() -> str:
    return ",".join(f"{n}:{ROLE_OF[n]}:{k}" for n, k in KEYS.items())


def high_alert(alert_id: str = "sec-1") -> dict[str, Any]:
    return {
        "id": alert_id,
        "timestamp": "2026-10-27T10:00:00.000+0000",
        "rule": {"id": "1", "level": 13, "description": "Encoded PowerShell", "mitre": {"id": ["T1059.001"]}},
        "agent": {"id": "001", "name": "web-server-01", "ip": "192.168.1.50"},
        "data": {"win": {"eventdata": {"targetUserName": "admin", "commandLine": "powershell -enc AA"}}},
    }


class RecordingRepository(NullRepository):
    """Persists audit rows in memory; can be told to fail the next N writes."""

    backend = "recording"

    def __init__(self) -> None:
        self.audit: list[dict[str, Any]] = []
        self.fail_next = 0

    async def check_health(self) -> ServiceHealth:
        return ServiceHealth(name="persistence", status=ServiceStatus.OK, detail="recording")

    async def _maybe_fail(self) -> None:
        if self.fail_next > 0:
            self.fail_next -= 1
            raise ConnectionError("simulated database outage")

    async def append_audit(self, event: dict[str, Any]) -> None:
        await self._maybe_fail()
        self.audit.append(event)

    async def upsert_alert(self, *a: Any, **k: Any) -> None:
        await self._maybe_fail()

    async def upsert_incident(self, *a: Any, **k: Any) -> None:
        await self._maybe_fail()

    async def upsert_approval(self, *a: Any, **k: Any) -> None:
        await self._maybe_fail()


def build(monkeypatch: pytest.MonkeyPatch | None = None, **env: str) -> dict[str, Any]:
    if monkeypatch is not None:
        from core.config import get_settings

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        get_settings.cache_clear()
    repo = RecordingRepository()
    store = InvestigationStore(repository=repo)
    engine = GuardrailEngine()
    engine.approval_service.on_change = store.queue_approval
    engine.audit_store.on_append = store.queue_audit
    enrichment = EnrichmentService(misp_client=MISPClient(enabled=False), cmdb_provider=MockIAMCMDBProvider(),
                                   demo_feed=DemoIntelFeed())
    runner = AlertWorkflowRunner(enable_graph_persistence=False, guardrail_engine=engine, enrichment_service=enrichment)
    init_api_dependencies(runner=runner, enrichment_service=enrichment, guardrail_engine=engine, store=store,
                          runtime={"demo_mode": True})
    configure_registry(APIKeyRegistry(_keys_spec()))
    app = create_app()
    return {"app": app, "client": TestClient(app, raise_server_exceptions=False), "store": store,
            "engine": engine, "repo": repo}


@pytest.fixture
def ctx() -> dict[str, Any]:
    return build()


def _proposal_on_incident(c: TestClient, who: str = "analyst") -> tuple[str, str]:
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert()}, headers=H["analyst"])
    incident_id = res.json()["incident_id"]
    res = c.post(f"/api/v1/incidents/{incident_id}/actions",
                 json={"action_name": "isolate_host", "target": "web-server-01", "rationale": "contain host"}, headers=H[who])
    return incident_id, res.json()["guardrail"]["required_approvals"][0]


# ── Role matrix over every route ────────────────────────────────────────────


def _routes(app: Any) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for route in app.routes:
        if isinstance(route, APIRoute):
            path = route.path.replace("{entity_id:path}", "{entity_id}")
            out.extend((m, path) for m in route.methods)
    return out


def test_every_route_declares_a_role(ctx: dict[str, Any]) -> None:
    registered = set(_routes(ctx["app"]))
    assert registered == set(ROUTE_ROLES), (
        f"undeclared: {registered - set(ROUTE_ROLES)}; stale: {set(ROUTE_ROLES) - registered}"
    )


def test_role_matrix_enforced_server_side(monkeypatch: pytest.MonkeyPatch) -> None:
    # Lockout disabled here: this test deliberately sends many bad keys (lockout has its own test).
    c: TestClient = build(monkeypatch, AUTH_MAX_FAILURES="0")["client"]
    for (method, path), required in ROUTE_ROLES.items():
        url = path.format(alert_id="x", scenario_id="x", incident_id="x", entity_id="x", request_id="x")
        if path.endswith("/lookup"):
            url += "?indicator=1.2.3.4"
        anon = c.request(method, url, json={})
        if required == PUBLIC:
            assert anon.status_code not in (401, 403), (method, path)
            continue
        assert anon.status_code == 401, (method, path, anon.status_code)
        bad = c.request(method, url, json={}, headers={"Authorization": "Bearer not-a-real-key-000000"})
        assert bad.status_code == 401, (method, path)
        for who in ("viewer", "analyst", "approver"):
            res = c.request(method, url, json={}, headers=H[who])
            if RANK[ROLE_OF[who]] < RANK[required]:
                assert res.status_code == 403, (method, path, who, res.status_code)
            else:
                assert res.status_code not in (401, 403), (method, path, who, res.status_code)


def test_keys_are_never_echoed(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    me = c.get("/api/v1/auth/me", headers=H["analyst"])
    assert me.json() == {"name": "analyst", "role": "analyst"}
    for res in (me, c.get("/api/v1/integrations/status", headers=H["viewer"]),
                c.get("/api/v1/incidents", headers={"Authorization": "Bearer guess-guess-guess-0000"})):
        for key in KEYS.values():
            assert key not in res.text
        assert "guess-guess-guess" not in res.text


# ── Brute force, rate limit, body size, CORS ────────────────────────────────


def test_auth_failures_lock_out_client(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = build(monkeypatch, AUTH_MAX_FAILURES="3", AUTH_LOCKOUT_SECONDS="60")
    c: TestClient = ctx["client"]
    for _ in range(3):
        assert c.get("/api/v1/incidents", headers={"Authorization": "Bearer wrong-key-000000000"}).status_code == 401
    locked = c.get("/api/v1/incidents", headers=H["viewer"])  # even a valid key is refused while locked
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0
    assert c.get("/health/live").status_code == 200


def test_rate_limit_and_exempt_liveness(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = build(monkeypatch, RATE_LIMIT_PER_MINUTE="5")
    c: TestClient = ctx["client"]
    codes = [c.get("/api/v1/stats", headers=H["viewer"]).status_code for _ in range(7)]
    assert codes[:5] == [200] * 5
    assert codes[5:] == [429, 429]
    assert all(c.get("/health/live").status_code == 200 for _ in range(10))


def test_chunked_body_without_content_length_is_limited(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]

    def chunks() -> Iterator[bytes]:
        yield b'{"raw_alert": {"full_log": "'
        for _ in range(40):
            yield b"x" * 10_000
        yield b'"}}'

    res = c.post("/api/v1/alerts/ingest", content=chunks(),
                  headers={**H["analyst"], "Content-Type": "application/json"})
    assert res.status_code == 413


def test_cors_allows_only_configured_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = build(monkeypatch, CORS_ORIGINS="http://localhost:5173,*")
    c: TestClient = ctx["client"]
    pre = {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"}
    ok = c.options("/api/v1/stats", headers={"Origin": "http://localhost:5173", **pre})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = c.options("/api/v1/stats", headers={"Origin": "https://evil.example", **pre})
    assert evil.headers.get("access-control-allow-origin") is None
    assert "access-control-allow-credentials" not in ok.headers


# ── Approval races and state machine ────────────────────────────────────────


async def _concurrent(app: Any, calls: list[tuple[str, dict[str, Any], dict[str, str]]]) -> list[int]:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        results = await asyncio.gather(*(client.post(url, json=body, headers=hdr) for url, body, hdr in calls))
    return [r.status_code for r in results]


def test_concurrent_decisions_and_executions_resolve_once(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    _, request_id = _proposal_on_incident(c)
    decide = f"/api/v1/approvals/{request_id}/decide"
    codes = asyncio.run(_concurrent(ctx["app"], [
        (decide, {"decision": "APPROVE", "reason": "a"}, H["approver"]),
        (decide, {"decision": "REJECT", "reason": "b"}, H["approver2"]),
        (decide, {"decision": "APPROVE", "reason": "c"}, H["approver2"]),
    ]))
    assert sorted(codes) == [200, 409, 409]
    status = ctx["engine"].approval_service.get_request(request_id).status
    if status == ApprovalStatus.APPROVED:
        execute = f"/api/v1/approvals/{request_id}/execute"
        codes = asyncio.run(_concurrent(ctx["app"], [(execute, {}, H["approver"])] * 5))
        assert sorted(codes) == [200, 409, 409, 409, 409]
        executed = [e for e in ctx["engine"].audit_store.get_events() if e.operation == "simulated_action_executed"]
        assert len(executed) == 1


def test_approval_state_machine_is_one_way() -> None:
    svc = ApprovalService()
    proposal = ActionProposal(action_name="isolate_host", category=ActionCategory.CONTAINMENT,
                              target_entities=["host:a"], rationale="r")
    approved = svc.create_request(proposal)
    svc.approve(approved.request_id, "rev")
    with pytest.raises(ValueError, match="Cannot reject request .* status 'APPROVED'"):
        svc.reject(approved.request_id, "rev")
    svc.mark_executed(approved.request_id, "rev", "simulated")
    rid = approved.request_id
    ops: list[Callable[[], object]] = [
        lambda: svc.approve(rid, "rev"),
        lambda: svc.reject(rid, "rev"),
        lambda: svc.revoke(rid),
        lambda: svc.mark_executed(rid, "rev", "x"),
    ]
    for op in ops:
        with pytest.raises(ValueError, match="status 'EXECUTED'"):
            op()
    rejected = svc.create_request(proposal)
    svc.reject(rejected.request_id, "rev")
    with pytest.raises(ValueError, match="status 'REJECTED'"):
        svc.approve(rejected.request_id, "rev")
    expired = svc.create_request(proposal, timeout_seconds=30)
    expired.expires_at = time.time() - 1
    with pytest.raises(ValueError, match="Cannot approve expired request"):
        svc.approve(expired.request_id, "rev")
    refreshed = svc.get_request(expired.request_id)
    assert refreshed is not None
    assert refreshed.status == ApprovalStatus.EXPIRED


def test_execution_audit_names_the_executor(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    _, request_id = _proposal_on_incident(c)
    c.post(f"/api/v1/approvals/{request_id}/decide", json={"decision": "APPROVE", "reason": "ok"}, headers=H["approver"])
    assert c.post(f"/api/v1/approvals/{request_id}/execute", headers=H["approver"]).status_code == 200
    allow = [e for e in ctx["engine"].audit_store.get_events()
             if e.approval_id == request_id and e.decision == "ALLOW"]
    assert allow
    assert allow[-1].actor == "approver"
    assert allow[-1].metadata["proposed_by"] == "analyst"


def test_guardrail_errors_fail_closed(ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    engine: GuardrailEngine = ctx["engine"]
    proposal = ActionProposal(action_name="isolate_host", category=ActionCategory.CONTAINMENT,
                              target_entities=["host:a"], rationale="r")
    monkeypatch.setattr(engine.approval_service, "create_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = engine.evaluate(proposal)
    assert result.decision == DecisionType.ERROR
    assert not result.is_executable
    assert result.required_approvals == []


# ── Persistence ordering under failure ──────────────────────────────────────


def test_failed_writes_are_retried_in_order(ctx: dict[str, Any]) -> None:
    c: TestClient = ctx["client"]
    repo: RecordingRepository = ctx["repo"]
    repo.fail_next = 1
    res = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("outage-1")}, headers=H["analyst"])
    assert res.status_code == 500
    assert "simulated database outage" not in res.text
    assert ctx["store"].pending_writes > 0

    # Retrying the same alert is deduplicated AND drains the queue in order.
    retry = c.post("/api/v1/alerts/ingest", json={"raw_alert": high_alert("outage-1")}, headers=H["analyst"])
    assert retry.status_code == 200
    assert retry.json()["deduplicated"] is True
    assert ctx["store"].pending_writes == 0

    from guardrails.audit import AuditEvent, HashChainAuditStore

    persisted = HashChainAuditStore()
    ok, err = persisted.restore([AuditEvent.model_validate(e) for e in repo.audit])
    assert ok, err
    assert [e["event_id"] for e in repo.audit] == [e.event_id for e in ctx["engine"].audit_store.get_events()]


# ── Error hygiene and health ────────────────────────────────────────────────


def test_unexpected_errors_do_not_leak_details(ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ctx["store"], "dashboard", lambda **k: (_ for _ in ()).throw(RuntimeError("db password=hunter2 at /srv")))
    res = ctx["client"].get("/api/v1/dashboard", headers=H["viewer"])
    assert res.status_code == 500
    assert res.json() == {"detail": "Internal server error"}
    assert "hunter2" not in res.text
    assert "Traceback" not in res.text


def test_health_reports_unavailable_dependencies(ctx: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    async def down() -> ServiceHealth:
        return ServiceHealth(name="persistence", status=ServiceStatus.DOWN, detail="postgres unreachable: OSError")

    monkeypatch.setattr(ctx["repo"], "check_health", down)
    res = ctx["client"].get("/health")
    assert res.status_code == 503
    assert {s["name"]: s["status"] for s in res.json()["services"]}["persistence"] == "down"


def test_incident_grouping_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    groupings = []
    for _ in range(2):
        ctx = build()
        c: TestClient = ctx["client"]
        for sid in ("benign-activity", "intrusion-chain", "c2-beacon", "intrusion-chain"):
            c.post(f"/api/v1/demo/scenarios/{sid}/load", headers=H["analyst"])
        incidents = c.get("/api/v1/incidents?page_size=100", headers=H["viewer"]).json()["items"]
        groupings.append(sorted((i["alert_count"], tuple(sorted(i["hosts"])), i["priority"]) for i in incidents))
    assert groupings[0] == groupings[1]
    assert (6, ("db-server-01", "web-server-01"), "CRITICAL") in groupings[0]
