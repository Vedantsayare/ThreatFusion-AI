# API reference

Base URL: `http://127.0.0.1:8000`. Interactive OpenAPI docs: `/docs` (generated
from the running code, so always current). All endpoints except the health
endpoints require `Authorization: Bearer <api key>`.

| Role | Can |
|---|---|
| `viewer` | all `GET` endpoints |
| `analyst` | + ingest, demo scenarios, intel lookup, enrichment, incident status/notes, propose actions, narrative |
| `approver` | + approve/reject/execute response actions |

Errors are JSON: `{"detail": "<message>"}`. Status codes used: `200`, `201`,
`401` (missing/invalid key), `403` (role or separation-of-duties), `404`,
`409` (state conflict: already decided, expired, replay, guardrail refusal),
`413` (body > `MAX_REQUEST_BYTES`), `422` (validation), `500` (generic message
only), `503` (readiness failure).

```bash
export TF=http://127.0.0.1:8000
export ANALYST="Authorization: Bearer $(grep ^API_KEYS .env | tr ',' '\n' | grep ':analyst:' | cut -d: -f3)"
export APPROVER="Authorization: Bearer $(grep ^API_KEYS .env | tr ',' '\n' | grep ':approver:' | cut -d: -f3)"
```

## Health

| Method & path | Auth | Description |
|---|---|---|
| `GET /health/live` | none | Process liveness, no dependency checks |
| `GET /health`, `/health/ready`, `/api/v1/health` | none | Readiness: persistence, Neo4j, MISP, Wazuh poller, audit-chain checks. 503 if persistence or audit chain is down |
| `GET /api/v1/auth/me` | viewer | The authenticated principal |

## Alerts

| Method & path | Role | Description |
|---|---|---|
| `POST /api/v1/alerts/ingest` | analyst | Ingest one alert (201), or return the existing one for a duplicate (200, `deduplicated: true`) |
| `POST /api/v1/alerts/ingest/batch` | analyst | Up to 100 alerts; per-item `created` / `deduplicated` / `failed` |
| `GET /api/v1/alerts` (alias `/api/v1/investigations`) | viewer | Paginated list. Query: `page`, `page_size` (≤100), `priority`, `status`, `search`, `incident_id`, `host` |
| `GET /api/v1/alerts/{alert_id}` (alias `/api/v1/investigations/{alert_id}`) | viewer | Full detail: finding, triage + score breakdown, enrichment, stages, guardrail results, raw alert |
| `POST /api/v1/investigations/{alert_id}/enrich` | analyst | Re-run enrichment (does not change the stored score) |

```bash
curl -s -X POST $TF/api/v1/alerts/ingest -H "$ANALYST" -H 'Content-Type: application/json' -d '{
  "source": "manual",
  "raw_alert": {
    "id": "manual-0001",
    "timestamp": "2026-10-27T10:00:00.000+0000",
    "rule": {"id": "5712", "level": 10, "description": "SSH brute force against admin account", "mitre": {"id": ["T1110.001"]}},
    "agent": {"id": "001", "name": "web-server-01", "ip": "192.168.1.50"},
    "data": {"srcip": "203.0.113.195", "dstip": "192.168.1.50", "dstuser": "admin"}
  }
}'
```

## Demo scenarios (synthetic)

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/demo/scenarios` | viewer | Available scenarios |
| `POST /api/v1/demo/scenarios/{scenario_id}/load` | analyst | Ingest through the normal pipeline; idempotent. 403 when `DEMO_MODE=false` |

Scenario IDs: `intrusion-chain`, `c2-beacon`, `benign-activity`, `adversarial-telemetry`.

## Incidents

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/incidents` | viewer | Paginated; `status`, `priority`, `search`. Open first, then risk |
| `GET /api/v1/incidents/{id}` | viewer | Incident + alert summaries + approvals + related audit events + action catalog + narrative mode |
| `PATCH /api/v1/incidents/{id}/status` | analyst | `{"status": "OPEN|INVESTIGATING|ESCALATED|RESOLVED|FALSE_POSITIVE", "reason": "..."}`; 409 if unchanged |
| `POST /api/v1/incidents/{id}/notes` | analyst | `{"text": "..."}` |
| `POST /api/v1/incidents/{id}/actions` | analyst | Propose a simulated action: `{"action_name", "target", "rationale"}`. Target must be a host/IP/account observed in the incident |
| `POST /api/v1/incidents/{id}/narrative` | analyst | `{"use_llm": false}` — evidence-cited summary (template, or LLM when configured) |
| `GET /api/v1/incidents/{id}/report` | viewer | JSON report download |
| `GET /api/v1/incidents/{id}/graph` | viewer | Nodes/edges for the incident; `source` is `neo4j` or `workflow_resolution` |
| `GET /api/v1/graph/entities/{entity_id}?depth=1` | viewer | Neighborhood of a canonical entity (`asset:agent:001`, `ioc:ip:203.0.113.195`, …) |

```bash
curl -s -X POST $TF/api/v1/incidents/INC-XXXX/actions -H "$ANALYST" -H 'Content-Type: application/json' \
  -d '{"action_name": "isolate_host", "target": "db-server-01", "rationale": "Large outbound transfer after lateral movement"}'
```

## Approvals & guardrails

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/approvals?status=PENDING` | viewer | Queue (statuses: PENDING, APPROVED, REJECTED, EXPIRED, REVOKED, EXECUTED) |
| `GET /api/v1/approvals/{request_id}` | viewer | One request incl. bound proposal and `expires_in_seconds` |
| `POST /api/v1/approvals/{request_id}/decide` | approver | `{"decision": "APPROVE"|"REJECT", "reason": "..."}`. Reviewer = authenticated principal. 403 on self-approval, 409 if not PENDING/expired |
| `POST /api/v1/approvals/{request_id}/execute` | approver | Re-validates via guardrail and executes once (simulated). 409 if not APPROVED, expired, tampered, or already executed |
| `GET /api/v1/actions/catalog` | viewer | Allowed (simulated) actions |

## Threat intelligence

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/intel/indicators` | viewer | Indicators seen in alerts with latest verdict and linked alerts/incidents |
| `GET /api/v1/intel/lookup?indicator=198.51.100.22` | analyst | On-demand lookup (IP or domain) |
| `GET /api/v1/intel/demo-feed` | viewer | Contents of the synthetic feed |

## Dashboard, audit, integrations

| Method & path | Role | Description |
|---|---|---|
| `GET /api/v1/dashboard?bucket_hours=1` | viewer | Counts, trend, top hosts/users/tactics, priority incidents, recent alerts/approvals/audit, service health |
| `GET /api/v1/stats` | viewer | Legacy flat counts (`critical`, `high`, …, `priority_p1..p4` aliases) |
| `GET /api/v1/audit?page=1&page_size=50&operation=&actor=` | viewer | Audit events, newest first |
| `GET /api/v1/audit/verify` | viewer | Recompute the hash chain |
| `GET /api/v1/integrations/status` | viewer | Wazuh/Neo4j/MISP/CMDB/persistence/LLM/auth/demo state (no credentials) |
