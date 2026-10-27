# Architecture

This document covers internals. For the overview diagrams, scoring tables, and
the graph model, see the [README](../README.md#architecture). Decisions are
recorded in [ADR-0000](adr/0000-infrastructure-baseline.md) and
[ADR-0001](adr/0001-platform-completion.md).

## Module responsibilities

| Module | Responsibility | Talks to |
|---|---|---|
| `api/app.py` | Lifespan wiring of the single object graph; CORS, size limit, security headers, generic 500 | everything below |
| `api/auth.py` | API-key registry (hashed), role dependencies | — |
| `api/routes.py` | HTTP surface, serialization, role checks | `SOCService`, store |
| `api/service.py` | The one ingest → correlate → approve → execute path; graph views; narrative; report | runner, store, guardrails, narrative, Neo4j |
| `api/incidents.py` | Incident model, correlation keys, risk recompute | — |
| `api/store.py` | In-memory working set, dedup index, ordered write queue, dashboard aggregates | repository |
| `api/persistence.py` | SQLAlchemy async repository (PostgreSQL / SQLite / null) | database |
| `orchestrator/*` | LangGraph state, nodes, edges, runner | normalizer, resolver, Neo4j, enrichment, triage, guardrails |
| `normalization/*` | OCSF models + normalizer, ATT&CK reference labels, IP classification | — |
| `graph/*` | Canonical-ID resolver; async Neo4j client (parameterized MERGE, whitelisted labels) | Neo4j |
| `ingestion/*` | Wazuh client + poller, MISP client, CMDB/IAM provider, intel verdicts, enrichment service | Wazuh, MISP |
| `agents/*` | Investigation context (graph history), deterministic triage, narrative | Neo4j, LLM (optional) |
| `guardrails/*` | Policy engine, approval lifecycle, hash-chained audit, action catalog | — |
| `simulation/*` | Labelled benchmark + evaluation; synthetic demo scenarios | — |
| `dashboard/` | React SPA (hash router, Cytoscape) talking only to `/api` and `/health` | API |

## Request lifecycle: `POST /api/v1/alerts/ingest`

1. `require_analyst` resolves the bearer key to a `Principal`.
2. `SOCService.ingest` computes the fingerprint (`source + upstream id`, else a SHA-256 of canonical JSON). On a hit it audits `alert_deduplicated` and returns the stored output.
3. `AlertWorkflowRunner.process_alert` runs the LangGraph with `alert_id = alert-<fingerprint[:16]>`, so IDs are stable across retries and restarts.
4. Nodes in order: `receive_alert` → `validate_input` → `normalize_alert` → `resolve_entities` (resolver reset per alert) → `persist_to_graph` (bounded retry on `GraphConnectionError`/timeout; skipped when Neo4j is absent) → `gather_investigation_context` → `enrich_indicators` (15 s stage budget, 8 s per-indicator MISP budget) → `perform_triage` (deterministic score; guardrail evaluation of triage-recommended actions creates approval requests) → `synthesize_final_result` (status + audit event).
5. The store saves the output. `_correlate` links the alert to an incident or opens one, recomputes risk, binds the triage approvals to the incident, and audits the outcome.
6. `store.flush()` writes queued rows (alert, incident, approvals, audit events) in order. Only then does the handler return 201.

## State and persistence

```
            ┌────────────── process memory ──────────────┐
 request →  │ InvestigationStore   ApprovalService   HashChainAuditStore │
            │   (alerts, incidents,   (requests)       (events, last hash) │
            │    dedup index)                                           │
            │        └──── on_change / on_append hooks ────┘            │
            │                 ordered write queue                       │
            └─────────────────────────┬─────────────────────────────────┘
                                      │ flush() before response
                                      ▼
                   tf_alerts · tf_incidents · tf_approvals · tf_audit_events
                         (PostgreSQL via asyncpg, or SQLite via aiosqlite)
```

- Reads are served from memory. Startup reloads all rows (`load_all`), restores approvals and the audit chain, and verifies the chain.
- The audit table has an autoincrement `seq` column, and reload orders by it. A lock serializes writes, so on-disk order equals chain order.
- If a database write fails, the request returns a generic 500. Already-applied in-memory state is not rolled back, which is a known limitation for a single-process lab deployment.

## Concurrency model

Single uvicorn worker, single asyncio loop. The working set is process-local, so multiple workers would diverge. Neo4j and the database are accessed with async drivers. The Wazuh poller runs as a background task on the same loop and uses the same `SOCService.ingest`.

## Failure behaviour

| Failure | Behaviour |
|---|---|
| PostgreSQL unreachable at startup | API refuses to start (fail closed) |
| Database write fails mid-request | 500 with exception class only; `/health` reports persistence state |
| Neo4j unreachable at startup | Runs without graph persistence; graph views use per-alert resolution, labelled `not persisted` |
| Neo4j write fails during a run | Bounded retries, then stage PARTIAL; uncertainty recorded; workflow continues |
| MISP slow or down | Indicator verdict UNKNOWN with reason; other sources and CMDB still apply |
| Whole enrichment stage fails | Stage PARTIAL; triage runs without context; uncertainty recorded |
| Guardrail exception | Decision ERROR (deny) |
| Audit chain fails verification | `/health` 503, `/api/v1/audit/verify` shows the break |
| LLM failure or invalid output | Template narrative, with the reason listed in `warnings` |

## Frontend

`dashboard/src`: `api.ts` (fetch wrapper with bearer token from `sessionStorage`, error surfacing, auto sign-out on 401), `router.ts` (hash routes `#/section/id?query`), `components/` (layout, login, shared UI, Cytoscape canvas), `pages/` (overview, alerts, incidents + workspace, approvals, audit / graph / intel / settings). Types in `types.ts` mirror the backend models field for field. There are no mock fallbacks: if the API is unreachable, the UI says so.
