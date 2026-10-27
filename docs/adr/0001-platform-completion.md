# ADR-0001 — Platform completion: end-to-end workflow decisions

**Date**: 2026-10-27
**Status**: Accepted
**Authors**: ThreatFusion AI project

Each decision below is one paragraph, per the project's ADR rule.

## D1 — One shared GuardrailEngine for workflow and API

Previously the API built its own `GuardrailEngine` while the LangGraph runner built another, so approval requests created during triage were invisible to `POST /approvals/{id}/decide` (404). The application now constructs exactly one engine (with one `ApprovalService` and one `HashChainAuditStore`) and passes it to both; `init_api_dependencies` raises if a runner with a different engine is supplied. This is the only way an approval can be cryptographically bound to the action the workflow proposed and later re-validated at execution time.

## D2 — Per-alert entity-resolution scope

`EntityResolver` is stateful. Shared across the runner, each alert's `ResolutionResult` included every entity ever seen, so memory grew without bound and every alert re-wrote the whole history to Neo4j. The workflow now calls `resolver.reset()` before resolving each alert. Cross-alert identity continuity is still guaranteed because canonical IDs are deterministic (`asset:agent:001`, `identity:user:root@web-server-01`, …) and Neo4j `MERGE`s on them; cross-alert *grouping* is the job of the incident correlator (D5), which records why alerts were linked.

## D3 — Persistence: JSON documents in PostgreSQL/SQLite with write-through

Alerts (full workflow output), incidents, approval requests, and audit events are stored as JSON documents in four tables (`tf_alerts`, `tf_incidents`, `tf_approvals`, `tf_audit_events`) via SQLAlchemy async (asyncpg for PostgreSQL, aiosqlite for a no-Docker SQLite file). The in-memory working set serves reads; every mutating request flushes queued writes, in order, before it responds, so a client is never told something was saved that the database did not accept, and audit rows land in chain order. Documents (not a normalized schema) were chosen because the domain models are already strict Pydantic types and the read paths are small; a normalized schema plus Alembic migrations is the right next step when query volume requires it. Tables are created idempotently at startup. `PERSISTENCE_BACKEND=memory` exists for tests and is reported as `degraded` by `/health`. If PostgreSQL is configured but unreachable the API refuses to start (fail closed) rather than silently running without durability.

## D4 — API-key authentication with ordered roles

A complete identity system (OIDC, sessions, password storage) was out of scope for this release. API keys from `API_KEYS` (`name:role:key`) are hashed (SHA-256) at load, compared in constant time, and mapped to ordered roles `viewer < analyst < approver < admin`. The authenticated principal name is the only identity written to the audit log; the deprecated `reviewer_id` request field is ignored. Placeholder or short keys are rejected, and with no valid keys every protected endpoint returns 401 (fail closed). Separation of duties: the proposer of an action cannot approve it. This is suitable for a trusted local/lab deployment, not for internet exposure.

## D5 — Deterministic incident correlation on strong keys only

Alerts are grouped into incidents only through strong, specific keys: Wazuh agent ID (0.9), non-generic hostname (0.7), account scoped to a host (0.8), external IP (0.6), and internal host address (0.5, so traffic *from* a compromised host links to alerts *on* it). Generic attributes (generic usernames unscoped, private IPs as standalone indicators, generic hostnames) never correlate. A 24-hour window around the incident's activity bounds weak links. Every link stores its matched key, basis, and confidence. Alerts triaged LOW that match nothing do not open an incident. Incident risk is the maximum alert score plus a bounded attack-progression bonus (+5 for two distinct ATT&CK tactics, +10 for three or more); alert-level factors are not re-added, avoiding double counting.

## D6 — Documentation IP ranges count as external

Python's `ipaddress.is_global` is `False` for RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). Those ranges are never used as internal address space and are the conventional stand-ins for internet hosts in examples, tests, and our synthetic scenarios (an existing test already assumed `203.0.113.5` earned the public-IP factor). `normalization.net.is_external_ip` treats them as external so the external-exposure factor and external-IP correlation behave as intended on demo data.

## D7 — Threat-intel verdicts and the synthetic demo feed

Per-source verdicts are combined with "most severe wins": MALICIOUS > SUSPICIOUS > BENIGN > UNKNOWN. BENIGN survives only when a source explicitly allow-lists an indicator and no available source disagrees. No information, or a failed/disabled lookup, is UNKNOWN with the reason recorded; it never lowers a score. In demo mode a static feed of RFC 5737 / `example.*` indicators supplies verdicts so the workflow is demonstrable without MISP; every such verdict carries `synthetic: true` and is labelled in the UI and in score-breakdown text.

## D8 — Response actions are simulated

All catalogued actions (`create_investigation_task`, `isolate_host`, `block_ip`, `disable_account`, `reset_credentials`) are simulated. Execution requires an APPROVED, unexpired request whose stored proposal still hashes to the approved `action_hash`; the guardrail re-evaluates it, the request moves to the terminal `EXECUTED` state (replay protection), and the outcome text states that no external system was contacted. Real integrations must replace the simulation explicitly and report confirmed outcomes.

## D9 — LLM is optional, advisory, evidence-bound

Only the incident narrative may use an LLM. Evidence is assembled deterministically and numbered (E1…); the model receives it inside an `<evidence>` block declared untrusted, must answer in JSON, and every fact and hypothesis must cite known evidence IDs. Invalid JSON, unknown citations, missing citations, refusals, or call failures fall back to the deterministic template with the reason shown. Narrative output never alters scores, priorities, status, or guardrail decisions. Supported providers: `anthropic` (official SDK, optional `[llm]` extra) and `ollama` (local HTTP); `none` (default) uses the template; `openai`/`gemini` are accepted for config compatibility but fall back to the template and say so.
