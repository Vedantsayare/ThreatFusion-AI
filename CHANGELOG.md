# Changelog

## 1.2.0 — 2026-10-28 (release-readiness audit)

Full report: [`docs/RELEASE_READINESS.md`](docs/RELEASE_READINESS.md).

### Security
- **Fixed (High):** a failed database write was dropped while later writes still persisted, leaving a gap in the stored audit chain. Writes are now dequeued only after success and retried in order.
- Added authentication brute-force lockout (`AUTH_MAX_FAILURES`, `AUTH_LOCKOUT_SECONDS`) and per-client rate limiting (`RATE_LIMIT_PER_MINUTE`).
- The body-size limit now covers chunked uploads (buffered, bounded ASGI middleware → 413).
- Guardrail audit events are attributed to the acting principal; at execution that's the approver, and the proposer is kept in metadata.
- Private IPs are no longer sent to threat-intel sources.

### Detection
- Same-indicator evidence counts once: intel on an IP subsumes that IP's external-exposure points, which stay intrinsic for the CRITICAL rule.
- New reproducible benchmark `python -m simulation.benchmark` with per-class precision/recall/F1/FPR/FNR, attention metrics, and per-miss diagnosis; report in `docs/DETECTION_EVALUATION.md`, pinned by a test. Results are unchanged: 85% without enrichment, 80% with.

### Tests and tooling
- `tests/unit/test_security_hardening.py`: role matrix over every route, lockout, rate limit, chunked body, CORS, concurrent decisions/executions, ordered write retry, attribution, fail-closed guardrail, non-leaking 500s, health under outage, deterministic grouping.
- Playwright browser test (`npm run test:e2e`) for the full analyst → approver → audit workflow against an isolated stack in local Chrome.
- `ruff check .` passes (72 findings introduced in 1.1.0 fixed; FastAPI `Depends`/`Query` registered as immutable calls).
- The Vite proxy target is configurable via `TF_API_URL`.

### Hygiene
- Unstaged five component deletions that had been staged with `git rm`. Nothing is staged or committed.

## 1.1.0 — 2026-10-28

End-to-end SOC workflow completed and verified against live PostgreSQL and Neo4j.
Details and evidence: [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md).
Design decisions: [`docs/adr/0001-platform-completion.md`](docs/adr/0001-platform-completion.md).

### Security fixes
- One shared `GuardrailEngine` for workflow and API. Triage-created approvals were previously undecidable.
- API-key authentication with ordered roles (`viewer < analyst < approver < admin`). The reviewer identity now comes from the key, and the body `reviewer_id` is ignored.
- Approval decisions are final (`reject()` no longer flips approved requests). Separation of duties: proposers cannot approve their own actions.
- New `EXECUTED` terminal state: execution re-validates the stored proposal hash through the guardrail and is single-use (replay protection).
- Response actions restricted to an allow-listed catalog and to targets observed in the incident. All actions are simulated.
- CORS restricted to an explicit allow-list (was `*` with credentials). Request-size limit, `Cache-Control: no-store`, CSP on API responses, generic 500 bodies. `X-XSS-Protection` is set to `0` per current OWASP guidance.

### Correctness fixes
- Dashboard severity counters (triage emits `CRITICAL..LOW`; stats counted `P1..P4`).
- Per-alert entity-resolution scope (the shared resolver previously accumulated every alert).
- Windows `eventdata` user and process normalization; destination domains.
- RFC 5737 documentation addresses are treated as external (`normalization/net.py`).
- The test helper `_make_settings` passed ignored upper-case kwargs, so the production-TLS test never ran in production mode. Fixed, and the test now passes.
- The live Neo4j test is marked `integration` and excluded from the default `pytest` run.
- The mypy error in `wazuh_client.authenticate` is fixed.

### Features
- Durable persistence (PostgreSQL or SQLite) for alerts, incidents, approvals, and the audit chain, verified at startup.
- Neo4j connected at startup with fallback and honest reporting; incident and entity graph endpoints.
- Deduplicated ingestion (single, batch, demo scenarios); the optional Wazuh poller is now wired into the same pipeline.
- New LangGraph stage `enrich_indicators`: threat-intel verdicts (MALICIOUS/SUSPICIOUS/BENIGN/UNKNOWN) from MISP and a labelled synthetic demo feed, plus CMDB/IAM context, with per-source time budgets.
- Triage: per-factor `score_breakdown`, threat-intel and asset-criticality factors, privilege counted once, and `priority_rule`. Context alone cannot raise an alert to CRITICAL.
- Incidents: deterministic correlation on strong keys with a recorded basis and confidence, risk with attack-progression bonus, status lifecycle, notes, history, JSON report export.
- Evidence-cited narrative: deterministic template, plus optional Anthropic/Ollama output validated against evidence IDs.
- Audit log listing and verification endpoints; `/health/live` and real readiness checks.
- Dashboard rebuilt: sign-in, SOC overview, alerts with ingestion and scenarios, alert detail, incident workspace (overview, timeline, Cytoscape graph, narrative, response, notes), knowledge-graph explorer, threat intel, approvals, audit log, integrations.
- `scripts/bootstrap_env.py` generates `.env` with random secrets and API keys.

### Docs
- README rewritten from the verified implementation. Added `docs/ARCHITECTURE.md`, `API_REFERENCE.md`, `SECURITY.md`, `DEMO_GUIDE.md`, `TROUBLESHOOTING.md`, `IMPLEMENTATION_STATUS.md`, and ADR-0001.
