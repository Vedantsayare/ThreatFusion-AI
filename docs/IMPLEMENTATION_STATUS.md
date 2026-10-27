# Implementation status

Last updated: 2026-10-28 (after the release-readiness audit; see [`RELEASE_READINESS.md`](RELEASE_READINESS.md)). Environment: macOS (Apple Silicon), Python 3.13.5,
Node 22.21, Docker 29.8 with PostgreSQL 16.4, Neo4j 5.24 Community, and Redis 7.4
from `docker-compose.yml`.

## 1. Baseline (repository `HEAD` 7a9f969, before this work)

Measured on an untouched `git archive` of `HEAD`:

| Check | Result |
|---|---|
| `pytest tests/unit` | **244 passed, 1 failed** (`test_production_rejects_insecure_bolt_scheme`) |
| `mypy` (packages) | 1 error (`ingestion/wazuh_client.py:214`) |
| `npm run build` | passed |
| Labelled benchmark (`simulation/evaluation.py`, 20 synthetic alerts) | 85% accuracy, macro-F1 0.859 |

### Defects found during the audit

| # | Defect | Impact |
|---|---|---|
| 1 | The API and the LangGraph runner each built their own `GuardrailEngine` | Approvals created by triage could never be decided via the API (404) |
| 2 | `reviewer_id` taken from the request body; no authentication at all | Anyone could approve anything as anyone |
| 3 | `ApprovalService.reject()` ignored status | An APPROVED request could be flipped; decisions were not final |
| 4 | No execution step after approval | Approve/reject had no effect; replay protection untestable |
| 5 | `/stats` counted `P1..P4` while triage emits `CRITICAL..LOW` | Every severity counter was always 0 |
| 6 | Shared stateful `EntityResolver` was never reset | Each alert's result contained every prior entity (unbounded memory, full graph re-write per alert) |
| 7 | Windows `eventdata` (`targetUserName`, `commandLine`) not normalized | User/process missing for most Windows scenarios |
| 8 | Python's `is_global` is False for RFC 5737 ranges | The external-exposure factor never fired on demo/test IPs (an existing test assumed it did) |
| 9 | No persistence: PostgreSQL provisioned but unused | All data lost on restart |
| 10 | Wazuh poller never started by the app; integrations endpoint hard-coded `wazuh.enabled: true` | Status misreported |
| 11 | Neo4j never connected by the app (`enable_graph_persistence=False`) | Graph features inert |
| 12 | CORS `*` with credentials | Unsafe default |
| 13 | Dashboard offline fallback reported Neo4j "enabled" when the API was down | Fake status |
| 14 | No LLM code; no Cytoscape despite README; no UI ingestion | Documented features missing |
| 15 | Test helper passed upper-case kwargs to `AppSettings`, which silently ignored them | The production-TLS test never ran in production mode (cause of the baseline failure; the guard itself was correct) |
| 16 | Live Neo4j test not marked `integration` | Ran during plain `pytest` against the real DB |
| 17 | `misp-docker` is a gitlink without `.gitmodules` | Cannot be fetched with `git submodule` |
| 18 | README marked phases complete that weren't (e.g. Redis Streams, WebSocket API, PostgreSQL schema) | Inaccurate documentation |

## 2. Current state

### Verified (exercised in this environment)

| Area | How verified |
|---|---|
| Unit + API + security suite | `pytest`: **298 passed, 0 failed**, 1 deselected (live integration test) |
| Live Neo4j integration test | `pytest -m integration`: 1 passed |
| Type checking | `mypy .` (strict, incl. tests): **no issues in 75 files** |
| Lint | `ruff check .`: **all checks passed** |
| Browser E2E | `npm run test:e2e` (Playwright, local Chrome, isolated stack): **1 passed**, a 14-step analyst → approver → audit flow |
| Security controls | Role matrix over all 36 route/method pairs; lockout; rate limit; chunked-body limit; CORS; concurrent decision/execution; ordered write retry (`tests/unit/test_security_hardening.py`) |
| Frontend | `npm run build` (`tsc` + Vite): passed, no warnings |
| End-to-end over HTTP, live PostgreSQL + Neo4j | 25/25 scripted checks: auth 401/403, scenario ingest, Neo4j writes, breakdown = score, correlation (6 alerts → 1 CRITICAL incident across 6 tactics), Neo4j-backed incident/entity graphs with edge provenance, template narrative, status/notes, propose → 403 for analyst → 409 before approval → approve → simulated execute → 409 replay, reject, idempotent reload, audit verify, report export, dashboard |
| Restart persistence (PostgreSQL) | API restarted: 10 alerts, 4 incidents (incl. INVESTIGATING), approval states, and the audit chain restored and re-verified |
| Restart persistence (SQLite) | Unit test restarts the app twice against a temp SQLite file |
| Dashboard in Chrome against the live API (manual) | Sign-in, overview, alerts, alert detail, incident workspace (overview, graph, response), propose action as analyst, sign in as approver, approve and execute, audit log + chain verification, threat intel, integrations. Bugs found here were fixed (see CHANGELOG) |
| Security headers / 401 | `curl` against the live API |

### Implemented, not verified against the real external system

| Area | Why not verified |
|---|---|
| Wazuh polling (`WAZUH_ENABLED=true`) | No Wazuh manager/indexer available; client + poller covered by mocked unit tests |
| MISP lookups | No MISP instance; client, verdict mapping, timeouts, and failures covered by mocked tests |
| LLM narrative (`anthropic`, `ollama`) | No credentials/local model used; JSON/evidence validation and fallback covered by tests with a stubbed provider |
| Linux / Windows | Only macOS was run |

### Not implemented / planned

- Redis usage (provisioned only)
- Alembic migrations (tables created at startup)
- OIDC/SSO, key rotation, proxy-level rate limiting (in-process per-IP throttling exists)
- Real response connectors (all actions simulated)
- External anchoring of the audit-chain head
- Broader browser coverage (one Playwright flow today)
- Frontend unit tests (none configured)

## 3. Triage benchmark (regression check)

Reproducible with `python -m simulation.benchmark` (full output in [`DETECTION_EVALUATION.md`](DETECTION_EVALUATION.md)). Synthetic, project-authored labels; this is not a measure of real-world detection accuracy.

| Mode | Accuracy | Macro-F1 | Notes |
|---|---|---|---|
| Baseline (`HEAD`) | 0.85 | 0.859 | 3 HIGH-labelled alerts scored CRITICAL |
| Current, no enrichment | 0.85 | 0.859 | Identical to baseline |
| Current, enrichment, before the context rule | 0.70 | 0.701 | Asset criticality / SUSPICIOUS intel tipped borderline alerts over thresholds |
| Current, enrichment (final) | 0.80 | 0.815 | Context rule + same-IP evidence dedupe. Remaining delta: 1 MEDIUM → HIGH from a HIGH-criticality asset |

## 4. External dependencies and credentials

| Dependency | Required? | Credentials |
|---|---|---|
| PostgreSQL | For `PERSISTENCE_BACKEND=postgres` | `POSTGRES_PASSWORD` (generated by `scripts/bootstrap_env.py`) |
| Neo4j | Optional (fallback exists) | `NEO4J_PASSWORD` (generated) |
| Redis | Not used | `REDIS_PASSWORD` (generated; compose requires it) |
| Wazuh | Optional | API user/password you create |
| MISP | Optional | Auth key you create |
| LLM | Optional | `LLM_API_KEY` (Anthropic) or a local Ollama |

## 5. Prioritized next steps

1. Verify Wazuh against a real manager/indexer and record fixtures.
2. Alembic migrations + normalized tables; query-side pagination in SQL.
3. OIDC + short-lived tokens; move throttling to the proxy.
4. Extend Playwright coverage (graph, false-positive closure, error states).
5. Recalibrate the original triage weights against real labelled data (3 HIGH → CRITICAL over-escalations on the benchmark predate this work).
