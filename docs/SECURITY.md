# Security model, threat model, and limitations

ThreatFusion AI is a **lab / portfolio-grade** SOC copilot. It is designed to be
safe by default for a trusted local deployment. It is **not** production-ready
and must not be exposed to the internet as-is.

## Trust boundaries

| Boundary | Treated as | Controls |
|---|---|---|
| Alert content (Wazuh, JSON submissions, demo scenarios) | Untrusted data | Pydantic validation, size limits (256 KB body, 100 alerts/batch), raw alert preserved verbatim, never executed, never interpreted as instructions |
| Threat intel (MISP, demo feed) | Untrusted data | Verdict policy (UNKNOWN ≠ safe), source attribution, synthetic label |
| CMDB / IAM context | Untrusted data | Used only as additive scoring context; the bundled provider is a mock with synthetic records |
| LLM output | Untrusted advisory text | JSON schema + evidence-ID validation; never alters scores, status, or guardrail decisions |
| API callers | Authenticated principals | API-key auth, ordered roles, separation of duties |
| Databases (PostgreSQL, Neo4j, Redis) | Trusted infrastructure | Bound to 127.0.0.1 in docker-compose, passwords from `.env` |

## Controls implemented

- **Authentication**: `Authorization: Bearer <key>` (or `X-API-Key`). Keys are SHA-256 hashed in memory and compared in constant time. Placeholder/short keys are ignored. No keys configured → every protected endpoint returns 401.
- **Authorization**: `viewer` (read) < `analyst` (ingest, notes, status, propose actions) < `approver` (decide, execute) < `admin`. Enforced per endpoint via FastAPI dependencies.
- **Identity in audit**: the authenticated principal is the recorded actor. Request-body identity fields are ignored.
- **Human approval**: every containment/remediation/administrative action needs an approval. Approvals are bound to a SHA-256 hash of the exact action (name, category, targets, parameters, evidence refs), expire (default 30 min, `APPROVAL_TIMEOUT_SECONDS`), are single-use (`EXECUTED` is terminal), cannot be flipped after decision, and cannot be self-approved.
- **Guardrail engine**: deterministic Python. Prohibited actions are denied; blast radius is capped (`MAX_ISOLATION_BLAST_RADIUS`); privileged accounts add a violation and force approval; any evaluation exception yields `ERROR` (fail closed). Execution re-evaluates the stored proposal against the approval.
- **Action allow-list**: only catalogued actions may be proposed, and only against hosts/IPs/accounts observed in the incident.
- **Simulation**: no response action contacts an external system in this release.
- **Audit log**: SHA-256 hash chain; secrets (`password=`, `token:`, `Bearer …`) redacted and control characters stripped before hashing; persisted in order; verified at startup and via `GET /api/v1/audit/verify`; `/health` returns 503 if the chain fails verification.
- **Throttling**: per-client sliding-window rate limit (`RATE_LIMIT_PER_MINUTE`, default 600) and an authentication brute-force lockout. After `AUTH_MAX_FAILURES` (10) failed keys within `AUTH_LOCKOUT_SECONDS` (300), every request from that client gets 429 with `Retry-After`, valid keys included, so a guessing client can't detect a hit. `/health/live` is exempt.
- **Body size**: the ASGI middleware buffers at most `MAX_REQUEST_BYTES` (256 KB) *before* the app runs, so oversized bodies get 413 whether or not `Content-Length` is sent (chunked uploads included).
- **Attribution**: guardrail decisions are attributed to the principal who triggered the evaluation. At execution that's the approver; the proposer is kept in event metadata.
- **Write ordering**: database writes are dequeued only after they succeed. A transient failure leaves them queued and retries them in order, so the persisted audit chain never has a gap.
- **Input handling**: Pydantic models with length limits; `source` restricted to `[A-Za-z0-9_.:-]{1,64}`; parameterized SQL (SQLAlchemy Core) and parameterized Cypher with whitelisted labels/relationship types.
- **HTTP hardening**: explicit CORS allow-list (`CORS_ORIGINS`, wildcards dropped, no credentials), `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store`, restrictive CSP on API responses, generic 500 bodies (exception class only, no messages or stack traces).
- **Secrets**: only in `.env` (git-ignored, written mode 600 by `scripts/bootstrap_env.py`). `AppSettings.safe_summary()` is the only config logged. Production mode rejects placeholder secrets and disabled TLS verification.

## Important limitations

1. **The hash chain is tamper-evident, not immutable.** It detects modification, deletion, insertion, and reordering relative to the stored chain. An attacker with write access to the database can rewrite the whole chain and produce a new valid one. For stronger guarantees, periodically anchor the head hash (shown by `/api/v1/audit/verify`) somewhere the attacker cannot write (WORM storage, a separate system, a signed timestamp).
2. **API keys are long-lived shared secrets.** There is no rotation tooling, expiry, MFA, or SSO. Keys are kept in browser `sessionStorage` by the dashboard (cleared when the tab closes) and are readable by any script running on the dashboard origin.
3. **Throttling is per client IP and in-process.** Behind a reverse proxy, or the Vite dev proxy, all users share one address: one client's failed logins lock everyone out for the window, and the rate budget is shared. In that topology, enforce limits at the proxy. Limits reset when the process restarts.
4. **Public metadata endpoints.** `/health*` and `/docs` (OpenAPI) are unauthenticated. They reveal component names and status (never credentials or connection strings). Restrict them at the proxy if that matters in your environment.
5. **Partial-failure semantics.** When a database write fails, the request returns 500 but the in-memory state keeps the change, and the write is retried on the next request. A crash before the retry loses that change. The audit chain stays consistent (no gaps), but the most recent events may be missing.
6. **Single-process state.** The working set lives in one process; running multiple API workers would diverge. Run one uvicorn worker.
7. **Redis is provisioned but unused** by the application code; no queue durability is claimed. The one justified future use is a Redis Streams consumer group between the Wazuh poller and API workers. It would be needed only to run more than one worker (see item 6), and it is not built.
8. **The CMDB/IAM provider is a mock** with synthetic records.
9. **The Wazuh poller is implemented but was not verified against a live Wazuh instance** in this environment. Note that the Wazuh *server* API does not expose alerts at `/alerts` on all versions; alerts typically live in the Wazuh indexer. Adjust `WAZUH_ALERTS_ENDPOINT` accordingly.
10. **Neo4j and PostgreSQL use plaintext connections** on localhost in the development compose file.

## Responsible use

The bundled scenarios are synthetic defensive telemetry describing what detection rules reported; they contain no attack tooling. Use the platform only on systems and data you are authorized to monitor. Do not connect real response integrations without adding confirmation, rollback, and outcome verification, and keep the human-approval gate in place.

## Reporting

Report suspected vulnerabilities privately to the repository owner rather than in a public issue.
