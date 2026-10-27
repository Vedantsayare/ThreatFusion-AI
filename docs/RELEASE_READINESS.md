# Release readiness report

Date: 2026-10-28 · Scope: uncommitted working tree on `main` (base `7a9f969`) ·
Environment: macOS (Apple Silicon), Python 3.13.5, Node 22.21, Docker 29.8 with
PostgreSQL 16.4 / Neo4j 5.24 Community / Redis 7.4, Google Chrome (for Playwright).

**Verdict: ready for a portfolio demo and a trusted internal lab. Not ready for production** (see §6).

---

## 0. Working-tree hygiene

| Check | Result |
|---|---|
| Staged changes | **None.** Five component deletions had been staged with `git rm` in the previous session. They were unstaged (`git restore --staged`); the files remain deleted in the working tree. Nothing has been committed or pushed. |
| `.env`, `*.db`, `.venv/`, `node_modules/`, Playwright output | Git-ignored (verified with `git check-ignore`) |
| Tracked sensitive files | None (`git ls-files` scan for `.env`, keys, certs, `.db`) |
| Generated secrets in committable files | **0 hits.** Every value of `SECRET_KEY`, database passwords, and `API_KEYS` from `.env` was searched for across all tracked and untracked-unignored files. |
| Test credentials in repo | Only e2e-only placeholder keys (`e2e-*-key-0123456789abcdef`, `sec-*`, `viewer-key-*`). They are valid only for ephemeral test servers. |
| Destructive operations | None. No volumes, databases, or Git history were reset or recreated. |

## 1. Security findings by severity

### Fixed in this audit

| Sev. | Finding | Fix | Test |
|---|---|---|---|
| **High** | `store.flush()` dequeued each write *before* awaiting it. One failed DB write was lost while later writes still persisted, leaving a permanent gap in the **stored** audit chain (it would fail verification after restart). | A write is dequeued only after success; failures stay at the head and are retried in order. `pending_writes` is exposed. | `test_failed_writes_are_retried_in_order` |
| Medium | No authentication brute-force protection | Per-client lockout after `AUTH_MAX_FAILURES` (10) failures in `AUTH_LOCKOUT_SECONDS` (300). Returns 429 with `Retry-After`, valid keys included. Verified live: 10× 401, then 429. | `test_auth_failures_lock_out_client` |
| Medium | No rate limiting | Per-client sliding window (`RATE_LIMIT_PER_MINUTE`, 600); `/health/live` exempt | `test_rate_limit_and_exempt_liveness` |
| Medium | Body-size limit only checked `Content-Length`, so chunked uploads bypassed it | Pure-ASGI middleware buffers at most `MAX_REQUEST_BYTES` before the app runs → 413 | `test_chunked_body_without_content_length_is_limited` |
| Medium | Guardrail ALLOW at execution was audited under the **proposer's** name instead of the approver who executed | `evaluate(..., actor=)`; proposer kept in metadata | `test_execution_audit_names_the_executor` |
| Low | Private IPs were sent to threat-intel sources: noise, and disclosure of internal addressing | Only external IPs and domains are looked up | `test_private_ips_are_not_sent_to_intel_sources` |
| Low | MISP "not configured" was reported as "lookup unavailable" | Per-source reason in the rationale | `test_disabled_misp_is_reported_as_not_configured` |

### Verified correct (no change needed)

| Control | Evidence |
|---|---|
| Every route enforces its role server-side | `test_every_route_declares_a_role` fails if any route lacks a declared role; `test_role_matrix_enforced_server_side` checks anonymous → 401, bad key → 401, under-privileged → 403, sufficient role → allowed, for all 36 route/method pairs |
| Viewer cannot ingest/propose/decide; analyst cannot decide | Role matrix + Playwright step 9 (analyst decide → 403) |
| Proposer cannot approve own action | `test_self_approval_is_forbidden` |
| Keys hashed (SHA-256) and compared in constant time; never echoed in responses | `api/auth.py`; `test_keys_are_never_echoed`. Auth-failure logs record client and path only. |
| Approvals bound to exact action hash; tampering denied at execution | `test_tampered_action_is_denied_at_execution` |
| Expired, replayed, already-decided approvals rejected; one-way state machine | `test_approval_state_machine_is_one_way`, `test_expired_approval_cannot_be_approved_or_executed`, Playwright step 14 |
| Concurrent decisions and executions resolve exactly once | `test_concurrent_decisions_and_executions_resolve_once` (3 concurrent decisions → one 200; 5 concurrent executes → one 200, one audit event). Safe because check-and-transition has no `await` in between (single event loop). |
| No execution before approval | `test_workflow_approvals_are_decidable_and_single_use` |
| Guardrail errors fail closed | `test_guardrail_errors_fail_closed` (decision `ERROR`, no approval created) |
| Explicit CORS allow-list, wildcards dropped, no credentials | `test_cors_allows_only_configured_origins` |
| 500s leak nothing | `test_unexpected_errors_do_not_leak_details` (body is exactly `{"detail": "Internal server error"}`) |
| Security headers | `nosniff`, `DENY`, `X-XSS-Protection: 0`, `Referrer-Policy`, `Permissions-Policy`, `no-store`, CSP on API responses (checked with `curl` against the live API) |

### Open (documented, not fixed)

| Sev. | Finding | Why not fixed now |
|---|---|---|
| Medium | API keys are long-lived shared secrets; no rotation, expiry, MFA, or SSO | Needs a real identity provider. A fake SSO was deliberately not added. |
| Medium | Throttling is per client IP and in-process. Behind a proxy (including the Vite dev proxy) all users share one IP, so one client's failures lock everyone out. Limits reset on restart. | Correct enforcement belongs at the proxy/gateway in multi-user deployments |
| Medium | Single-process state: running more than one uvicorn worker would diverge | Architectural; see Redis note below |
| Low | Partial failure: after a DB error the request returns 500 but memory keeps the change until the queued write succeeds. A crash before that loses the most recent changes (the chain stays gap-free). | Requires transactional rework (write DB first, then memory) |
| Low | `/health*` and `/docs` are unauthenticated and reveal component names and status | Acceptable for a lab; restrict at the proxy |
| Low | The dashboard keeps the API key in `sessionStorage` (readable by any script on that origin) | Inherent to bearer keys in a SPA; needs HttpOnly session cookies plus CSRF protection |
| Info | Hash chain is tamper-evident, not immutable: an attacker with unrestricted DB write access can recompute a valid chain | Anchor the head hash externally (roadmap) |
| Info | Plaintext DB connections on localhost in dev compose | Dev-only configuration |

**Redis:** provisioned in `docker-compose.yml` and **not used by any code**. No durability or queueing is claimed. Its one justified future use is a Redis Streams consumer group between the Wazuh poller and API workers, needed only if the API runs more than one worker. Nothing was added just to fill out the architecture.

## 2. Other fixes in this audit

- `ruff check .`: 72 findings, all introduced by the previous session (**baseline was clean**), are now fixed. 36 were auto-fixed (compound asserts split, imports sorted) and the rest by hand: specific `match=` on `pytest.raises`, `BodyTooLargeError` naming, fixture `return`. FastAPI `Depends`/`Query` are registered as `extend-immutable-calls` (documented B008 false positive for the framework idiom).
- Triage: same-indicator double count removed. Intel on an IP subsumes that IP's external-exposure points. The subsumed points remain *intrinsic* for the "context alone cannot reach CRITICAL" rule. An earlier version of this fix accidentally dropped them and raised benchmark accuracy to 85%; that side effect was identified and reverted rather than kept.

## 3. Tests executed (final run, exact results)

| Command | Result | Baseline (`7a9f969`) |
|---|---|---|
| `pytest` | **298 passed**, 1 deselected (live test), 1 third-party deprecation warning (Starlette test client / anyio) | 244 passed, 1 failed |
| `pytest -m integration` (live Neo4j container) | **1 passed** | not separable (unmarked) |
| `mypy .` (strict, incl. tests) | **no issues in 75 files** | 1 error |
| `ruff check .` | **All checks passed** | All checks passed |
| `npm run build` (`tsc` + Vite) | **passed**, no warnings | passed |
| `npm run test:e2e` (Playwright, Chrome, isolated stack) | **1 passed** (14-step workflow), stable across 3 runs | not configured |
| Frontend unit tests | **none configured** | none |
| `python -m simulation.benchmark` | reproducible; see §4 | — |
| Live API on PostgreSQL + Neo4j after restart | 11 alerts / 4 incidents / approvals (incl. one naturally EXPIRED) restored; audit chain verified (55 events); health ok | — |

The one baseline failure (`test_production_rejects_insecure_bolt_scheme`) was a test-helper bug, fixed in the previous session. It is not counted as a new failure.

**New tests in this audit:** `tests/unit/test_security_hardening.py` (15), `tests/unit/test_benchmark.py` (1), 3 in `test_platform.py`, and `dashboard/e2e/approval-flow.spec.ts` (1 browser test).

### Browser test coverage (`dashboard/e2e/approval-flow.spec.ts`)

1. open dashboard, 2. sign in as analyst, 3. load the synthetic intrusion scenario, 4. alerts visible, 5. open the generated incident, 6. risk explanation, attack progression, correlation basis, and affected hosts visible, 7. propose `isolate_host` on `db-server-01`, 8. pending approval shown with its ID, 9. analyst has no decision control **and** the API returns 403, 10. sign in as approver, 11. approve that exact request, 12. execute and see `EXECUTED` / "executed (simulated)", 13. audit log shows the decision and execution events, chain intact, 14. re-execute → 409, reverse decision → 409, final status `EXECUTED`, chain verified.

The test runs its own API (port 8010, temporary SQLite, Neo4j off, e2e-only keys) and Vite server (port 5175). The live demo data was confirmed unchanged afterwards.

## 4. Detection evaluation

Full report: [`DETECTION_EVALUATION.md`](DETECTION_EVALUATION.md), regenerated by `python -m simulation.benchmark --out docs/DETECTION_EVALUATION.md` and pinned by `tests/unit/test_benchmark.py`.

| Mode | Accuracy | Macro-F1 | Over-esc. | Under-esc. | HIGH+CRIT precision | HIGH+CRIT recall | Attention FPR |
|---|---|---|---|---|---|---|---|
| baseline (no enrichment) | 85.0% | 0.859 | 3 | 0 | 100% | 100% | 0% |
| enriched (demo intel + mock CMDB) | 80.0% | 0.815 | 4 | 0 | 91.7% | 100% | 11.1% |

Per-alert analysis of every miss:

- **P2-01, P2-02, P2-03** (labelled HIGH, scored CRITICAL in both modes) are **rule/label disagreements**. Their intrinsic factors alone reach 80–90: Medium/High-severity rule + privileged account (+15) + high-impact ATT&CK technique (+15) (+ external IP for P2-01). The same combination on correctly-labelled CRITICAL items (e.g. P1-04) must stay CRITICAL, so no weight change fixes these three without breaking others. That makes it a labelling or policy question, not a bug.
- **P3-05** (labelled MEDIUM, scored HIGH with enrichment) is **context-driven**: intrinsic 55, plus asset criticality HIGH (+5) = 60. Raising a web-service shell on a HIGH-criticality, PCI-tagged production server is defensible, so it was left as is.
- **Correlated evidence:** P2-01 previously counted the same IP twice (exposure +10 and SUSPICIOUS intel +10). Fixed; no priority changed.
- **Missing intelligence:** UNKNOWN never adds points and is recorded as an uncertainty. Confirmed in every miss's breakdown.
- **Label consistency:** the benchmark labels HIGH some alerts with the same factor profile that the demo scenarios (and the scoring policy) treat as CRITICAL. With 4–6 samples per class, each error moves a class rate by 17–25 points.

**Limitations:** 20 synthetic alerts with author-written labels that are not independent of the rules. Weights were **not** tuned to this set. Proposed evidence-based next step: recalibrate `privileged_account_boost` + `high_impact_mitre_boost` (which co-occur on most Windows execution alerts) against real, independently labelled alerts.

## 5. Integrations actually verified

| Integration | Real system? | How |
|---|---|---|
| PostgreSQL 16 | **Yes** (Docker) | Live ingest, restart restore, audit chain re-verification |
| Neo4j 5.24 | **Yes** (Docker) | Live graph writes and reads; `pytest -m integration` |
| SQLite | Yes (local file) | Restart test; Playwright stack |
| Google Chrome | Yes | Playwright E2E |
| Wazuh | **No**: mocked unit tests only | No instance available |
| MISP | **No**: mocked unit tests only | No instance available |
| LLM (Anthropic / Ollama) | **No**: stubbed provider tests only | No credentials or local model used |
| CMDB / IAM | **Synthetic mock** | `MockIAMCMDBProvider` |
| Threat intel in demos | **Synthetic feed** | RFC 5737 addresses / `example.*` domains, labelled `synthetic` |
| Redis | Not used | — |

## 6. Remaining blockers

**Production:** no SSO/MFA/key rotation; per-IP in-process throttling; single-worker state; partial-failure semantics; no external anchoring of the audit head; Wazuh/MISP/LLM unverified against real systems; plaintext DB links in dev compose; no schema migrations (tables created at startup); response actions are simulated only.

**Portfolio demo / internal lab:** none blocking. Known caveat: behind the Vite proxy, a demo participant who enters a wrong key 10 times locks everyone out for 5 minutes (`AUTH_LOCKOUT_SECONDS`).

## 7. Repeatable local demonstration

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python scripts/bootstrap_env.py      # first time only; refuses to overwrite an existing .env
docker compose up -d && docker compose ps
uvicorn api.app:app --host 127.0.0.1 --port 8000          # one worker
cd dashboard && npm install && npm run dev                 # http://localhost:5173
```

Then follow [`DEMO_GUIDE.md`](DEMO_GUIDE.md). Automated replay of the same flow: `cd dashboard && npm run test:e2e`.

Never run `scripts/bootstrap_env.py --force` against existing data volumes: it regenerates database passwords that PostgreSQL and Neo4j already initialized with.

## 8. Readiness

| Target | Ready? |
|---|---|
| Portfolio demonstration | **Yes** |
| Internal lab on a trusted network (single worker, behind no shared proxy or with proxy-level limits) | **Yes, with the documented limitations** |
| Production | **No.** See §6. |
