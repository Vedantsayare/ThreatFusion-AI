# Demo guide — the full SOC workflow in ~10 minutes

Everything in this walkthrough uses **synthetic** telemetry and a **synthetic**
threat-intel feed, clearly labelled as such in the UI and API. No external
system is contacted and every response action is simulated.

## 0. Prerequisites

Backend and frontend running (see README → Quick start). You need two API keys
from `.env` (printed by `scripts/bootstrap_env.py`):

- the **analyst** key (`tfa_…`) to ingest and propose actions
- the **approver** key (`tfp_…`) to approve and execute

Open http://localhost:5173 and sign in with the **analyst** key.

## 1. Ingest a multi-stage intrusion

1. Go to **Alerts**.
2. In *Synthetic demo scenarios*, click **Load** on *Multi-stage intrusion: web server to database exfiltration*.
3. The banner reports 6 new alerts and one incident ID. Loading again reports them as duplicates (idempotent ingestion).

What happened per alert: validate → OCSF normalize → resolve entities → persist to Neo4j (if running) → historical context → threat-intel + CMDB/IAM enrichment → deterministic triage → guardrail evaluation of triage-proposed actions → audit event. Then the correlator linked the alerts into one incident.

## 2. Inspect one alert

Click the *Encoded PowerShell command line executed* alert.

- **Overview**: normalized fields, including the Windows process command line and the account from `eventdata`.
- **Deterministic triage**: each score contribution with points (base severity, privileged account, high-impact technique, asset criticality…), the sum, and the priority rule applied.
- **Threat intelligence**: per-indicator verdicts; unknown indicators show `UNKNOWN`, never "safe".
- **Pipeline & guardrails**: every LangGraph stage with status/timing, and the guardrail decision for the containment action triage proposed (`REQUIRE_APPROVAL`).
- **Raw & normalized**: the original alert, preserved verbatim.

## 3. Work the incident

Open the incident (button at the top of the alert, or **Incidents**).

- **Overview → Risk explanation**: max alert score + attack-progression bonus (6 distinct ATT&CK tactics). **Correlation basis** shows *why* each alert joined (same Wazuh agent, same internal host address for the lateral movement, confidence per link).
- **Timeline**: brute force → login → PowerShell → sudo → lateral SSH → large upload to `files.example.net`.
- **Graph**: incident, asset, identity, IOC, and TTP nodes. Click any edge to see `valid_from`, `confidence`, and `source`. The badge states whether the graph came from Neo4j or from per-alert resolution (when Neo4j is down).
- **Investigation summary → Generate (template)**: facts and hypotheses, each citing evidence IDs (hover a citation). *Generate with AI* is enabled only if an LLM provider is configured; its output is validated against the same evidence IDs.
- Set status to **INVESTIGATING** with a reason. Add a note.

## 4. Propose a response action

In **Response**:

1. Choose *Isolate host (simulated)*, target `db-server-01`, and give a rationale.
2. Submit. The guardrail returns `REQUIRE_APPROVAL` and the request appears with its expiry.
3. Notice that an analyst cannot decide it. Even an approver cannot approve their own proposal.

## 5. Approve and execute as a different person

1. Sign out (sidebar) and sign in with the **approver** key.
2. Go to **Response Approvals** (the sidebar badge shows the pending count).
3. **Review…** → enter a reason → **Approve**.
4. **Execute (simulated)**. The guardrail re-validates the stored action against the approved hash, then marks it `EXECUTED`. Executing again is refused (replay protection).
5. Optionally reject one of the triage-proposed containment requests instead.

## 6. Verify the audit trail

Go to **Audit Log**:

- Every step above has an event: ingestion/correlation, guardrail decisions, the human decision, the simulated execution, status changes, notes, narrative generation.
- **Verify now** recomputes the SHA-256 chain: "Chain intact: N events verified".

## 7. Export

Back in the incident, **Export JSON report** downloads the incident, its alerts with triage and enrichment, the approvals, the related audit events, and the chain-verification result.

## 8. Other scenarios

- **Workstation beaconing to known C2 indicator**: the threat-intel factor (`198.51.100.22` is MALICIOUS in the synthetic feed) appears in the score breakdown.
- **Benign activity and a likely false positive**: the package-update alert stays LOW with no incident (allow-listed mirror = BENIGN). The off-hours login opens a MEDIUM incident; close it as **FALSE_POSITIVE** with a reason.
- **Alert text containing prompt-injection strings**: the alert's description tells an AI to "ignore all safety rules". It is scored by rules only, and the text appears verbatim as evidence, never as an instruction.

## Automated replay

`cd dashboard && npm run test:e2e` runs steps 1–6 in headless Chrome against an isolated, throwaway stack (port 8010 API with a temporary SQLite file, port 5175 dashboard). It does not touch your demo data.

## Presenter notes

- Ten wrong API keys within 5 minutes lock out the client IP (429). Behind the Vite dev proxy every browser shares `127.0.0.1`, so a lockout affects everyone in the demo until `AUTH_LOCKOUT_SECONDS` passes. Paste keys carefully, or lower `AUTH_MAX_FAILURES` for rehearsal.
- Approvals expire after 30 minutes (`APPROVAL_TIMEOUT_SECONDS`). Older triage proposals show `EXPIRED`, which is expected and is itself a good talking point.

## Repeat from scratch

Data persists across restarts (PostgreSQL or SQLite). To reset the demo:

- PostgreSQL: `docker compose down -v && docker compose up -d` (**destroys** all local ThreatFusion data volumes, including Neo4j; only do this deliberately). Do **not** run `scripts/bootstrap_env.py --force` while volumes exist: it changes the database passwords.
- SQLite: stop the API and delete the file at `SQLITE_PATH`.
