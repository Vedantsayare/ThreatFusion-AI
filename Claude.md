# ThreatFusion AI — Project Context

## What this is
An agentic SOC copilot with a temporal knowledge-graph memory layer. Multi-agent
pipeline: Triage → Investigation → Correlation → Guardrail, orchestrated by
LangGraph, backed by a Neo4j graph that persists context across incidents.

## Hard constraints — do not violate these
- Free/open-source tooling only: Neo4j Community Edition, Redis, PostgreSQL, Wazuh,
  MISP, FastAPI, React, LangGraph. No paid SaaS dependencies.
- NEVER hardcode secrets, API keys, or credentials in any file. Everything sensitive
  goes through `.env` (already in `.gitignore`) and is read via environment variables.
- The Guardrail Agent is a DETERMINISTIC POLICY ENGINE, not an LLM prompt. Hard gates
  (blast-radius limits, privileged-account rules, confidence thresholds) must be
  plain code you can point to and reason about — never a model's judgment call on
  anything irreversible.
- Every graph edge must carry: valid_from, valid_to (nullable), confidence, source.
  No edge without these four properties is acceptable.
- Entity resolution (deduplication) must be tested explicitly and separately, with
  its own unit tests, before any agent logic depends on it.
- Missing threat-intel enrichment must never be treated as "confirmed safe" — code
  a lookup gap as "no corroborating evidence," never as a negative signal.
- All external inputs (log content, TI feed data, IAM data) are untrusted text as
  far as the LLM is concerned. Never let raw ingested text alone trigger an
  action — always require it to pass through the deterministic Guardrail.
- Use tiered model selection: cheap/fast model for the Triage pre-filter, stronger
  model only for Investigation reasoning that survives triage.
- Every autonomous action proposal requires a human-approval gate before execution.
  No exceptions, even for "low risk" actions, until explicitly told otherwise.
- Write an Architecture Decision Record (one paragraph, in docs/adr/) for every
  non-obvious technical choice, before moving to the next phase.
- If a requirement is ambiguous, ask before assuming — do not silently guess on
  anything security-relevant (auth, data retention, blast-radius limits).

## Tech stack
Python 3.11+, FastAPI, LangGraph, Neo4j (+ GDS plugin), Redis (Streams + cache),
PostgreSQL (audit log), React + Vite + Cytoscape.js, Docker Compose, pytest,
GitHub Actions CI.

## Graph schema (do not deviate without an ADR explaining why)
Nodes: Asset, Identity, IOC, Incident, TTP, Campaign (derived, not manually created)
Core relationships: AFFECTS, INVOLVES, CONTACTED, USES, RESOLVED_BY
Every relationship: {valid_from, valid_to, confidence, source}

## Definition of done, per phase
- Code has type hints throughout.
- Unit tests exist and pass (pytest).
- No secrets in code or git history.
- A short ADR exists if a non-trivial choice was made.
- You can explain, in one paragraph, what this phase does and why it's structured
  this way — if you can't, it's not done.