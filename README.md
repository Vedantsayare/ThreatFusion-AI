# ThreatFusion AI

> **Agentic SOC copilot with a temporal knowledge-graph memory layer.**

A multi-agent security investigation and SOC automation platform:  
`Triage → Investigation → Correlation → Guardrail`, orchestrated by LangGraph,  
backed by a Neo4j graph that persists context across incidents.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, uvicorn |
| Agents | LangGraph, langchain-core |
| Alert source | Wazuh (existing Ubuntu VM) |
| Normalization | OCSF Security Finding schema |
| Graph DB | Neo4j 5 Community |
| Relational DB | PostgreSQL 16 |
| Cache / Queue | Redis 7 (Streams) |
| Threat Intel | MISP |
| Frontend | React + Vite + Cytoscape.js |
| Tests | pytest + pytest-asyncio |
| Containers | Docker Compose |

---

## Prerequisites

| Tool | Version |
|---|---|
| Python | ≥ 3.12 |
| Docker Desktop | ≥ 4.28 (or Docker Engine ≥ 26) |
| Docker Compose | ≥ v2.27 |
| Node.js | ≥ 20 (frontend only) |

---

## Quick Start — Windows (PowerShell)

### 1. Clone and enter the project

```powershell
cd D:\Project\ThreatFusion-AI
```

### 2. Create and activate the virtual environment

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 3. Install Python dependencies (dev extras)

```powershell
pip install -e ".[dev]"
```

### 4. Configure environment variables

```powershell
Copy-Item .env.example .env
# Then open .env in your editor and fill in all REPLACE_WITH_* values.
notepad .env
```

> **Never commit `.env` to git.** It is listed in `.gitignore`.

### 5. Start infrastructure services

```powershell
docker compose up -d
```

Wait ~60 s for Neo4j to finish its JVM startup, then verify:

```powershell
docker compose ps
# All three services should show status: healthy
```

### 6. Run the test suite

```powershell
pytest
```

---

## Project Structure

```text
ThreatFusion-AI/
├── core/           Shared config, logging, health models
├── ingestion/      Wazuh alert poller (Phase 2)
├── normalization/  OCSF mapper and entity resolution (Phase 3)
├── graph/          Neo4j temporal knowledge graph (Phases 1, 4)
├── agents/         Triage, Investigation, Correlation, Guardrail agents (Phases 6-7)
├── orchestrator/   LangGraph state and workflow (Phase 7)
├── api/            FastAPI application (Phase 9)
├── dashboard/      React + Vite + Cytoscape.js (Phase 10)
├── simulation/     Synthetic attack scenarios for testing
├── tests/          pytest unit and integration tests
└── docs/adr/       Architecture Decision Records
```

---

## Implementation Phases

| Phase | Milestone |
|---|---|
| **0** ✅ | Baseline setup, config, logging, test harness, Docker Compose |
| 1 | PostgreSQL schema + Neo4j constraints + Cypher query layer |
| 2 | Wazuh ingestion (live VM + mock fallback) |
| 3 | OCSF normalization + entity resolution (unit tested in isolation) |
| 4 | Temporal Neo4j ingestion |
| 5 | MISP + IAM/CMDB enrichment |
| 6 | Deterministic guardrail engine (plain Python, no LLM) |
| 7 | LangGraph multi-agent orchestrator |
| 8 | Human-in-the-loop approval queue |
| 9 | FastAPI REST + WebSocket backend |
| 10 | React dashboard + end-to-end simulation |

---

## Security Constraints

- All secrets live in `.env` only — never committed to git.
- The Guardrail Agent is **deterministic Python code**, not an LLM.
- Every consequential action requires **human approval** before execution.
- Missing threat-intel is coded as `UNKNOWN`, never as `safe`.
- All external queries use parameterized SQL and safe parameterized Cypher.
- The `safe_summary()` method on `AppSettings` is the only approved way to log configuration.

---

## Running Tests

```powershell
# Run all unit tests (no live services required)
pytest tests/unit/

# Run with coverage report
pytest tests/unit/ --cov=core --cov-report=term-missing

# Run integration tests (requires Docker services running)
pytest tests/integration/ -m integration
```

---

## Architecture Decision Records

Every non-obvious technical choice is documented in [`docs/adr/`](docs/adr/).  
See [ADR-0000](docs/adr/0000-infrastructure-baseline.md) for Phase 0 infrastructure decisions.
