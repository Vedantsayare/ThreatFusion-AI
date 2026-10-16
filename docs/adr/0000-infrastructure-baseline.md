# ADR-0000 — Infrastructure Baseline

**Date**: 2026-10-16  
**Status**: Accepted  
**Authors**: ThreatFusion AI project

---

## Context

Phase 0 establishes the foundational infrastructure for ThreatFusion AI.  
We need three persistence/messaging services before any application logic is written:  

| Need | Service |
|---|---|
| Relational store — alerts, audit logs, approvals | PostgreSQL |
| Fast cache and message stream | Redis |
| Security knowledge graph | Neo4j |

These choices are constrained by the project mandate: **free/open-source tooling only**.

---

## Decision 1 — PostgreSQL 16 for relational persistence

Chosen for:  
- ACID compliance and mature async Python support (`asyncpg` + SQLAlchemy 2.0 async).  
- Native JSONB columns for storing raw OCSF payloads alongside typed columns.  
- `AUDIT` trigger support for tamper-evident audit trails.  

**Alternatives considered**: MySQL — similar capability, but PostgreSQL's JSONB and `pg_audit` ecosystem better fit a SOC use case.

---

## Decision 2 — Redis 7 (Streams + AOF persistence)

Redis Streams provide ordered, consumer-group message delivery that is a better fit than a full message broker (RabbitMQ/Kafka) at this project scale.  
AOF (append-only file) persistence is enabled so alert streams survive a container restart.  
A password is required via `--requirepass`; no unauthenticated Redis is acceptable even in development.

**Alternatives considered**: RabbitMQ — would add complexity without providing meaningful capability improvements at Phase 0–5 alert volumes.

---

## Decision 3 — Neo4j 5 Community Edition

Community Edition is the only free-licensed Neo4j tier. It lacks hot standby and multi-database features, which are not required at this stage.  
All Cypher queries will be written using parameterized queries to prevent injection.  
Every relationship carries `{valid_from, valid_to, confidence, source}` as enforced by the schema — this is a hard constraint from `Claude.md` and cannot be relaxed without a new ADR.

**Alternatives considered**: Amazon Neptune, TigerGraph — both require SaaS or proprietary licences.

---

## Decision 4 — Python 3.12 + Pydantic Settings v2

Python 3.12 is the installed runtime. Pydantic v2 provides type-safe, validated configuration loading with `repr=False` on secret fields to prevent accidental leakage in log output or REPL `repr()` calls.

---

## Decision 5 — structlog for structured JSON logging

structlog produces machine-readable JSON log lines at all levels, making future log-aggregation (ELK/Loki) trivial. All events must carry `timestamp` and `level`.  
**Constraint enforced here**: `safe_summary()` on `AppSettings` is the only approved way to log configuration state — it explicitly excludes all secret fields.

---

## Consequences

- All developer workstations must have Docker Desktop (or Engine) installed.  
- The `.env` file is the single source of truth for all credentials; it is excluded from git via `.gitignore`.  
- Port collisions: if `5432`, `6379`, or `7474/7687` are in use on the host, the corresponding `POSTGRES_PORT`/`REDIS_PORT` env vars must be changed before starting Docker Compose.  
- Neo4j takes 30–60 s to reach healthy state due to JVM startup; health checks accommodate this with a 60 s `start_period`.
