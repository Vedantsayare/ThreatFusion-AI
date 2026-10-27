"""
api/persistence.py — Durable relational persistence (PostgreSQL or SQLite).

Stores JSON documents for alerts (workflow outputs), incidents, approval
requests, and the hash-chained audit log. The schema is created idempotently
at startup (``CREATE TABLE IF NOT EXISTS``); see docs/ARCHITECTURE.md.

Write path: the in-memory working set in api.store is authoritative for reads;
every mutation is written through to the database before the HTTP response is
returned, so a restart reloads exactly what clients were told was saved.
Writes are serialized with a lock so audit rows land in chain order.

Backends:
- postgres — asyncpg via SQLAlchemy async (docker-compose service)
- sqlite   — aiosqlite single-file database (no Docker needed)
- memory   — NullRepository; nothing survives a restart (tests / explicit opt-in)
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Protocol

from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from core.health import ServiceHealth, ServiceStatus
from core.logger import get_logger

logger = get_logger("api.persistence")

metadata = MetaData()

alerts_table = Table(
    "tf_alerts",
    metadata,
    Column("alert_id", String(128), primary_key=True),
    Column("fingerprint", String(128), nullable=False, index=True),
    Column("incident_id", String(64), nullable=True, index=True),
    Column("payload", Text, nullable=False),
    Column("created_at", Float, nullable=False),
    Column("updated_at", Float, nullable=False),
)

incidents_table = Table(
    "tf_incidents",
    metadata,
    Column("incident_id", String(64), primary_key=True),
    Column("payload", Text, nullable=False),
    Column("updated_at", Float, nullable=False),
)

approvals_table = Table(
    "tf_approvals",
    metadata,
    Column("request_id", String(64), primary_key=True),
    Column("payload", Text, nullable=False),
    Column("updated_at", Float, nullable=False),
)

audit_table = Table(
    "tf_audit_events",
    metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(64), nullable=False, unique=True),
    Column("event_hash", String(64), nullable=False),
    Column("prev_event_hash", String(64), nullable=False),
    Column("payload", Text, nullable=False),
)


class Repository(Protocol):
    backend: str

    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def check_health(self) -> ServiceHealth: ...
    async def upsert_alert(self, alert_id: str, fingerprint: str, incident_id: str | None, payload: dict[str, Any]) -> None: ...
    async def upsert_incident(self, incident_id: str, payload: dict[str, Any]) -> None: ...
    async def upsert_approval(self, request_id: str, payload: dict[str, Any]) -> None: ...
    async def append_audit(self, event: dict[str, Any]) -> None: ...
    async def load_all(self) -> dict[str, list[dict[str, Any]]]: ...


class NullRepository:
    """No durable storage. Health reports this honestly as degraded."""

    backend = "memory"

    async def start(self) -> None:
        return None

    async def close(self) -> None:
        return None

    async def check_health(self) -> ServiceHealth:
        return ServiceHealth(
            name="persistence",
            status=ServiceStatus.DEGRADED,
            detail="In-memory only: data is lost on restart (PERSISTENCE_BACKEND=memory)",
        )

    async def upsert_alert(self, alert_id: str, fingerprint: str, incident_id: str | None, payload: dict[str, Any]) -> None:
        return None

    async def upsert_incident(self, incident_id: str, payload: dict[str, Any]) -> None:
        return None

    async def upsert_approval(self, request_id: str, payload: dict[str, Any]) -> None:
        return None

    async def append_audit(self, event: dict[str, Any]) -> None:
        return None

    async def load_all(self) -> dict[str, list[dict[str, Any]]]:
        return {"alerts": [], "incidents": [], "approvals": [], "audit": []}


class SQLRepository:
    """SQLAlchemy-async repository for PostgreSQL or SQLite."""

    def __init__(self, url: str, backend: str) -> None:
        self.backend = backend
        self._url = url
        self._engine: AsyncEngine | None = None
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        self._engine = create_async_engine(self._url, pool_pre_ping=True)
        async with self._engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        logger.info("persistence_started", backend=self.backend)

    async def close(self) -> None:
        if self._engine is not None:
            await self._engine.dispose()

    @property
    def engine(self) -> AsyncEngine:
        if self._engine is None:
            raise RuntimeError("Repository not started")
        return self._engine

    async def check_health(self) -> ServiceHealth:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(select(1))
            return ServiceHealth(name="persistence", status=ServiceStatus.OK, detail=f"{self.backend} reachable")
        except Exception as err:
            return ServiceHealth(
                name="persistence",
                status=ServiceStatus.DOWN,
                detail=f"{self.backend} unreachable: {type(err).__name__}",
            )

    async def _upsert(self, table: Table, key_col: str, key: str, values: dict[str, Any]) -> None:
        async with self._lock, self.engine.begin() as conn:
            key_column = table.c[key_col]
            result = await conn.execute(update(table).where(key_column == key).values(**values))
            if result.rowcount == 0:
                await conn.execute(insert(table).values(**{key_col: key, **values}))

    async def upsert_alert(self, alert_id: str, fingerprint: str, incident_id: str | None, payload: dict[str, Any]) -> None:
        now = time.time()
        values = {
            "fingerprint": fingerprint,
            "incident_id": incident_id,
            "payload": json.dumps(payload, default=str),
            "updated_at": now,
        }
        async with self._lock, self.engine.begin() as conn:
            result = await conn.execute(
                update(alerts_table).where(alerts_table.c.alert_id == alert_id).values(**values)
            )
            if result.rowcount == 0:
                await conn.execute(insert(alerts_table).values(alert_id=alert_id, created_at=now, **values))

    async def upsert_incident(self, incident_id: str, payload: dict[str, Any]) -> None:
        await self._upsert(
            incidents_table,
            "incident_id",
            incident_id,
            {"payload": json.dumps(payload, default=str), "updated_at": time.time()},
        )

    async def upsert_approval(self, request_id: str, payload: dict[str, Any]) -> None:
        await self._upsert(
            approvals_table,
            "request_id",
            request_id,
            {"payload": json.dumps(payload, default=str), "updated_at": time.time()},
        )

    async def append_audit(self, event: dict[str, Any]) -> None:
        async with self._lock, self.engine.begin() as conn:
            await conn.execute(
                insert(audit_table).values(
                    event_id=event["event_id"],
                    event_hash=event["event_hash"],
                    prev_event_hash=event["prev_event_hash"],
                    payload=json.dumps(event, default=str),
                )
            )

    async def load_all(self) -> dict[str, list[dict[str, Any]]]:
        async with self.engine.connect() as conn:
            alerts = (await conn.execute(select(alerts_table).order_by(alerts_table.c.created_at))).mappings().all()
            incidents = (await conn.execute(select(incidents_table))).mappings().all()
            approvals = (await conn.execute(select(approvals_table))).mappings().all()
            audit = (await conn.execute(select(audit_table).order_by(audit_table.c.seq))).mappings().all()
        return {
            "alerts": [
                {"fingerprint": r["fingerprint"], "incident_id": r["incident_id"], **json.loads(r["payload"])}
                for r in alerts
            ],
            "incidents": [json.loads(r["payload"]) for r in incidents],
            "approvals": [json.loads(r["payload"]) for r in approvals],
            "audit": [json.loads(r["payload"]) for r in audit],
        }


def build_repository(backend: str, postgres_dsn: str, sqlite_path: str) -> Repository:
    """Create the repository for the configured backend."""
    if backend == "postgres":
        return SQLRepository(postgres_dsn, backend="postgres")
    if backend == "sqlite":
        return SQLRepository(f"sqlite+aiosqlite:///{sqlite_path}", backend="sqlite")
    return NullRepository()
