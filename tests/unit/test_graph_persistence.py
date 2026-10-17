"""
tests/unit/test_graph_persistence.py — Unit tests for Neo4j persistence client.

Tests use mocked AsyncDriver and AsyncSession to verify:
- Connection settings, safe __repr__, and production TLS security enforcement.
- Driver lifecycle and cleanup.
- Connectivity verification and health reporting.
- Schema constraint and index initialization.
- Idempotent entity and relationship persistence via parameterized MERGE.
- Temporal edge property preservation and update rules.
- Handling of missing nodes, query failures, and constraint violations.
- Safe parameterization of untrusted/malicious telemetry strings.
- Graph investigation queries and neighborhood retrieval.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from core.config import AppSettings
from core.health import ServiceStatus
from graph.client import (
    GraphConnectionError,
    GraphConstraintError,
    GraphError,
    GraphQueryError,
    Neo4jClient,
)
from graph.models import (
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationshipType,
    ResolutionResult,
)


def _make_settings(**kwargs: Any) -> AppSettings:
    """Helper to instantiate AppSettings with dev defaults."""
    env = {
        "APP_ENV": "development",
        "SECRET_KEY": "prod-secret-safe-key-length-minimum-32",
        "WAZUH_API_URL": "https://127.0.0.1:55000",
        "WAZUH_API_USER": "wazuh",
        "WAZUH_API_PASSWORD": "prod-wazuh-safe",
        "POSTGRES_PASSWORD": "prod-postgres-safe",
        "REDIS_PASSWORD": "prod-redis-safe",
        "NEO4J_URI": "bolt://localhost:7687",
        "NEO4J_USER": "neo4j",
        "NEO4J_PASSWORD": "prod-neo4j-safe",
        "MISP_URL": "https://127.0.0.1",
        "MISP_API_KEY": "prod-misp-safe",
        "LLM_API_KEY": "prod-llm-safe",
        "WAZUH_VERIFY_SSL": "true",
        "MISP_VERIFY_SSL": "true",
    }
    env.update(kwargs)
    return AppSettings(**env)  # type: ignore[arg-type]


class AsyncMockRecord:
    """Mock record mimicking neo4j.Record with .data() and __getitem__ support."""

    def __init__(self, data_dict: dict[str, Any]) -> None:
        self._data = data_dict

    def data(self) -> dict[str, Any]:
        return self._data

    def get(self, key: str, default: Any = None) -> Any:
        return self._data.get(key, default)

    def __getitem__(self, key: str) -> Any:
        return self._data[key]


class AsyncMockResult:
    """Mock result mimicking neo4j.AsyncResult with single() and async iteration."""

    def __init__(self, records: list[dict[str, Any]] | None = None) -> None:
        self._records = [AsyncMockRecord(r) for r in (records or [])]
        self._index = 0

    async def single(self) -> AsyncMockRecord | None:
        return self._records[0] if self._records else None

    def __aiter__(self) -> AsyncMockResult:
        self._index = 0
        return self

    async def __anext__(self) -> AsyncMockRecord:
        if self._index < len(self._records):
            rec = self._records[self._index]
            self._index += 1
            return rec
        raise StopAsyncIteration


@pytest.fixture
def mock_driver() -> AsyncMock:
    driver = AsyncMock()
    driver.verify_connectivity = AsyncMock(return_value=None)
    driver.close = AsyncMock(return_value=None)

    # Session mock setup
    session = AsyncMock()
    session.run = AsyncMock(return_value=AsyncMockResult([{"ping": 1}]))
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)

    driver.session = MagicMock(return_value=session)
    return driver


class TestNeo4jClientInit:
    """Tests client initialization, representation, and production security guards."""

    def test_safe_repr_omits_password(self) -> None:
        client = Neo4jClient(
            uri="bolt://127.0.0.1:7687",
            user="soc_analyst",
            password="ultra-secret-password-12345",
            driver=AsyncMock(),
        )
        repr_str = repr(client)
        assert "soc_analyst" in repr_str
        assert "bolt://127.0.0.1:7687" in repr_str
        assert "ultra-secret-password" not in repr_str

    def test_production_rejects_insecure_bolt_scheme(self) -> None:
        prod_settings = _make_settings(APP_ENV="production")
        with pytest.raises(GraphConnectionError, match="Production environment rejects insecure Neo4j URI"):
            Neo4jClient(settings=prod_settings, uri="bolt://neo4j.corp.internal:7687")

    def test_production_accepts_secure_tls_scheme(self) -> None:
        prod_settings = _make_settings(APP_ENV="production")
        mock_drv = AsyncMock()
        client = Neo4jClient(
            settings=prod_settings,
            uri="neo4j+s://neo4j.corp.internal:7687",
            driver=mock_drv,
        )
        assert client is not None

    @pytest.mark.asyncio
    async def test_aclose_releases_driver(self, mock_driver: AsyncMock) -> None:
        # Create client without external driver flag to test internal close
        client = Neo4jClient(driver=mock_driver)
        client._external_driver = False  # simulate owned driver
        await client.aclose()
        mock_driver.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_context_manager_cleanup(self, mock_driver: AsyncMock) -> None:
        client = Neo4jClient(driver=mock_driver)
        client._external_driver = False
        async with client:
            pass
        mock_driver.close.assert_awaited_once()


class TestNeo4jConnectivityAndHealth:
    """Tests connectivity verification and service health checks."""

    @pytest.mark.asyncio
    async def test_verify_connectivity_success(self, mock_driver: AsyncMock) -> None:
        client = Neo4jClient(driver=mock_driver)
        is_connected = await client.verify_connectivity()
        assert is_connected is True
        mock_driver.verify_connectivity.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_verify_connectivity_failure_raises_graph_connection_error(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        mock_driver.verify_connectivity = AsyncMock(side_effect=Exception("Connection refused"))
        client = Neo4jClient(driver=mock_driver)
        with pytest.raises(GraphConnectionError, match="Connection refused"):
            await client.verify_connectivity()

    @pytest.mark.asyncio
    async def test_check_health_reports_ok(self, mock_driver: AsyncMock) -> None:
        client = Neo4jClient(driver=mock_driver)
        health = await client.check_health()
        assert health.status == ServiceStatus.OK
        assert "operational" in health.detail

    @pytest.mark.asyncio
    async def test_check_health_reports_down_on_failure(self, mock_driver: AsyncMock) -> None:
        mock_driver.verify_connectivity = AsyncMock(side_effect=Exception("Database down"))
        client = Neo4jClient(driver=mock_driver)
        health = await client.check_health()
        assert health.status == ServiceStatus.DOWN
        assert "Database down" in health.detail


class TestSchemaConstraintsAndIndexes:
    """Tests schema initialization and constraint execution."""

    @pytest.mark.asyncio
    async def test_init_schema_creates_constraints_and_indexes(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        client = Neo4jClient(driver=mock_driver)
        await client.init_schema()

        session = mock_driver.session()
        # 5 constraints + 5 indexes = 10 calls to session.run
        assert session.run.call_count == 10

        # Verify calls use IF NOT EXISTS
        for call_args in session.run.call_args_list:
            query = call_args[0][0]
            assert "IF NOT EXISTS" in query


class TestEntityPersistence:
    """Tests idempotent node persistence with parameterized queries."""

    @pytest.mark.asyncio
    async def test_persist_asset_entity(self, mock_driver: AsyncMock) -> None:
        session = mock_driver.session()
        session.run = AsyncMock(
            return_value=AsyncMockResult([{"id": "asset:agent:001", "labels": ["Asset"]}])
        )

        client = Neo4jClient(driver=mock_driver)
        asset = EntityNode(
            canonical_id="asset:agent:001",
            entity_type=EntityType.ASSET,
            name="web-server-01",
            identifiers={"agent_id": "001", "hostname": "web-server-01"},
            properties={"ip": "192.168.1.50", "role": "web"},
            confidence=1.0,
            source_findings=["find-1"],
        )

        result = await client.persist_entity(asset)
        assert result["id"] == "asset:agent:001"
        assert result["labels"] == ["Asset"]

        # Verify Cypher query and parameters
        call_args = session.run.call_args
        cypher = call_args[0][0]
        params = call_args[0][1]

        assert "MERGE (n:Asset {id: $id})" in cypher
        assert params["id"] == "asset:agent:001"
        assert params["name"] == "web-server-01"
        assert params["confidence"] == 1.0
        assert params["source_findings"] == ["find-1"]
        assert params["properties"]["ip"] == "192.168.1.50"
        assert params["properties"]["ident_agent_id"] == "001"

    @pytest.mark.asyncio
    async def test_untrusted_injection_strings_are_parameterized(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        session = mock_driver.session()
        session.run = AsyncMock(
            return_value=AsyncMockResult([{"id": "identity:user:admin", "labels": ["Identity"]}])
        )

        client = Neo4jClient(driver=mock_driver)
        malicious_user = EntityNode(
            canonical_id="identity:user:admin",
            entity_type=EntityType.IDENTITY,
            name="admin'; MATCH (n) DETACH DELETE n; //",
            identifiers={"username": "admin"},
            properties={"malicious_attr": "<script>alert('xss')</script>"},
            confidence=0.9,
            source_findings=["find-injection"],
        )

        await client.persist_entity(malicious_user)

        call_args = session.run.call_args
        cypher = call_args[0][0]
        params = call_args[0][1]

        # Query must be clean Cypher template without concatenated strings
        assert "DETACH DELETE" not in cypher
        assert "<script>" not in cypher

        # Malicious string is safely contained inside the parameters dictionary
        assert params["name"] == "admin'; MATCH (n) DETACH DELETE n; //"
        assert params["properties"]["malicious_attr"] == "<script>alert('xss')</script>"

    @pytest.mark.asyncio
    async def test_invalid_label_raises_graph_query_error(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        client = Neo4jClient(driver=mock_driver)
        corrupted_entity = MagicMock(spec=EntityNode)
        corrupted_entity.entity_type = MagicMock()
        corrupted_entity.entity_type.value = "HackedLabel"

        with pytest.raises(GraphQueryError, match="Invalid entity label"):
            await client.persist_entity(corrupted_entity)

    @pytest.mark.asyncio
    async def test_constraint_violation_raises_graph_constraint_error(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        from neo4j.exceptions import ConstraintError

        session = mock_driver.session()
        session.run = AsyncMock(side_effect=ConstraintError("Simulated constraint violation"))

        client = Neo4jClient(driver=mock_driver)
        asset = EntityNode(
            canonical_id="asset:agent:001",
            entity_type=EntityType.ASSET,
            name="web-server-01",
        )
        with pytest.raises(GraphConstraintError, match="Constraint violation"):
            await client.persist_entity(asset)


class TestRelationshipPersistence:
    """Tests idempotent relationship persistence with temporal attributes."""

    @pytest.mark.asyncio
    async def test_persist_affects_relationship(self, mock_driver: AsyncMock) -> None:
        session = mock_driver.session()
        session.run = AsyncMock(
            return_value=AsyncMockResult([{
                "rel_type": "AFFECTS",
                "valid_from": "2026-10-17T12:00:00Z",
                "last_seen": "2026-10-17T12:00:00Z",
            }])
        )

        client = Neo4jClient(driver=mock_driver)
        edge = RelationshipEdge(
            source_id="finding:find-1",
            target_id="asset:agent:001",
            rel_type=RelationshipType.AFFECTS,
            valid_from="2026-10-17T12:00:00Z",
            valid_to=None,
            confidence=1.0,
            source="wazuh",
            properties={"action": "brute_force_detected"},
        )

        res = await client.persist_relationship(edge)
        assert res["rel_type"] == "AFFECTS"
        assert res["valid_from"] == "2026-10-17T12:00:00Z"

        call_args = session.run.call_args
        cypher = call_args[0][0]
        params = call_args[0][1]

        assert "MERGE (src)-[r:AFFECTS]->(dst)" in cypher
        assert params["source_id"] == "finding:find-1"
        assert params["target_id"] == "asset:agent:001"
        assert params["valid_from"] == "2026-10-17T12:00:00Z"
        assert params["valid_to"] is None
        assert params["confidence"] == 1.0
        assert params["source"] == "wazuh"
        assert params["properties"]["action"] == "brute_force_detected"

    @pytest.mark.asyncio
    async def test_persist_relationship_missing_nodes_raises_graph_query_error(
        self,
        mock_driver: AsyncMock,
    ) -> None:
        session = mock_driver.session()
        # Empty result simulates missing source or target node
        session.run = AsyncMock(return_value=AsyncMockResult([]))

        client = Neo4jClient(driver=mock_driver)
        edge = RelationshipEdge(
            source_id="non-existent-source",
            target_id="non-existent-target",
            rel_type=RelationshipType.CONTACTED,
            valid_from="2026-10-17T12:00:00Z",
        )

        with pytest.raises(GraphQueryError, match="missing endpoint node"):
            await client.persist_relationship(edge)


class TestResolutionResultBatchPersistence:
    """Tests persisting full ResolutionResult batches."""

    @pytest.mark.asyncio
    async def test_persist_resolution_result(self, mock_driver: AsyncMock) -> None:
        session = mock_driver.session()
        # Mock successful node and edge returns
        session.run = AsyncMock(
            side_effect=[
                AsyncMockResult([{"id": "asset:agent:001", "labels": ["Asset"]}]),
                AsyncMockResult([{"id": "finding:find-1", "labels": ["Incident"]}]),
                AsyncMockResult([{"rel_type": "AFFECTS", "valid_from": "2026-10-17T12:00:00Z", "last_seen": "2026-10-17T12:00:00Z"}]),
            ]
        )

        client = Neo4jClient(driver=mock_driver)

        asset = EntityNode(
            canonical_id="asset:agent:001",
            entity_type=EntityType.ASSET,
            name="web-01",
        )
        incident = EntityNode(
            canonical_id="finding:find-1",
            entity_type=EntityType.INCIDENT,
            name="SSH Alert",
        )
        edge = RelationshipEdge(
            source_id="finding:find-1",
            target_id="asset:agent:001",
            rel_type=RelationshipType.AFFECTS,
            valid_from="2026-10-17T12:00:00Z",
        )

        res_result = ResolutionResult(
            entities={"asset:agent:001": asset, "finding:find-1": incident},
            relationships=[edge],
        )

        counts = await client.persist_resolution_result(res_result)
        assert counts["nodes_persisted"] == 2
        assert counts["relationships_persisted"] == 1


class TestInvestigationQueries:
    """Tests graph lookup and neighborhood retrieval APIs."""

    @pytest.mark.asyncio
    async def test_get_entity_found(self, mock_driver: AsyncMock) -> None:
        session = mock_driver.session()
        session.run = AsyncMock(
            return_value=AsyncMockResult([{
                "id": "asset:agent:001",
                "labels": ["Asset"],
                "name": "web-server-01",
                "properties": {"ip": "192.168.1.50"},
            }])
        )

        client = Neo4jClient(driver=mock_driver)
        entity = await client.get_entity("asset:agent:001")
        assert entity is not None
        assert entity["id"] == "asset:agent:001"
        assert entity["labels"] == ["Asset"]

    @pytest.mark.asyncio
    async def test_get_entity_not_found(self, mock_driver: AsyncMock) -> None:
        session = mock_driver.session()
        session.run = AsyncMock(return_value=AsyncMockResult([]))

        client = Neo4jClient(driver=mock_driver)
        entity = await client.get_entity("missing:id")
        assert entity is None

    @pytest.mark.asyncio
    async def test_clear_database_requires_confirmation(self, mock_driver: AsyncMock) -> None:
        client = Neo4jClient(driver=mock_driver)
        with pytest.raises(GraphError, match="clear_database requires explicit confirm=True"):
            await client.clear_database(confirm=False)
