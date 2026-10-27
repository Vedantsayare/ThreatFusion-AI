"""
tests/integration/test_neo4j_live.py — Live integration tests against local Neo4j.

Executes actual Cypher operations against the local Docker Neo4j instance if running.
Skips cleanly if Neo4j is unreachable, adhering to the project's testing conventions.
"""

from __future__ import annotations

import os

import pytest
from dotenv import dotenv_values

from graph.client import Neo4jClient
from graph.models import (
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationshipType,
)

pytestmark = pytest.mark.integration


def _get_live_credentials() -> tuple[str, str, str]:
    """Read live credentials from local .env without exposing in logs."""
    env_vals = dotenv_values(".env")
    uri = str(env_vals.get("NEO4J_URI") or os.getenv("NEO4J_URI") or "bolt://127.0.0.1:7687")
    user = str(env_vals.get("NEO4J_USER") or os.getenv("NEO4J_USER") or "neo4j")
    password = str(env_vals.get("NEO4J_PASSWORD") or os.getenv("NEO4J_PASSWORD") or "")
    return uri, user, password


@pytest.mark.asyncio
async def test_live_neo4j_connectivity_and_operations() -> None:
    """End-to-end integration test verifying schema, persistence, and queries against real Neo4j."""
    uri, user, password = _get_live_credentials()
    if not password:
        pytest.skip("No NEO4J_PASSWORD found in .env; skipping live integration test")

    client = Neo4jClient(uri=uri, user=user, password=password)
    try:
        await client.verify_connectivity()
    except Exception as err:
        pytest.skip(f"Live Neo4j instance at {uri} unreachable: {err}")

    try:
        # 1. Health check
        health = await client.check_health()
        assert health.status.value == "ok"

        # 2. Schema initialization (uniqueness constraints & indexes)
        await client.init_schema()

        # 3. Create test entities
        asset = EntityNode(
            canonical_id="test:asset:live-001",
            entity_type=EntityType.ASSET,
            name="live-integration-host",
            identifiers={"agent_id": "live-001", "hostname": "live-integration-host"},
            properties={"ip": "10.200.1.5", "environment": "integration-test"},
            confidence=1.0,
            source_findings=["live-find-001"],
        )

        incident = EntityNode(
            canonical_id="test:finding:live-001",
            entity_type=EntityType.INCIDENT,
            name="Live Integration Test Finding",
            identifiers={"finding_uid": "live-find-001"},
            properties={"severity": "High", "severity_id": 4},
            confidence=1.0,
            source_findings=["live-find-001"],
        )

        await client.persist_entity(asset)
        await client.persist_entity(incident)

        # 4. Create evidence-backed relationship
        edge = RelationshipEdge(
            source_id="test:finding:live-001",
            target_id="test:asset:live-001",
            rel_type=RelationshipType.AFFECTS,
            valid_from="2026-10-17T12:00:00Z",
            valid_to=None,
            confidence=1.0,
            source="live_integration_test",
            properties={"test_run": True},
        )
        edge_res = await client.persist_relationship(edge)
        assert edge_res["rel_type"] == "AFFECTS"

        # 5. Query and verify round-trip persistence
        queried = await client.get_entity("test:asset:live-001")
        assert queried is not None
        assert queried["id"] == "test:asset:live-001"
        assert "Asset" in queried["labels"]
        assert queried["name"] == "live-integration-host"

        # 6. Query neighborhood
        neighborhood = await client.get_entity_neighborhood("test:finding:live-001", depth=1)
        assert neighborhood["center"] is not None
        assert len(neighborhood["neighbors"]) >= 1
        neighbor_ids = [n["id"] for n in neighborhood["neighbors"]]
        assert "test:asset:live-001" in neighbor_ids

    finally:
        # Cleanup test artifacts
        try:
            await client.run_query("MATCH (n) WHERE n.id STARTS WITH 'test:' DETACH DELETE n")
        except Exception:
            pass
        await client.aclose()
