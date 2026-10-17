"""
graph/client.py — Asynchronous Neo4j persistence client for ThreatFusion AI.

Provides secure, idempotent persistence of Phase 4 resolved entities, temporal
relationships, and graph investigation queries using the official Neo4j Python driver.
Adheres strictly to the ThreatFusion AI graph schema:
- Node labels: Asset, Identity, IOC, TTP, Incident
- Relationships: AFFECTS, INVOLVES, CONTACTED, USES, RESOLVED_BY
- Edge requirements: valid_from, valid_to (nullable), confidence, source
"""

from __future__ import annotations

import json
from typing import Any

from neo4j import AsyncDriver, AsyncGraphDatabase
from neo4j.exceptions import (
    AuthError,
    ConstraintError,
    DriverError,
    Neo4jError,
    ServiceUnavailable,
)

from core.config import AppSettings, get_settings
from core.health import ServiceHealth, ServiceStatus
from core.logger import get_logger
from graph.models import (
    EntityNode,
    EntityType,
    RelationshipEdge,
    RelationshipType,
    ResolutionResult,
)
from graph.resolver import EntityResolver
from normalization.models import OCSFSecurityFinding

logger = get_logger("graph.client")

# Strict whitelists to prevent Cypher injection on interpolated labels/types
VALID_NODE_LABELS = frozenset({e.value for e in EntityType})
VALID_REL_TYPES = frozenset({r.value for r in RelationshipType})


class GraphError(Exception):
    """Base exception for all graph persistence operations."""


class GraphConnectionError(GraphError):
    """Raised when connection or authentication to Neo4j fails."""


class GraphQueryError(GraphError):
    """Raised when a Cypher query execution fails."""


class GraphConstraintError(GraphQueryError):
    """Raised when a schema or uniqueness constraint violation occurs."""


def _sanitize_properties(props: dict[str, Any]) -> dict[str, Any]:
    """Sanitize properties so all values conform to Neo4j primitive/array constraints.

    Neo4j does not allow nested dictionaries as property values. Complex nested
    objects are serialized to JSON strings.
    """
    sanitized: dict[str, Any] = {}
    for k, v in props.items():
        if v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            sanitized[k] = v
        elif isinstance(v, (list, tuple)):
            if all(isinstance(item, (str, int, float, bool)) for item in v):
                sanitized[k] = list(v)
            else:
                sanitized[k] = json.dumps(v)
        elif isinstance(v, dict):
            sanitized[k] = json.dumps(v)
        else:
            sanitized[k] = str(v)
    return sanitized


class Neo4jClient:
    """Asynchronous Neo4j client managing schema, persistence, and graph queries.

    Features:
    - Secure connection initialization with production TLS enforcement.
    - Idempotent schema initialization (uniqueness constraints and indexes).
    - Idempotent node and relationship persistence using parameterized MERGE.
    - Temporal relationship tracking (valid_from, last_seen, valid_to, confidence, source).
    - Safe __repr__ omitting credentials.
    - Health reporting integrated with ServiceHealth model.
    """

    def __init__(
        self,
        settings: AppSettings | None = None,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str = "neo4j",
        timeout: float = 10.0,
        driver: AsyncDriver | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._uri = uri or self._settings.neo4j_uri
        self._user = user or self._settings.neo4j_user
        self._password = password or self._settings.neo4j_password
        self._database = database
        self._timeout = float(timeout)
        self._external_driver = driver is not None
        self._driver: AsyncDriver = driver or self._create_driver()

    def _create_driver(self) -> AsyncDriver:
        """Create and configure the official Neo4j AsyncDriver."""
        # Defense-in-depth: Reject unencrypted connection in production
        if self._settings.app_env == "production":
            is_secure_scheme = self._uri.startswith("neo4j+s://") or self._uri.startswith("bolt+s://")
            if not is_secure_scheme:
                raise GraphConnectionError(
                    f"Production environment rejects insecure Neo4j URI scheme: {self._uri!r}. "
                    "Must use neo4j+s:// or bolt+s:// with valid TLS certificates."
                )

        try:
            return AsyncGraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
                connection_timeout=self._timeout,
                max_connection_lifetime=3600,
            )
        except Exception as err:
            raise GraphConnectionError(f"Failed to create Neo4j driver: {err}") from err

    def __repr__(self) -> str:
        """Safe representation omitting database password."""
        return (
            f"<Neo4jClient uri={self._uri!r} "
            f"user={self._user!r} "
            f"database={self._database!r}>"
        )

    async def __aenter__(self) -> Neo4jClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Close driver and release connection pool."""
        if not self._external_driver:
            try:
                await self._driver.close()
            except Exception as err:
                logger.warning("neo4j_driver_close_error", error=str(err))

    async def verify_connectivity(self) -> bool:
        """Verify connectivity and authentication to the Neo4j cluster."""
        try:
            await self._driver.verify_connectivity()
            return True
        except (AuthError, ServiceUnavailable, DriverError) as err:
            raise GraphConnectionError(f"Neo4j connectivity check failed: {err}") from err
        except Exception as err:
            raise GraphConnectionError(f"Unexpected error during Neo4j connectivity check: {err}") from err

    async def check_health(self) -> ServiceHealth:
        """Check Neo4j health and return a typed ServiceHealth status."""
        try:
            await self._driver.verify_connectivity()
            async with self._driver.session(database=self._database) as session:
                result = await session.run("RETURN 1 AS ping")
                record = await result.single()
                if record and record.get("ping") == 1:
                    return ServiceHealth(
                        name="neo4j",
                        status=ServiceStatus.OK,
                        detail="Neo4j connection active and operational",
                    )
                return ServiceHealth(
                    name="neo4j",
                    status=ServiceStatus.DEGRADED,
                    detail="Neo4j reachable but ping query returned unexpected result",
                )
        except Exception as err:
            return ServiceHealth(
                name="neo4j",
                status=ServiceStatus.DOWN,
                detail=f"Neo4j unreachable: {err}",
            )

    # ── Schema & Constraints ─────────────────────────────────────────────────

    async def init_schema(self) -> None:
        """Idempotently initialize uniqueness constraints and performance indexes.

        Ensures that nodes of every entity label have a unique constraint on the 'id' property.
        """
        constraints = [
            ("asset_id_unique", "Asset", "id"),
            ("identity_id_unique", "Identity", "id"),
            ("ioc_id_unique", "IOC", "id"),
            ("ttp_id_unique", "TTP", "id"),
            ("incident_id_unique", "Incident", "id"),
        ]

        indexes = [
            ("asset_hostname_idx", "Asset", "hostname"),
            ("identity_username_idx", "Identity", "username"),
            ("ioc_ip_idx", "IOC", "ip"),
            ("ttp_tech_idx", "TTP", "technique_id"),
            ("incident_created_idx", "Incident", "created_time"),
        ]

        try:
            async with self._driver.session(database=self._database) as session:
                for c_name, label, prop in constraints:
                    query = f"CREATE CONSTRAINT {c_name} IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
                    await session.run(query)

                for idx_name, label, prop in indexes:
                    query = f"CREATE INDEX {idx_name} IF NOT EXISTS FOR (n:{label}) ON (n.{prop})"
                    await session.run(query)

            logger.info("neo4j_schema_initialized_successfully")
        except Exception as err:
            raise GraphQueryError(f"Failed to initialize Neo4j schema: {err}") from err

    # ── Entity & Relationship Persistence ────────────────────────────────────

    async def persist_entity(self, entity: EntityNode) -> dict[str, Any]:
        """Idempotently persist an EntityNode to Neo4j.

        Uses parameterized MERGE matching on canonical_id.
        Updates confidence with maximum-wins rule and deduplicates finding provenance.
        """
        label = entity.entity_type.value
        if label not in VALID_NODE_LABELS:
            raise GraphQueryError(f"Invalid entity label: {label!r}. Whitelist: {VALID_NODE_LABELS}")

        # Flatten identifiers into top-level properties prefixed with ident_ for direct index search
        combined_props = dict(entity.properties)
        for k, v in entity.identifiers.items():
            combined_props[f"ident_{k}"] = v

        sanitized_props = _sanitize_properties(combined_props)

        cypher = f"""
        MERGE (n:{label} {{id: $id}})
        ON CREATE SET
          n.name = $name,
          n.confidence = $confidence,
          n.source_findings = $source_findings,
          n.created_at = $created_at,
          n.updated_at = $updated_at,
          n += $properties
        ON MATCH SET
          n.name = COALESCE($name, n.name),
          n.confidence = CASE WHEN $confidence > n.confidence THEN $confidence ELSE n.confidence END,
          n.source_findings = reduce(acc = [], x IN (n.source_findings + $source_findings) | CASE WHEN x IN acc THEN acc ELSE acc + [x] END),
          n.updated_at = $updated_at,
          n += $properties
        RETURN n.id AS id, labels(n) AS labels
        """

        parameters = {
            "id": entity.canonical_id,
            "name": entity.name,
            "confidence": float(entity.confidence),
            "source_findings": list(entity.source_findings),
            "created_at": float(entity.created_at),
            "updated_at": float(entity.updated_at),
            "properties": sanitized_props,
        }

        try:
            async with self._driver.session(database=self._database) as session:
                result = await session.run(cypher, parameters)
                record = await result.single()
                if not record:
                    raise GraphQueryError(f"MERGE returned no record for entity {entity.canonical_id}")
                return {"id": record["id"], "labels": record["labels"]}
        except ConstraintError as err:
            raise GraphConstraintError(f"Constraint violation persisting entity {entity.canonical_id}: {err}") from err
        except Neo4jError as err:
            raise GraphQueryError(f"Cypher error persisting entity {entity.canonical_id}: {err}") from err
        except Exception as err:
            raise GraphQueryError(f"Unexpected failure persisting entity {entity.canonical_id}: {err}") from err

    async def persist_relationship(self, edge: RelationshipEdge) -> dict[str, Any]:
        """Idempotently persist an evidence-backed RelationshipEdge.

        Matches source and destination nodes by id.
        Preserves valid_from, updates last_seen, and applies confidence maximum-wins rule.
        """
        rel_type = edge.rel_type.value
        if rel_type not in VALID_REL_TYPES:
            raise GraphQueryError(f"Invalid relationship type: {rel_type!r}. Whitelist: {VALID_REL_TYPES}")

        sanitized_props = _sanitize_properties(edge.properties)

        cypher = f"""
        MATCH (src {{id: $source_id}})
        MATCH (dst {{id: $target_id}})
        MERGE (src)-[r:{rel_type}]->(dst)
        ON CREATE SET
          r.valid_from = $valid_from,
          r.last_seen = $valid_from,
          r.valid_to = $valid_to,
          r.confidence = $confidence,
          r.source = $source,
          r += $properties
        ON MATCH SET
          r.last_seen = $valid_from,
          r.confidence = CASE WHEN $confidence > r.confidence THEN $confidence ELSE r.confidence END,
          r += $properties
        RETURN type(r) AS rel_type, r.valid_from AS valid_from, r.last_seen AS last_seen
        """

        parameters = {
            "source_id": edge.source_id,
            "target_id": edge.target_id,
            "valid_from": edge.valid_from,
            "valid_to": edge.valid_to,
            "confidence": float(edge.confidence),
            "source": edge.source,
            "properties": sanitized_props,
        }

        try:
            async with self._driver.session(database=self._database) as session:
                result = await session.run(cypher, parameters)
                record = await result.single()
                if not record:
                    raise GraphQueryError(
                        f"Cannot persist relationship: missing endpoint node(s) for {edge.source_id} -> {edge.target_id}"
                    )
                return {
                    "rel_type": record["rel_type"],
                    "valid_from": record["valid_from"],
                    "last_seen": record["last_seen"],
                }
        except Neo4jError as err:
            raise GraphQueryError(f"Cypher error persisting edge {edge.source_id} -> {edge.target_id}: {err}") from err
        except Exception as err:
            raise GraphQueryError(f"Unexpected error persisting edge {edge.source_id} -> {edge.target_id}: {err}") from err

    async def persist_resolution_result(self, result: ResolutionResult) -> dict[str, int]:
        """Persist all entities and relationships in a ResolutionResult.

        Entities are persisted first to ensure relationship endpoints exist.
        """
        nodes_persisted = 0
        for entity in result.entities.values():
            await self.persist_entity(entity)
            nodes_persisted += 1

        edges_persisted = 0
        for edge in result.relationships:
            await self.persist_relationship(edge)
            edges_persisted += 1

        logger.info(
            "neo4j_persisted_resolution_result",
            nodes_count=nodes_persisted,
            edges_count=edges_persisted,
            conflicts_count=len(result.conflicts),
        )

        return {
            "nodes_persisted": nodes_persisted,
            "relationships_persisted": edges_persisted,
        }

    async def persist_finding(
        self,
        finding: OCSFSecurityFinding,
        resolver: EntityResolver | None = None,
    ) -> dict[str, int]:
        """Convenience pipeline: Resolve an OCSF finding and persist its graph representation."""
        res = resolver or EntityResolver()
        resolution_result = res.resolve_finding(finding)
        return await self.persist_resolution_result(resolution_result)

    # ── Graph Query & Investigation APIs ─────────────────────────────────────

    async def get_entity(self, canonical_id: str) -> dict[str, Any] | None:
        """Retrieve an entity node by its canonical ID."""
        cypher = "MATCH (n {id: $id}) RETURN n.id AS id, labels(n) AS labels, n.name AS name, properties(n) AS properties"
        try:
            async with self._driver.session(database=self._database) as session:
                result = await session.run(cypher, {"id": canonical_id})
                record = await result.single()
                if not record:
                    return None
                return {
                    "id": record["id"],
                    "labels": record["labels"],
                    "name": record["name"],
                    "properties": record["properties"],
                }
        except Exception as err:
            raise GraphQueryError(f"Failed to query entity {canonical_id}: {err}") from err

    async def get_entity_neighborhood(
        self,
        canonical_id: str,
        depth: int = 1,
    ) -> dict[str, Any]:
        """Retrieve an entity and its neighboring connected nodes up to bounded depth."""
        bounded_depth = max(1, min(depth, 3))
        cypher = f"""
        MATCH (center {{id: $id}})
        OPTIONAL MATCH path = (center)-[r*1..{bounded_depth}]-(neighbor)
        WITH center,
             collect(DISTINCT neighbor) AS neighbors,
             collect(DISTINCT relationships(path)) AS rel_batches
        RETURN center.id AS center_id,
               labels(center) AS center_labels,
               properties(center) AS center_props,
               [n IN neighbors | {{id: n.id, labels: labels(n), name: n.name, properties: properties(n)}}] AS neighbors,
               [batch IN rel_batches | [rel IN batch | {{
                 type: type(rel),
                 source: startNode(rel).id,
                 target: endNode(rel).id,
                 properties: properties(rel)
               }}]] AS relationships
        """

        try:
            async with self._driver.session(database=self._database) as session:
                result = await session.run(cypher, {"id": canonical_id})
                record = await result.single()
                if not record or record["center_id"] is None:
                    return {"center": None, "neighbors": [], "relationships": []}

                flat_rels: list[dict[str, Any]] = []
                for batch in record["relationships"]:
                    for rel in batch:
                        if rel not in flat_rels:
                            flat_rels.append(rel)

                return {
                    "center": {
                        "id": record["center_id"],
                        "labels": record["center_labels"],
                        "properties": record["center_props"],
                    },
                    "neighbors": record["neighbors"],
                    "relationships": flat_rels,
                }
        except Exception as err:
            raise GraphQueryError(f"Failed to query neighborhood for {canonical_id}: {err}") from err

    async def get_incident_subgraph(self, finding_uid: str) -> dict[str, Any]:
        """Retrieve the incident node and all connected contextual entities."""
        incident_id = f"finding:{finding_uid}"
        return await self.get_entity_neighborhood(incident_id, depth=1)

    async def run_query(
        self,
        cypher: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute an arbitrary parameterized read/write Cypher query."""
        try:
            async with self._driver.session(database=self._database) as session:
                result = await session.run(cypher, parameters or {})
                return [record.data() async for record in result]
        except Neo4jError as err:
            raise GraphQueryError(f"Cypher execution failed: {err}") from err
        except Exception as err:
            raise GraphQueryError(f"Unexpected query failure: {err}") from err

    async def clear_database(self, confirm: bool = False) -> None:
        """Delete all nodes and relationships (Test utility). Requires confirm=True."""
        if not confirm:
            raise GraphError("clear_database requires explicit confirm=True")
        try:
            async with self._driver.session(database=self._database) as session:
                await session.run("MATCH (n) DETACH DELETE n")
            logger.warning("neo4j_database_cleared")
        except Exception as err:
            raise GraphQueryError(f"Failed to clear database: {err}") from err
