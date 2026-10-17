"""
graph/models.py — Graph entity and relationship models for entity resolution.

Defines typed Pydantic models for graph nodes (Asset, Identity, IOC, TTP, Incident)
and temporal edges conforming to the ThreatFusion AI graph schema.
Prepared for future Neo4j graph ingestion without implementing persistence in this phase.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EntityType(str, Enum):
    """Canonical node labels in the ThreatFusion AI knowledge graph."""

    ASSET = "Asset"
    IDENTITY = "Identity"
    IOC = "IOC"
    TTP = "TTP"
    INCIDENT = "Incident"


class RelationshipType(str, Enum):
    """Core relationship types in the ThreatFusion AI knowledge graph."""

    AFFECTS = "AFFECTS"
    INVOLVES = "INVOLVES"
    CONTACTED = "CONTACTED"
    USES = "USES"
    RESOLVED_BY = "RESOLVED_BY"


class EntityNode(BaseModel):
    """Resolved graph entity node with canonical identifier and provenance."""

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
        validate_assignment=True,
    )

    canonical_id: str
    entity_type: EntityType
    name: str
    identifiers: dict[str, str] = Field(default_factory=dict)
    properties: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source_findings: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    def to_graph_dict(self) -> dict[str, Any]:
        """Serialize node representation suitable for Neo4j Cypher parameterization."""
        return {
            "id": self.canonical_id,
            "label": self.entity_type.value,
            "name": self.name,
            "identifiers": self.identifiers,
            "properties": self.properties,
            "confidence": self.confidence,
            "source_findings": self.source_findings,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class RelationshipEdge(BaseModel):
    """Directed, temporal graph edge between two resolved entities.

    Every edge strictly requires:
    - valid_from: Start of temporal validity (ISO string or timestamp)
    - valid_to: End of validity or None if ongoing
    - confidence: Confidence score (0.0 to 1.0)
    - source: Provenance / telemetry origin
    """

    model_config = ConfigDict(
        extra="ignore",
        populate_by_name=True,
        validate_assignment=True,
    )

    source_id: str
    target_id: str
    rel_type: RelationshipType
    valid_from: str
    valid_to: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = "wazuh"
    properties: dict[str, Any] = Field(default_factory=dict)

    def to_graph_dict(self) -> dict[str, Any]:
        """Serialize edge representation suitable for Neo4j Cypher parameterization."""
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "type": self.rel_type.value,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "confidence": self.confidence,
            "source": self.source,
            "properties": self.properties,
        }


class ResolutionConflict(BaseModel):
    """Records an ambiguous or conflicting identity match where merge was refused."""

    model_config = ConfigDict(extra="ignore")

    entity_type: EntityType
    existing_entity_id: str
    candidate_identifiers: dict[str, str]
    reason: str
    finding_uid: str
    detected_at: float = Field(default_factory=time.time)


class ResolutionResult(BaseModel):
    """Aggregate result of entity resolution across one or more findings."""

    model_config = ConfigDict(extra="ignore")

    entities: dict[str, EntityNode] = Field(default_factory=dict)
    relationships: list[RelationshipEdge] = Field(default_factory=list)
    conflicts: list[ResolutionConflict] = Field(default_factory=list)
    unresolved: list[dict[str, Any]] = Field(default_factory=list)

    def to_cypher_parameters(self) -> dict[str, Any]:
        """Format resolved entities and relationships for batch Neo4j ingestion."""
        return {
            "nodes": [entity.to_graph_dict() for entity in self.entities.values()],
            "edges": [rel.to_graph_dict() for rel in self.relationships],
        }
