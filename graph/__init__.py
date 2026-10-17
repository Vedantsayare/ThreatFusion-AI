"""
graph — Temporal knowledge-graph models, entity resolution, and Neo4j persistence.

Exports canonical graph entity models, temporal edges, conflict tracking,
EntityResolver, and the asynchronous Neo4jClient.
"""

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
    ResolutionConflict,
    ResolutionResult,
)
from graph.resolver import EntityResolver

__all__ = [
    "EntityNode",
    "EntityResolver",
    "EntityType",
    "GraphConnectionError",
    "GraphConstraintError",
    "GraphError",
    "GraphQueryError",
    "Neo4jClient",
    "RelationshipEdge",
    "RelationshipType",
    "ResolutionConflict",
    "ResolutionResult",
]
