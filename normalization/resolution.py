"""
normalization/resolution.py — Entity resolution alias module.

Re-exports graph entity models and EntityResolver from graph package for convenience.
"""

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
    "RelationshipEdge",
    "RelationshipType",
    "ResolutionConflict",
    "ResolutionResult",
]
