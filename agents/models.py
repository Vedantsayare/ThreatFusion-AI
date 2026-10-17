"""
agents/models.py — Data models for deterministic triage and investigation engine.

Defines typed Pydantic models for incident priorities, triage scoring results,
evidence provenance, observed facts versus inferences, and investigation context.
"""

from __future__ import annotations

import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IncidentPriority(str, Enum):
    """Deterministic triage priority levels for security findings."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceItem(BaseModel):
    """Structured evidence reference with origin provenance and confidence."""

    model_config = ConfigDict(extra="ignore")

    source: str
    evidence_type: str
    detail: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class EvidenceFact(BaseModel):
    """An empirically observed fact directly attested by telemetry or database state."""

    model_config = ConfigDict(extra="ignore")

    fact_type: str  # e.g. "telemetry", "graph_node", "graph_edge", "history"
    source: str     # e.g. "wazuh_alert", "neo4j_graph"
    description: str
    timestamp: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)


class EvidenceInference(BaseModel):
    """An analytical deduction derived from observed facts (clearly separated from facts)."""

    model_config = ConfigDict(extra="ignore")

    inference_type: str  # e.g. "privileged_risk", "brute_force_pattern", "external_exposure"
    rationale: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    derived_from: list[str] = Field(default_factory=list)


class InvestigationContext(BaseModel):
    """Contextual evidence retrieved from the knowledge graph and entity resolution."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    graph_available: bool = True
    lookup_error: str | None = None
    retrieved_at: float = Field(default_factory=time.time)

    # Separation of observed facts from inferences
    observed_facts: list[EvidenceFact] = Field(default_factory=list)
    inferences: list[EvidenceInference] = Field(default_factory=list)

    # Graph structure
    entities_found: list[dict[str, Any]] = Field(default_factory=list)
    relationships_found: list[dict[str, Any]] = Field(default_factory=list)
    historical_finding_count: int = Field(default=0, ge=0)

    # Completeness and conflict reporting
    conflicting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    """Structured, deterministic assessment of an incident's priority and investigation scope."""

    model_config = ConfigDict(extra="ignore")

    finding_id: str
    title: str
    priority: IncidentPriority
    score: int = Field(..., ge=0, le=100)
    severity: str
    original_severity: str | None = None

    # Reasons and justification
    reasons: list[str] = Field(default_factory=list)
    evidence: list[EvidenceItem] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)

    # Uncertainty and missing data tracking
    has_missing_data: bool = False
    uncertainties: list[str] = Field(default_factory=list)

    # Advisory next steps (strictly advisory, requires human review)
    recommended_steps: list[str] = Field(default_factory=list)

    # Provenance
    triaged_at: float = Field(default_factory=time.time)
    policy_version: str = "1.0.0"
