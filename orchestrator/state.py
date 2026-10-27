"""
orchestrator/state.py — Typed workflow state and models for LangGraph orchestration.

Defines:
- WorkflowStatus and StageStatus lifecycle enums.
- StageRecord tracking execution metadata per node.
- AlertWorkflowState (TypedDict) for the LangGraph StateGraph.
- AlertWorkflowOutput (Pydantic model) for structured, immutable caller results.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TypedDict

from pydantic import BaseModel, ConfigDict, Field

from agents.models import InvestigationContext, TriageResult
from graph.models import ResolutionResult
from guardrails.models import GuardrailResult
from normalization.models import OCSFSecurityFinding


class WorkflowStatus(str, Enum):
    """Lifecycle status of the entire alert workflow execution."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class StageStatus(str, Enum):
    """Execution status of an individual workflow node / stage."""

    NOT_STARTED = "NOT_STARTED"
    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class StageRecord(BaseModel):
    """Execution metadata and performance record for a single workflow stage."""

    model_config = ConfigDict(extra="ignore")

    stage_name: str
    status: StageStatus
    started_at: float
    completed_at: float | None = None
    duration_ms: float = 0.0
    error: str | None = None
    message: str | None = None
    retry_count: int = 0


class AlertWorkflowState(TypedDict, total=False):
    """Typed state dictionary passed between nodes in the LangGraph alert workflow."""

    # ── Input & Provenance ───────────────────────────────────────────────────
    alert_id: str
    raw_alert: dict[str, Any]
    source: str
    source_provenance: dict[str, Any]
    received_at: float

    # ── Validation Stage ─────────────────────────────────────────────────────
    is_valid: bool
    validation_errors: list[str]

    # ── Normalization Stage ──────────────────────────────────────────────────
    finding: OCSFSecurityFinding | None
    normalization_error: str | None

    # ── Entity Resolution Stage ──────────────────────────────────────────────
    resolution: ResolutionResult | None
    resolution_error: str | None

    # ── Graph Persistence Stage ──────────────────────────────────────────────
    graph_persistence_enabled: bool
    graph_persisted: bool
    persisted_nodes_count: int
    persisted_edges_count: int
    persistence_error: str | None

    # ── Investigation Context Stage ──────────────────────────────────────────
    investigation_context: InvestigationContext | None
    investigation_error: str | None

    # ── Enrichment Stage ─────────────────────────────────────────────────────
    enrichment: dict[str, Any] | None
    enrichment_error: str | None
    approval_context: dict[str, Any]

    # ── Triage Stage ─────────────────────────────────────────────────────────
    triage_result: TriageResult | None
    triage_error: str | None

    # ── Execution Controls, Retries & Auditing ────────────────────────────────
    workflow_status: str
    current_stage: str
    completed_stages: list[str]
    stage_records: dict[str, dict[str, Any]]
    retry_counts: dict[str, int]
    max_retries: int
    retry_needed: bool
    last_error: str | None
    errors: list[str]
    started_at: float
    completed_at: float | None
    duration_ms: float

    # ── Guardrails & Audit ───────────────────────────────────────────────────
    guardrail_results: list[dict[str, Any]]
    pending_approvals: list[str]
    audit_event_ids: list[str]

    # ── Structured Final Result ──────────────────────────────────────────────
    final_output: dict[str, Any] | None


class AlertWorkflowOutput(BaseModel):
    """Structured, immutable final output produced by the LangGraph alert workflow."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str
    workflow_status: WorkflowStatus
    is_valid: bool
    source: str
    received_at: float
    completed_at: float
    duration_ms: float

    # Stage execution provenance
    completed_stages: list[str] = Field(default_factory=list)
    stage_records: dict[str, StageRecord] = Field(default_factory=dict)

    # Domain outputs from pipeline stages
    finding: OCSFSecurityFinding | None = None
    resolution: ResolutionResult | None = None
    graph_persisted: bool = False
    persisted_nodes_count: int = 0
    persisted_edges_count: int = 0
    investigation_context: InvestigationContext | None = None
    triage_result: TriageResult | None = None

    # Audit, uncertainty, guardrails, and error tracking
    errors: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    guardrail_results: list[GuardrailResult] = Field(default_factory=list)
    pending_approvals: list[str] = Field(default_factory=list)
    audit_event_ids: list[str] = Field(default_factory=list)
    raw_alert_preserved: bool = True
    source_provenance: dict[str, Any] = Field(default_factory=dict)
    enrichment: dict[str, Any] | None = None
