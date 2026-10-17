"""
api/models.py — Request and response schemas for ThreatFusion AI FastAPI endpoints.
"""

from __future__ import annotations

from typing import Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class AlertIngestRequest(BaseModel):
    """Payload to ingest and process a security alert."""

    model_config = ConfigDict(extra="ignore")

    raw_alert: dict[str, Any]
    source: str = "wazuh"
    provenance: dict[str, Any] = Field(default_factory=dict)


class InvestigationSummary(BaseModel):
    """Brief summary record for paginated alert list views."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str
    finding_id: str | None = None
    title: str
    priority: str
    score: int
    severity: str
    workflow_status: str
    received_at: float
    duration_ms: float
    asset_name: str | None = None
    username: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    pending_approvals_count: int = 0


class PaginatedResponse(BaseModel, Generic[T]):  # noqa: UP046
    """Standardized bounded paginated container."""

    model_config = ConfigDict(extra="ignore")

    items: list[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class InvestigationDetailResponse(BaseModel):
    """Complete detail view of an investigated security alert."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str
    workflow_status: str
    is_valid: bool
    source: str
    received_at: float
    completed_at: float
    duration_ms: float

    # Stages and domain results
    completed_stages: list[str] = Field(default_factory=list)
    finding: dict[str, Any] | None = None
    resolution: dict[str, Any] | None = None
    graph_persisted: bool = False
    persisted_nodes_count: int = 0
    persisted_edges_count: int = 0
    investigation_context: dict[str, Any] | None = None
    triage_result: dict[str, Any] | None = None

    # Safety and guardrails
    guardrail_results: list[dict[str, Any]] = Field(default_factory=list)
    pending_approvals: list[str] = Field(default_factory=list)
    audit_event_ids: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    # External enrichment
    enrichment: dict[str, Any] | None = None


class ApprovalDecisionRequest(BaseModel):
    """Reviewer decision payload for human-in-the-loop approval."""

    model_config = ConfigDict(extra="ignore")

    reviewer_id: str
    decision: Literal["APPROVE", "REJECT"]
    reason: str | None = None


class ApprovalDecisionResponse(BaseModel):
    """Outcome of submitting an approval decision."""

    model_config = ConfigDict(extra="ignore")

    request_id: str
    status: str
    reviewer_id: str
    decision_at: float
    decision_reason: str | None = None
    message: str


class IntegrationsStatusResponse(BaseModel):
    """Availability and connectivity status of external integrations."""

    model_config = ConfigDict(extra="ignore")

    wazuh: dict[str, Any]
    neo4j: dict[str, Any]
    misp: dict[str, Any]
    cmdb: dict[str, Any]


class HealthResponse(BaseModel):
    """Aggregate health check response."""

    model_config = ConfigDict(extra="ignore")

    status: str
    services: list[dict[str, Any]]
    checked_at: float
