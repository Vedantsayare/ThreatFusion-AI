"""
api/models.py — Request and response schemas for ThreatFusion AI FastAPI endpoints.
"""

from __future__ import annotations

from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

T = TypeVar("T")


SourceName = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]


class AlertIngestRequest(BaseModel):
    """Payload to ingest and process a security alert (Wazuh-style JSON)."""

    model_config = ConfigDict(extra="ignore")

    raw_alert: dict[str, Any] = Field(..., min_length=1)
    source: SourceName = "wazuh"
    provenance: dict[str, Any] = Field(default_factory=dict)


class AlertBatchIngestRequest(BaseModel):
    """Up to 100 raw alerts from one source."""

    model_config = ConfigDict(extra="ignore")

    alerts: list[dict[str, Any]] = Field(..., min_length=1, max_length=100)
    source: SourceName = "wazuh"
    provenance: dict[str, Any] = Field(default_factory=dict)


class IncidentStatusRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["OPEN", "INVESTIGATING", "ESCALATED", "RESOLVED", "FALSE_POSITIVE"]
    reason: str = Field(..., min_length=3, max_length=1000)


class NoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., min_length=1, max_length=4000)


class ActionProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_name: str = Field(..., min_length=3, max_length=64)
    target: str = Field(..., min_length=1, max_length=255)
    rationale: str = Field(..., min_length=5, max_length=2000)


class NarrativeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    use_llm: bool = False


class IncidentSummary(BaseModel):
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    title: str
    status: str
    priority: str
    risk_score: int
    alert_count: int
    hosts: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    first_seen: float | None = None
    last_seen: float | None = None
    updated_at: float
    synthetic: bool = False


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
    event_time: float | None = None
    duration_ms: float
    asset_name: str | None = None
    username: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    pending_approvals_count: int = 0
    incident_id: str | None = None
    source: str | None = None
    synthetic: bool = False


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
    stage_records: dict[str, Any] = Field(default_factory=dict)
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

    # Correlation & provenance
    incident_id: str | None = None
    source_provenance: dict[str, Any] = Field(default_factory=dict)
    deduplicated: bool = False


class ApprovalDecisionRequest(BaseModel):
    """Reviewer decision payload for human-in-the-loop approval.

    ``reviewer_id`` is accepted for backward compatibility but IGNORED: the
    reviewer recorded is always the authenticated principal.
    """

    model_config = ConfigDict(extra="ignore")

    decision: Literal["APPROVE", "REJECT"]
    reason: str | None = Field(default=None, max_length=2000)
    reviewer_id: str | None = Field(default=None, description="Deprecated; ignored")


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
    persistence: dict[str, Any] = Field(default_factory=dict)
    llm: dict[str, Any] = Field(default_factory=dict)
    auth: dict[str, Any] = Field(default_factory=dict)
    demo_mode: bool = False


class HealthResponse(BaseModel):
    """Aggregate health check response."""

    model_config = ConfigDict(extra="ignore")

    status: str
    services: list[dict[str, Any]]
    checked_at: float
