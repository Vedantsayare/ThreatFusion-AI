"""
api — ThreatFusion AI API Layer for Investigations, Integrations, and Approvals.
"""

from api.app import create_app
from api.models import (
    AlertIngestRequest,
    ApprovalDecisionRequest,
    ApprovalDecisionResponse,
    HealthResponse,
    IntegrationsStatusResponse,
    InvestigationDetailResponse,
    InvestigationSummary,
    PaginatedResponse,
)
from api.routes import init_api_dependencies, router
from api.store import InvestigationStore, default_investigation_store

__all__ = [
    "AlertIngestRequest",
    "ApprovalDecisionRequest",
    "ApprovalDecisionResponse",
    "HealthResponse",
    "IntegrationsStatusResponse",
    "InvestigationDetailResponse",
    "InvestigationStore",
    "InvestigationSummary",
    "PaginatedResponse",
    "create_app",
    "default_investigation_store",
    "init_api_dependencies",
    "router",
]
