"""
guardrails/models.py — Data models for centralized guardrails and policy enforcement.

Defines:
- DecisionType: ALLOW, REQUIRE_APPROVAL, DENY, ERROR.
- ActionCategory: READ_ONLY, CONTAINMENT, REMEDIATION, ADMINISTRATIVE.
- ActionProposal: Typed action request with deterministic cryptographic hashing.
- PolicyViolation: Explicit rule violation detail.
- GuardrailResult: Deterministic decision record with audit linkage.
"""

from __future__ import annotations

import hashlib
import json
import time
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DecisionType(str, Enum):
    """Guardrail decision outcomes."""

    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    ERROR = "ERROR"


class ActionCategory(str, Enum):
    """Categorization of proposed security actions."""

    READ_ONLY = "READ_ONLY"
    CONTAINMENT = "CONTAINMENT"
    REMEDIATION = "REMEDIATION"
    ADMINISTRATIVE = "ADMINISTRATIVE"


class ActionProposal(BaseModel):
    """Proposed security operation evaluated by the guardrail policy engine."""

    model_config = ConfigDict(extra="ignore")

    action_name: str
    category: ActionCategory
    target_entities: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    rationale: str
    evidence_refs: list[str] = Field(default_factory=list)
    proposed_by: str = "triage_engine"
    proposed_at: float = Field(default_factory=time.time)

    def compute_action_hash(self) -> str:
        """Compute deterministic SHA-256 hash binding action parameters and scope.

        Any alteration to action_name, category, target_entities, or parameters
        produces a different hash, preventing approval tampering or parameter injection.
        """
        canonical_dict = {
            "action_name": self.action_name.strip().lower(),
            "category": self.category.value,
            "target_entities": sorted(self.target_entities),
            "parameters": self.parameters,
            "evidence_refs": sorted(self.evidence_refs),
        }
        serialized = json.dumps(canonical_dict, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class PolicyViolation(BaseModel):
    """Explicit violation detected during guardrail policy evaluation."""

    model_config = ConfigDict(extra="ignore")

    rule_name: str
    reason: str
    severity: str = "CRITICAL"


class GuardrailResult(BaseModel):
    """Immutable result of a guardrail policy evaluation."""

    model_config = ConfigDict(extra="ignore")

    decision: DecisionType
    action_proposal: ActionProposal
    action_hash: str
    policy_id: str
    reason: str
    violations: list[PolicyViolation] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    evaluated_at: float = Field(default_factory=time.time)
    audit_event_id: str | None = None

    @property
    def is_executable(self) -> bool:
        """True only if the operation was directly ALLOWED without pending gates."""
        return self.decision == DecisionType.ALLOW
