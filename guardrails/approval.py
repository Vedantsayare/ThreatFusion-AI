"""
guardrails/approval.py — Human approval lifecycle management and binding enforcement.

Enforces:
- Cryptographic binding of approvals to exact action parameters via action_hash.
- Any modification to an approved action invalidates the approval.
- Explicit expiration windows; expired requests can never authorize execution.
- Reviewer identity recording without fabrication.
- Rejection and revocation lifecycle handling.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from guardrails.models import ActionProposal


class ApprovalStatus(str, Enum):
    """Lifecycle status of a human approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    # Terminal: the approved action was executed once (simulated or real).
    # An EXECUTED approval can never authorize a second execution (replay guard).
    EXECUTED = "EXECUTED"


class ApprovalRequest(BaseModel):
    """Immutable human approval request cryptographically bound to an ActionProposal."""

    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(default_factory=lambda: f"apr-{uuid.uuid4().hex[:12]}")
    action_hash: str
    action_name: str
    target_entities: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str
    evidence_refs: list[str] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)
    expires_at: float
    status: ApprovalStatus = ApprovalStatus.PENDING

    # Full proposal kept so the exact action can be re-evaluated at execution time.
    proposal: ActionProposal | None = None
    proposed_by: str = "triage_engine"
    # Non-hashed linkage for navigation (incident / alert the request belongs to).
    context: dict[str, Any] = Field(default_factory=dict)

    # Reviewer decision fields (set only upon authorized decision)
    reviewer_id: str | None = None
    decision_at: float | None = None
    decision_reason: str | None = None

    # Execution record (set only after a successful, guardrail-validated execution)
    executed_at: float | None = None
    executed_by: str | None = None
    execution_outcome: str | None = None

    def is_expired(self, current_time: float | None = None) -> bool:
        """Check whether this approval request has passed its expiration deadline."""
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def is_valid_for(
        self,
        action: ActionProposal,
        current_time: float | None = None,
    ) -> tuple[bool, str]:
        """Verify whether this approval strictly authorizes the given action proposal.

        Requires:
        1. Status must be APPROVED (existence of request alone NEVER authorizes).
        2. Current time must be strictly before expires_at.
        3. Action proposal hash must exactly match action_hash (binding check).
        """
        now = current_time if current_time is not None else time.time()

        if self.status != ApprovalStatus.APPROVED:
            return False, f"Approval request '{self.request_id}' status is '{self.status.value}', not APPROVED"

        if self.is_expired(now):
            return False, f"Approval request '{self.request_id}' expired at {self.expires_at} (current: {now})"

        current_hash = action.compute_action_hash()
        if self.action_hash != current_hash:
            return (
                False,
                f"Action parameter mismatch: approved hash '{self.action_hash}' does not match current hash '{current_hash}'",
            )

        return True, f"Action authorized by valid approval '{self.request_id}' by reviewer '{self.reviewer_id}'"


class ApprovalService:
    """Manages the lifecycle, storage, and validation of human approval requests."""

    def __init__(
        self,
        default_timeout_seconds: float = 1800.0,
        on_change: Callable[[ApprovalRequest], None] | None = None,
    ) -> None:
        self.default_timeout_seconds = max(30.0, default_timeout_seconds)
        self._requests: dict[str, ApprovalRequest] = {}
        # Persistence hook invoked after every state change.
        self.on_change = on_change

    def _changed(self, req: ApprovalRequest) -> None:
        if self.on_change is not None:
            self.on_change(req)

    def restore(self, requests: list[ApprovalRequest]) -> None:
        """Load previously persisted requests (startup only)."""
        for req in requests:
            self._requests[req.request_id] = req

    def list_all(self, status: ApprovalStatus | None = None) -> list[ApprovalRequest]:
        """List requests newest first, refreshing expiry on pending ones."""
        out: list[ApprovalRequest] = []
        for req in self._requests.values():
            self.get_request(req.request_id)
            if status is None or req.status == status:
                out.append(req)
        return sorted(out, key=lambda r: r.created_at, reverse=True)

    def create_request(
        self,
        action: ActionProposal,
        timeout_seconds: float | None = None,
        context: dict[str, Any] | None = None,
    ) -> ApprovalRequest:
        """Create a new pending approval request bound to the exact action proposal."""
        ttl = timeout_seconds if timeout_seconds is not None else self.default_timeout_seconds
        now = time.time()
        req = ApprovalRequest(
            action_hash=action.compute_action_hash(),
            action_name=action.action_name,
            target_entities=list(action.target_entities),
            parameters=dict(action.parameters),
            reason=action.rationale,
            evidence_refs=list(action.evidence_refs),
            created_at=now,
            expires_at=now + ttl,
            status=ApprovalStatus.PENDING,
            proposal=action.model_copy(deep=True),
            proposed_by=action.proposed_by,
            context=dict(context or {}),
        )
        self._requests[req.request_id] = req
        self._changed(req)
        return req

    def get_request(self, request_id: str) -> ApprovalRequest | None:
        """Retrieve request by ID, automatically updating status to EXPIRED if deadline passed."""
        req = self._requests.get(request_id)
        if req and req.status == ApprovalStatus.PENDING and req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            self._changed(req)
        return req

    def approve(
        self,
        request_id: str,
        reviewer_id: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Record an authorized human approval decision."""
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("Reviewer identity cannot be empty when approving an action")

        req = self.get_request(request_id)
        if not req:
            raise KeyError(f"Approval request '{request_id}' not found")

        if req.is_expired():
            if req.status == ApprovalStatus.PENDING:
                req.status = ApprovalStatus.EXPIRED
                self._changed(req)
            raise ValueError(f"Cannot approve expired request '{request_id}'")

        if req.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot approve request '{request_id}' with status '{req.status.value}'")

        req.status = ApprovalStatus.APPROVED
        req.reviewer_id = reviewer_id.strip()
        req.decision_at = time.time()
        req.decision_reason = reason
        self._changed(req)
        return req

    def reject(
        self,
        request_id: str,
        reviewer_id: str,
        reason: str | None = None,
    ) -> ApprovalRequest:
        """Record a human rejection decision."""
        if not reviewer_id or not reviewer_id.strip():
            raise ValueError("Reviewer identity cannot be empty when rejecting an action")

        req = self.get_request(request_id)
        if not req:
            raise KeyError(f"Approval request '{request_id}' not found")

        # Decisions are final: an approved/executed/expired request cannot be
        # silently flipped to REJECTED (use revoke() to withdraw an approval).
        if req.status != ApprovalStatus.PENDING:
            raise ValueError(f"Cannot reject request '{request_id}' with status '{req.status.value}'")

        req.status = ApprovalStatus.REJECTED
        req.reviewer_id = reviewer_id.strip()
        req.decision_at = time.time()
        req.decision_reason = reason
        self._changed(req)
        return req

    def revoke(self, request_id: str, reason: str | None = None) -> ApprovalRequest:
        """Revoke a previously approved or pending request."""
        req = self.get_request(request_id)
        if not req:
            raise KeyError(f"Approval request '{request_id}' not found")

        if req.status not in (ApprovalStatus.PENDING, ApprovalStatus.APPROVED):
            raise ValueError(f"Cannot revoke request '{request_id}' with status '{req.status.value}'")

        req.status = ApprovalStatus.REVOKED
        req.decision_reason = reason
        self._changed(req)
        return req

    def mark_executed(self, request_id: str, executed_by: str, outcome: str) -> ApprovalRequest:
        """Consume an APPROVED request exactly once (replay protection)."""
        req = self.get_request(request_id)
        if not req:
            raise KeyError(f"Approval request '{request_id}' not found")
        if req.status != ApprovalStatus.APPROVED:
            raise ValueError(f"Cannot execute request '{request_id}' with status '{req.status.value}'")
        if req.is_expired():
            raise ValueError(f"Approval '{request_id}' expired before execution")
        req.status = ApprovalStatus.EXECUTED
        req.executed_at = time.time()
        req.executed_by = executed_by
        req.execution_outcome = outcome
        self._changed(req)
        return req

    def list_pending(self) -> list[ApprovalRequest]:
        """List all currently pending and unexpired approval requests."""
        now = time.time()
        pending: list[ApprovalRequest] = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.PENDING:
                if req.is_expired(now):
                    req.status = ApprovalStatus.EXPIRED
                    self._changed(req)
                else:
                    pending.append(req)
        return pending
