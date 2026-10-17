"""
guardrails/engine.py — Centralized deterministic guardrail policy engine.

Enforces:
- Hard policy boundaries (blast-radius limits, privileged-account gates, prohibited actions).
- Fail-closed evaluation: policy errors never grant authorization.
- Strict human approval verification: containment actions require valid, unexpired, bound approvals.
- Integration with HashChainAuditStore for tamper-evident decision records.
- Untrusted telemetry strings never override guardrail policies.
"""

from __future__ import annotations

from core.logger import get_logger
from guardrails.approval import ApprovalRequest, ApprovalService
from guardrails.audit import HashChainAuditStore
from guardrails.models import (
    ActionCategory,
    ActionProposal,
    DecisionType,
    GuardrailResult,
    PolicyViolation,
)

logger = get_logger("guardrails.engine")

DEFAULT_PRIVILEGED_ACCOUNTS = frozenset({
    "root",
    "admin",
    "administrator",
    "system",
    "local service",
    "domain admins",
    "sudo",
})

DEFAULT_PROHIBITED_ACTIONS = frozenset({
    "clear_audit_logs",
    "drop_database",
    "disable_guardrails",
    "modify_audit_store",
    "unrestricted_shell_exec",
    "delete_temporal_graph",
})


class GuardrailPolicy:
    """Configurable security boundaries and constraints for guardrail evaluations."""

    def __init__(
        self,
        max_blast_radius: int = 3,
        privileged_accounts_require_approval: bool = True,
        prohibited_actions: set[str] | frozenset[str] | None = None,
        privileged_accounts: frozenset[str] | None = None,
        policy_id: str = "default_guardrail_policy_v1",
    ) -> None:
        self.max_blast_radius = max(1, max_blast_radius)
        self.privileged_accounts_require_approval = privileged_accounts_require_approval
        self.prohibited_actions = (
            frozenset(prohibited_actions) if prohibited_actions is not None else DEFAULT_PROHIBITED_ACTIONS
        )
        self.privileged_accounts = (
            privileged_accounts if privileged_accounts is not None else DEFAULT_PRIVILEGED_ACCOUNTS
        )
        self.policy_id = policy_id


class GuardrailEngine:
    """Centralized safety policy engine evaluating all proposed security operations."""

    def __init__(
        self,
        policy: GuardrailPolicy | None = None,
        approval_service: ApprovalService | None = None,
        audit_store: HashChainAuditStore | None = None,
    ) -> None:
        self.policy = policy or GuardrailPolicy()
        self.approval_service = approval_service or ApprovalService()
        self.audit_store = audit_store or HashChainAuditStore()

    def evaluate(
        self,
        proposal: ActionProposal,
        approval: ApprovalRequest | None = None,
    ) -> GuardrailResult:
        """Evaluate an action proposal against safety policies and optional human approval.

        Enforces fail-closed semantics: any failure during evaluation denies authorization.
        """
        action_hash = proposal.compute_action_hash()
        violations: list[PolicyViolation] = []
        action_clean = proposal.action_name.strip().lower()

        try:
            # 1. Prohibited Action Check (hard absolute gate)
            if action_clean in self.policy.prohibited_actions:
                violation = PolicyViolation(
                    rule_name="prohibited_action",
                    reason=f"Action '{proposal.action_name}' is explicitly prohibited by policy",
                    severity="CRITICAL",
                )
                violations.append(violation)
                return self._finalize_result(
                    decision=DecisionType.DENY,
                    proposal=proposal,
                    action_hash=action_hash,
                    reason=violation.reason,
                    violations=violations,
                )

            # 2. Blast Radius Boundary Check
            target_count = len(proposal.target_entities)
            if target_count > self.policy.max_blast_radius:
                violation = PolicyViolation(
                    rule_name="blast_radius_exceeded",
                    reason=(
                        f"Blast radius exceeded: action targets {target_count} entities, "
                        f"exceeding policy limit of {self.policy.max_blast_radius}"
                    ),
                    severity="CRITICAL",
                )
                violations.append(violation)
                return self._finalize_result(
                    decision=DecisionType.DENY,
                    proposal=proposal,
                    action_hash=action_hash,
                    reason=violation.reason,
                    violations=violations,
                )

            # 3. Read-Only Operations (Passive investigation/triage)
            if proposal.category == ActionCategory.READ_ONLY:
                return self._finalize_result(
                    decision=DecisionType.ALLOW,
                    proposal=proposal,
                    action_hash=action_hash,
                    reason="Permitted read-only operation",
                    violations=[],
                )

            # 4. Privileged Account Check
            targets_privileged = False
            user_param = str(proposal.parameters.get("username") or proposal.parameters.get("user") or "")
            if user_param.strip().lower() in self.policy.privileged_accounts:
                targets_privileged = True

            # Also check if any target entity is a privileged identity
            for target in proposal.target_entities:
                if any(priv in target.lower() for priv in self.policy.privileged_accounts):
                    targets_privileged = True

            if targets_privileged and self.policy.privileged_accounts_require_approval:
                violations.append(
                    PolicyViolation(
                        rule_name="privileged_account_targeted",
                        reason=f"Action targets privileged administrative entity '{user_param or proposal.target_entities}'",
                        severity="HIGH",
                    )
                )

            # 5. Check Human Approval for Containment/Remediation/Administrative Actions
            if proposal.category in (
                ActionCategory.CONTAINMENT,
                ActionCategory.REMEDIATION,
                ActionCategory.ADMINISTRATIVE,
            ) or targets_privileged:

                # If no approval was provided, create/record an approval request
                if approval is None:
                    req = self.approval_service.create_request(proposal)
                    return self._finalize_result(
                        decision=DecisionType.REQUIRE_APPROVAL,
                        proposal=proposal,
                        action_hash=action_hash,
                        reason=f"Security-sensitive action requires human approval (created request '{req.request_id}')",
                        violations=violations,
                        required_approvals=[req.request_id],
                    )

                # An approval was provided; verify its cryptographic binding and validity
                is_valid, validation_msg = approval.is_valid_for(proposal)
                if not is_valid:
                    violation = PolicyViolation(
                        rule_name="invalid_approval",
                        reason=f"Provided approval is invalid or action was altered: {validation_msg}",
                        severity="CRITICAL",
                    )
                    violations.append(violation)
                    return self._finalize_result(
                        decision=DecisionType.DENY,
                        proposal=proposal,
                        action_hash=action_hash,
                        reason=validation_msg,
                        violations=violations,
                    )

                # Valid human approval confirmed!
                return self._finalize_result(
                    decision=DecisionType.ALLOW,
                    proposal=proposal,
                    action_hash=action_hash,
                    reason=f"Action authorized by human approval '{approval.request_id}' (reviewer: '{approval.reviewer_id}')",
                    violations=violations,
                    required_approvals=[approval.request_id],
                )

            # Fallback for unclassified actions: fail-closed by requiring approval
            req = self.approval_service.create_request(proposal)
            return self._finalize_result(
                decision=DecisionType.REQUIRE_APPROVAL,
                proposal=proposal,
                action_hash=action_hash,
                reason="Unclassified active operation requires human approval",
                violations=violations,
                required_approvals=[req.request_id],
            )

        except Exception as err:
            # Fail-closed guarantee: any unexpected error in policy evaluation produces ERROR / DENY
            logger.error("guardrail_evaluation_error", action=proposal.action_name, error=str(err))
            err_violation = PolicyViolation(
                rule_name="policy_evaluation_error",
                reason=f"Fail-closed: guardrail evaluation failed safely ({err})",
                severity="CRITICAL",
            )
            return self._finalize_result(
                decision=DecisionType.ERROR,
                proposal=proposal,
                action_hash=action_hash,
                reason=err_violation.reason,
                violations=[err_violation],
            )

    def _finalize_result(
        self,
        decision: DecisionType,
        proposal: ActionProposal,
        action_hash: str,
        reason: str,
        violations: list[PolicyViolation],
        required_approvals: list[str] | None = None,
    ) -> GuardrailResult:
        """Log audit event to HashChainAuditStore and construct GuardrailResult."""
        audit_event = self.audit_store.log_event(
            actor=proposal.proposed_by,
            operation=proposal.action_name,
            decision=decision.value,
            policy_id=self.policy.policy_id,
            outcome=reason,
            evidence_refs=proposal.evidence_refs,
            approval_id=required_approvals[0] if required_approvals else None,
            metadata={
                "action_hash": action_hash,
                "category": proposal.category.value,
                "targets": proposal.target_entities,
                "violations_count": len(violations),
            },
        )

        return GuardrailResult(
            decision=decision,
            action_proposal=proposal,
            action_hash=action_hash,
            policy_id=self.policy.policy_id,
            reason=reason,
            violations=violations,
            required_approvals=required_approvals or [],
            audit_event_id=audit_event.event_id,
        )
