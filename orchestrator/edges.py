"""
orchestrator/edges.py — Conditional routing functions for the LangGraph alert workflow.

Defines deterministic branching rules:
- Fails fast to synthesis on invalid input or normalization failure.
- Bounded retry loops for recoverable persistence failures.
- Guarantees every execution path reaches a valid termination node.
"""

from __future__ import annotations

from orchestrator.state import AlertWorkflowState


def route_after_validation(state: AlertWorkflowState) -> str:
    """Route to normalization on valid input; fail fast to synthesis on validation failure."""
    if not state.get("is_valid", False):
        return "synthesize_final_result"
    return "normalize_alert"


def route_after_normalization(state: AlertWorkflowState) -> str:
    """Route to entity resolution on successful normalization; fail fast on schema error."""
    if state.get("finding") is None:
        return "synthesize_final_result"
    return "resolve_entities"


def route_after_persistence(state: AlertWorkflowState) -> str:
    """Route back for bounded retry on transient database error; proceed to investigation otherwise."""
    if state.get("retry_needed", False):
        retries = state.get("retry_counts", {}).get("persist_to_graph", 0)
        max_r = state.get("max_retries", 2)
        if retries <= max_r:
            return "persist_to_graph"

    return "gather_investigation_context"
