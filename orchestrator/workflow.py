"""
orchestrator/workflow.py — LangGraph StateGraph assembly and workflow runner.

Assembles the AlertWorkflow StateGraph with deterministic nodes, conditional routing,
bounded retries, and honest partial status tracking.
Provides AlertWorkflowRunner for single alert and batch processing.
"""

from __future__ import annotations

import time
from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from core.config import AppSettings
from core.logger import get_logger
from graph.client import Neo4jClient
from orchestrator.edges import (
    route_after_normalization,
    route_after_persistence,
    route_after_validation,
)
from orchestrator.nodes import AlertWorkflowNodes
from orchestrator.state import (
    AlertWorkflowOutput,
    AlertWorkflowState,
    WorkflowStatus,
)

logger = get_logger("orchestrator.workflow")


def build_alert_workflow(
    nodes: AlertWorkflowNodes,
) -> CompiledStateGraph[Any, Any, Any, Any]:
    """Build and compile the LangGraph alert processing StateGraph.

    Node sequence:
    1. receive_alert: Ingests alert and sets provenance.
    2. validate_input: Validates dictionary structure; branches on failure.
    3. normalize_alert: Maps to OCSFSecurityFinding; branches on failure.
    4. resolve_entities: Deduplicates entities into ResolutionResult.
    5. persist_to_graph: Idempotent Neo4j write with bounded retries.
    6. gather_investigation_context: Queries graph neighborhood and historical count.
    7. perform_triage: Computes deterministic priority score and advisory steps.
    8. synthesize_final_result: Generates immutable final AlertWorkflowOutput.
    """
    workflow = StateGraph(AlertWorkflowState)

    # 1. Register discrete nodes
    workflow.add_node("receive_alert", nodes.receive_alert)
    workflow.add_node("validate_input", nodes.validate_input)
    workflow.add_node("normalize_alert", nodes.normalize_alert)
    workflow.add_node("resolve_entities", nodes.resolve_entities)
    workflow.add_node("persist_to_graph", nodes.persist_to_graph)
    workflow.add_node("gather_investigation_context", nodes.gather_investigation_context)
    workflow.add_node("perform_triage", nodes.perform_triage)
    workflow.add_node("synthesize_final_result", nodes.synthesize_final_result)

    # 2. Register linear and conditional edges
    workflow.add_edge(START, "receive_alert")
    workflow.add_edge("receive_alert", "validate_input")

    workflow.add_conditional_edges(
        "validate_input",
        route_after_validation,
        {
            "normalize_alert": "normalize_alert",
            "synthesize_final_result": "synthesize_final_result",
        },
    )

    workflow.add_conditional_edges(
        "normalize_alert",
        route_after_normalization,
        {
            "resolve_entities": "resolve_entities",
            "synthesize_final_result": "synthesize_final_result",
        },
    )

    workflow.add_edge("resolve_entities", "persist_to_graph")

    workflow.add_conditional_edges(
        "persist_to_graph",
        route_after_persistence,
        {
            "persist_to_graph": "persist_to_graph",
            "gather_investigation_context": "gather_investigation_context",
        },
    )

    workflow.add_edge("gather_investigation_context", "perform_triage")
    workflow.add_edge("perform_triage", "synthesize_final_result")
    workflow.add_edge("synthesize_final_result", END)

    return workflow.compile()


class AlertWorkflowRunner:
    """High-level runner managing the compiled LangGraph workflow execution."""

    def __init__(
        self,
        settings: AppSettings | None = None,
        graph_client: Neo4jClient | None = None,
        enable_graph_persistence: bool = True,
        max_retries: int = 2,
        nodes: AlertWorkflowNodes | None = None,
    ) -> None:
        self.settings = settings
        self.graph_client = graph_client
        self.enable_graph_persistence = enable_graph_persistence
        self.max_retries = max_retries

        self.nodes = nodes or AlertWorkflowNodes(
            graph_client=graph_client,
            enable_graph_persistence=enable_graph_persistence,
            max_retries=max_retries,
        )
        self.workflow: CompiledStateGraph[Any, Any, Any, Any] = build_alert_workflow(self.nodes)

    async def process_alert(
        self,
        raw_alert: dict[str, Any],
        source: str = "wazuh",
        provenance: dict[str, Any] | None = None,
    ) -> AlertWorkflowOutput:
        """Execute the LangGraph workflow for a single security alert.

        Args:
            raw_alert: Raw, unnormalized alert dictionary.
            source: Ingestion source identifier (default "wazuh").
            provenance: Optional metadata tracking upstream ingestion context.

        Returns:
            AlertWorkflowOutput: Validated, immutable workflow summary.
        """
        initial_state: AlertWorkflowState = {
            "raw_alert": raw_alert,
            "source": source,
            "source_provenance": provenance or {},
            "received_at": time.time(),
            "max_retries": self.max_retries,
            "workflow_status": WorkflowStatus.PENDING.value,
        }

        final_state: dict[str, Any] = await self.workflow.ainvoke(initial_state)

        # Parse final output model
        final_dict = final_state.get("final_output")
        if final_dict:
            return AlertWorkflowOutput.model_validate(final_dict)

        # Fallback if synthesis failed unexpectedly
        return AlertWorkflowOutput(
            alert_id=str(final_state.get("alert_id", "unknown")),
            workflow_status=WorkflowStatus.FAILED,
            is_valid=final_state.get("is_valid", False),
            source=source,
            received_at=final_state.get("received_at", time.time()),
            completed_at=time.time(),
            duration_ms=0.0,
            errors=final_state.get("errors", ["Workflow terminated without final output"]),
        )

    async def process_batch(
        self,
        alerts: list[dict[str, Any]],
        source: str = "wazuh",
    ) -> list[AlertWorkflowOutput]:
        """Execute the workflow across a batch of alerts sequentially and safely.

        Args:
            alerts: List of raw alert dictionaries.
            source: Source identifier.

        Returns:
            list[AlertWorkflowOutput]: Execution results for each alert.
        """
        results: list[AlertWorkflowOutput] = []
        for alert in alerts:
            result = await self.process_alert(alert, source=source)
            results.append(result)
        return results
