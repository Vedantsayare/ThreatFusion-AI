"""
simulation/evaluation.py — Quantitative evaluation harness and metrics calculator.

Calculates:
- Multi-class Precision, Recall, and F1-score across priority levels (P1, P2, P3, P4).
- 4x4 Confusion Matrix.
- Overall classification accuracy.
- Guardrail policy enforcement accuracy.
- MITRE technique extraction recall.
"""

from __future__ import annotations

import time
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from core.logger import get_logger
from orchestrator.workflow import AlertWorkflowRunner
from simulation.scenarios import LabeledAlert, get_benchmark_dataset

logger = get_logger("simulation.evaluation")


class ClassMetrics(BaseModel):
    """Evaluation metrics for a single priority classification class."""

    model_config = ConfigDict(extra="ignore")

    priority: str
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    support: int = 0


class EvaluationReport(BaseModel):
    """Complete quantitative evaluation summary report."""

    model_config = ConfigDict(extra="ignore")

    total_samples: int
    evaluated_at: float = Field(default_factory=time.time)
    duration_ms: float = 0.0
    overall_accuracy: float = 0.0
    macro_f1: float = 0.0
    class_metrics: dict[str, ClassMetrics] = Field(default_factory=dict)
    confusion_matrix: dict[str, dict[str, int]] = Field(default_factory=dict)
    guardrail_accuracy: float = 0.0
    mitre_extraction_recall: float = 0.0
    failures: list[dict[str, Any]] = Field(default_factory=list)
    dataset_disclaimer: str = (
        "Dataset is a controlled synthetic benchmark of 20 representative alerts. "
        "Metrics demonstrate deterministic engine correctness against defined test rules, "
        "not empirical real-world production detection accuracy."
    )


PRIORITY_TO_P: dict[str, str] = {
    "CRITICAL": "P1",
    "HIGH": "P2",
    "MEDIUM": "P3",
    "LOW": "P4",
    "P1": "P1",
    "P2": "P2",
    "P3": "P3",
    "P4": "P4",
}


async def evaluate_pipeline(
    runner: AlertWorkflowRunner | None = None,
    dataset: list[LabeledAlert] | None = None,
) -> EvaluationReport:
    """Run full pipeline evaluation against the ground-truth benchmark dataset."""
    alerts = dataset or get_benchmark_dataset()
    workflow_runner = runner or AlertWorkflowRunner(enable_graph_persistence=False)

    priorities = ["P1", "P2", "P3", "P4"]

    # Initialize 4x4 confusion matrix: matrix[actual][predicted]
    confusion: dict[str, dict[str, int]] = {
        act: dict.fromkeys(priorities, 0) for act in priorities
    }

    correct_predictions = 0
    guardrail_matches = 0
    total_mitre_expected = 0
    total_mitre_extracted = 0
    failures: list[dict[str, Any]] = []

    start_time = time.perf_counter()

    for item in alerts:
        output = await workflow_runner.process_alert(
            raw_alert=item.raw_alert,
            source="evaluation_harness",
            provenance={"scenario_id": item.scenario_id},
        )

        actual = item.expected_priority
        raw_pred = (
            output.triage_result.priority.value
            if output.triage_result
            else "LOW"
        )
        predicted = PRIORITY_TO_P.get(raw_pred.upper(), "P4")

        confusion[actual][predicted] += 1

        if predicted == actual:
            correct_predictions += 1
        else:
            failures.append(
                {
                    "scenario_id": item.scenario_id,
                    "name": item.name,
                    "expected_priority": actual,
                    "predicted_priority": predicted,
                    "reasons": output.triage_result.reasons if output.triage_result else [],
                }
            )

        # Check guardrail expectation
        has_approval = len(output.pending_approvals) > 0
        if has_approval == item.expect_guardrail_block:
            guardrail_matches += 1

        # Check MITRE technique extraction
        if item.expected_mitre and output.triage_result:
            extracted_techniques = set(output.triage_result.mitre_techniques)
            expected_techniques = set(item.expected_mitre)
            total_mitre_expected += len(expected_techniques)
            total_mitre_extracted += len(expected_techniques.intersection(extracted_techniques))

    duration_ms = (time.perf_counter() - start_time) * 1000.0
    total = len(alerts)
    overall_accuracy = correct_predictions / total if total > 0 else 0.0
    guardrail_acc = guardrail_matches / total if total > 0 else 0.0
    mitre_recall = (
        total_mitre_extracted / total_mitre_expected
        if total_mitre_expected > 0
        else 1.0
    )

    # Calculate per-class precision, recall, F1
    class_metrics: dict[str, ClassMetrics] = {}
    f1_sum = 0.0

    for p in priorities:
        tp = confusion[p][p]
        # Sum column for FP (predicted as p, but actual was not p)
        fp = sum(confusion[act][p] for act in priorities if act != p)
        # Sum row for FN (actual was p, but predicted as something else)
        fn = sum(confusion[p][pred] for pred in priorities if pred != p)
        support = sum(confusion[p].values())

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        f1_sum += f1

        class_metrics[p] = ClassMetrics(
            priority=p,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(prec, 4),
            recall=round(rec, 4),
            f1_score=round(f1, 4),
            support=support,
        )

    macro_f1 = f1_sum / len(priorities)

    report = EvaluationReport(
        total_samples=total,
        evaluated_at=time.time(),
        duration_ms=round(duration_ms, 2),
        overall_accuracy=round(overall_accuracy, 4),
        macro_f1=round(macro_f1, 4),
        class_metrics=class_metrics,
        confusion_matrix=confusion,
        guardrail_accuracy=round(guardrail_acc, 4),
        mitre_extraction_recall=round(mitre_recall, 4),
        failures=failures,
    )

    logger.info(
        "evaluation_completed",
        total=total,
        accuracy=report.overall_accuracy,
        macro_f1=report.macro_f1,
        duration_ms=report.duration_ms,
    )

    return report
