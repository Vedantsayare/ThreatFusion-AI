"""
tests/unit/test_benchmark.py — Pins triage behaviour on the synthetic benchmark.

If a triage change moves these numbers, update docs/DETECTION_EVALUATION.md
(`python -m simulation.benchmark --out docs/DETECTION_EVALUATION.md`) and
explain the change; never tune weights just to raise this small, synthetic,
author-labelled score.
"""

from __future__ import annotations

import pytest

from orchestrator.workflow import AlertWorkflowRunner
from simulation.benchmark import run_all, to_markdown
from simulation.evaluation import evaluate_pipeline


async def test_benchmark_results_are_stable_and_consistent() -> None:
    baseline, enriched = await run_all()
    b, e = baseline.summary(), enriched.summary()

    assert b["accuracy"] == pytest.approx(0.85)
    assert e["accuracy"] == pytest.approx(0.80)
    assert b["under_escalations"] == 0
    assert e["under_escalations"] == 0
    assert e["attention"]["false_negative_rate"] == 0.0

    # Same numbers as the original evaluation harness for the un-enriched pipeline.
    original = await evaluate_pipeline(AlertWorkflowRunner(enable_graph_persistence=False))
    assert original.overall_accuracy == pytest.approx(b["accuracy"])

    # Every miss carries an explanation derived from its own score contributions.
    for result in (baseline, enriched):
        for p in result.predictions:
            if p.predicted != p.expected:
                assert p.tags
                assert p.breakdown
                assert sum(c["points"] for c in p.breakdown) == p.score

    report = to_markdown([baseline, enriched])
    assert "Confusion matrix" in report
    assert "Misclassified alerts" in report
