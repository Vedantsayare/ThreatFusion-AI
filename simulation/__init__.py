"""
simulation — Attack simulation fixtures, benchmark evaluation, and hardening tests.
"""

from simulation.evaluation import (
    ClassMetrics,
    EvaluationReport,
    evaluate_pipeline,
)
from simulation.scenarios import (
    SCENARIO_BRUTE_FORCE,
    SCENARIO_C2_BEACONING,
    SCENARIO_CONFLICTING_EVIDENCE,
    SCENARIO_CRITICAL_LATERAL_MOVEMENT,
    SCENARIO_NORMAL_BASELINE,
    SCENARIO_PROMPT_INJECTION_TELEMETRY,
    LabeledAlert,
    get_benchmark_dataset,
)

__all__ = [
    "SCENARIO_BRUTE_FORCE",
    "SCENARIO_C2_BEACONING",
    "SCENARIO_CONFLICTING_EVIDENCE",
    "SCENARIO_CRITICAL_LATERAL_MOVEMENT",
    "SCENARIO_NORMAL_BASELINE",
    "SCENARIO_PROMPT_INJECTION_TELEMETRY",
    "ClassMetrics",
    "EvaluationReport",
    "LabeledAlert",
    "evaluate_pipeline",
    "get_benchmark_dataset",
]
