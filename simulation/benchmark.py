"""
simulation/benchmark.py — Reproducible triage benchmark (enrichment off vs on).

Usage:
    python -m simulation.benchmark                      # print Markdown report
    python -m simulation.benchmark --out docs/DETECTION_EVALUATION.md
    python -m simulation.benchmark --json               # machine-readable

Runs the labelled synthetic dataset (simulation/scenarios.py) through the real
LangGraph workflow twice:
  - "baseline":  no enrichment (as the pipeline behaved before enrichment existed)
  - "enriched":  synthetic demo intel feed + mock CMDB/IAM (MISP disabled)
Neo4j is not used, so historical-recurrence scoring is inactive in both modes.

Reports, per mode: confusion matrix, per-class precision / recall / F1 /
false-positive rate / false-negative rate, binary "needs attention"
(HIGH+CRITICAL) metrics, over/under-escalation counts, and for every
misclassified alert its score contributions with diagnostic tags.

The labels were written by the project authors for a 20-alert synthetic set.
Treat results as a regression check on triage behaviour, not as a measure of
real-world detection accuracy.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from ingestion.cmdb import MockIAMCMDBProvider
from ingestion.enrichment import EnrichmentService
from ingestion.intel import DemoIntelFeed
from ingestion.misp import MISPClient
from orchestrator.workflow import AlertWorkflowRunner
from simulation.evaluation import PRIORITY_TO_P
from simulation.scenarios import LabeledAlert, get_benchmark_dataset

CLASSES = ["P1", "P2", "P3", "P4"]
NAMES = {"P1": "CRITICAL", "P2": "HIGH", "P3": "MEDIUM", "P4": "LOW"}
ATTENTION = {"P1", "P2"}  # analyst must look now


@dataclass
class Prediction:
    scenario_id: str
    name: str
    expected: str
    predicted: str
    score: int
    priority_rule: str
    breakdown: list[dict[str, Any]]
    tags: list[str] = field(default_factory=list)


@dataclass
class ModeResult:
    mode: str
    predictions: list[Prediction]

    @property
    def confusion(self) -> dict[str, dict[str, int]]:
        m = {a: dict.fromkeys(CLASSES, 0) for a in CLASSES}
        for pr in self.predictions:
            m[pr.expected][pr.predicted] += 1
        return m

    def per_class(self) -> dict[str, dict[str, float]]:
        m = self.confusion
        n = len(self.predictions)
        out: dict[str, dict[str, float]] = {}
        for c in CLASSES:
            tp = m[c][c]
            fp = sum(m[a][c] for a in CLASSES if a != c)
            fn = sum(m[c][p] for p in CLASSES if p != c)
            tn = n - tp - fp - fn
            precision = tp / (tp + fp) if tp + fp else 0.0
            recall = tp / (tp + fn) if tp + fn else 0.0
            out[c] = {
                "support": tp + fn,
                "precision": precision,
                "recall": recall,
                "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
                "fpr": fp / (fp + tn) if fp + tn else 0.0,
                "fnr": fn / (fn + tp) if fn + tp else 0.0,
            }
        return out

    def summary(self) -> dict[str, Any]:
        n = len(self.predictions)
        correct = sum(p.expected == p.predicted for p in self.predictions)
        per = self.per_class()
        rank = {c: i for i, c in enumerate(CLASSES)}  # P1=0 (most severe)
        over = sum(rank[p.predicted] < rank[p.expected] for p in self.predictions)
        under = sum(rank[p.predicted] > rank[p.expected] for p in self.predictions)
        tp = sum(p.expected in ATTENTION and p.predicted in ATTENTION for p in self.predictions)
        fp = sum(p.expected not in ATTENTION and p.predicted in ATTENTION for p in self.predictions)
        fn = sum(p.expected in ATTENTION and p.predicted not in ATTENTION for p in self.predictions)
        tn = n - tp - fp - fn
        return {
            "mode": self.mode,
            "samples": n,
            "accuracy": correct / n if n else 0.0,
            "macro_f1": sum(per[c]["f1"] for c in CLASSES) / len(CLASSES),
            "over_escalations": over,
            "under_escalations": under,
            "attention": {
                "precision": tp / (tp + fp) if tp + fp else 0.0,
                "recall": tp / (tp + fn) if tp + fn else 0.0,
                "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
                "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
                "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            },
            "per_class": per,
            "confusion": self.confusion,
        }


def _diagnose(pred: Prediction, raw: dict[str, Any]) -> list[str]:
    """Tag why a prediction differs from its label, using its own score contributions."""
    tags: list[str] = []
    factors = {c["factor"]: c for c in pred.breakdown}
    context = sum(c["points"] for c in pred.breakdown if c["factor"] in ("threat_intel", "asset_criticality"))
    intel = factors.get("threat_intel")
    subsumed = re.search(r"subsumes \+(\d+) external exposure", str(intel.get("detail", ""))) if intel else None
    intrinsic = pred.score - context + (int(subsumed.group(1)) if subsumed else 0)
    if "Hard rule" in pred.priority_rule:
        tags.append("hard rule applied")
    if _bucket(intrinsic) == pred.predicted:
        tags.append(f"rule/label disagreement: intrinsic detection factors alone (score {intrinsic}) reach this priority")
    elif context:
        tags.append(f"context-driven: intrinsic score {intrinsic}; asset criticality / intel moved it across a threshold")
    exposure = factors.get("external_exposure")
    if exposure and intel and str(exposure.get("evidence_ref", "")).split(":")[-1] in str(intel.get("evidence_ref", "")):
        tags.append("correlated evidence: same IP earns both external_exposure and threat_intel")
    return tags


def _bucket(score: int) -> str:
    if score >= 80:
        return "P1"
    if score >= 60:
        return "P2"
    if score >= 35:
        return "P3"
    return "P4"


async def run_mode(mode: str, dataset: list[LabeledAlert]) -> ModeResult:
    enrichment = None
    if mode == "enriched":
        enrichment = EnrichmentService(
            misp_client=MISPClient(enabled=False),
            cmdb_provider=MockIAMCMDBProvider(),
            demo_feed=DemoIntelFeed(),
        )
    runner = AlertWorkflowRunner(enable_graph_persistence=False, enrichment_service=enrichment)
    preds: list[Prediction] = []
    for item in dataset:
        out = await runner.process_alert(item.raw_alert, source="benchmark")
        t = out.triage_result
        predicted = PRIORITY_TO_P.get(t.priority.value, "P4") if t else "P4"
        pred = Prediction(
            scenario_id=item.scenario_id,
            name=item.name,
            expected=item.expected_priority,
            predicted=predicted,
            score=t.score if t else 0,
            priority_rule=(t.priority_rule or "") if t else "not triaged",
            breakdown=[c.model_dump() for c in t.score_breakdown] if t else [],
        )
        if pred.predicted != pred.expected:
            pred.tags = _diagnose(pred, item.raw_alert)
        preds.append(pred)
    return ModeResult(mode, preds)


async def run_all() -> list[ModeResult]:
    dataset = get_benchmark_dataset()
    return [await run_mode("baseline", dataset), await run_mode("enriched", dataset)]


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def to_markdown(results: list[ModeResult]) -> str:
    lines = [
        "# Detection evaluation (synthetic benchmark)",
        "",
        "Generated by `python -m simulation.benchmark --out docs/DETECTION_EVALUATION.md`. Do not edit by hand.",
        "",
        "- Dataset: `simulation/scenarios.py::get_benchmark_dataset()`, 20 synthetic alerts with project-authored labels",
        "  (P1 CRITICAL ×5, P2 HIGH ×6, P3 MEDIUM ×5, P4 LOW ×4).",
        "- **baseline**: no enrichment. **enriched**: synthetic demo intel feed + mock CMDB/IAM. MISP disabled; Neo4j unused,",
        "  so historical recurrence is inactive in both modes.",
        "- **Limitations:** tiny, synthetic, author-labelled, and not independent of the rules. Use it as a regression check,",
        "  not as an accuracy claim. Rates computed on 4–6 samples per class move in steps of 17–25 percentage points.",
        "",
        "## Summary",
        "",
        "| Mode | Accuracy | Macro-F1 | Over-escalated | Under-escalated | Attention precision | Attention recall | Attention FPR | Attention FNR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in results:
        s = r.summary()
        a = s["attention"]
        lines.append(
            f"| {r.mode} | {_pct(s['accuracy'])} | {s['macro_f1']:.3f} | {s['over_escalations']} | {s['under_escalations']} "
            f"| {_pct(a['precision'])} | {_pct(a['recall'])} | {_pct(a['false_positive_rate'])} | {_pct(a['false_negative_rate'])} |"
        )
    lines += [
        "",
        "\"Attention\" treats HIGH and CRITICAL as positive (an analyst must act now) and MEDIUM and LOW as negative.",
        "",
    ]
    for r in results:
        s = r.summary()
        lines += [f"## Mode: {r.mode}", "", "### Confusion matrix (rows = label, columns = predicted)", "",
                  "| label \\ predicted | " + " | ".join(NAMES[c] for c in CLASSES) + " |",
                  "|---|" + "---|" * len(CLASSES)]
        for a in CLASSES:
            lines.append(f"| **{NAMES[a]}** | " + " | ".join(str(s["confusion"][a][p]) for p in CLASSES) + " |")
        lines += ["", "### Per class", "", "| Class | Support | Precision | Recall | F1 | FPR | FNR |", "|---|---|---|---|---|---|---|"]
        for c in CLASSES:
            m = s["per_class"][c]
            lines.append(
                f"| {NAMES[c]} | {int(m['support'])} | {_pct(m['precision'])} | {_pct(m['recall'])} | {m['f1']:.3f} "
                f"| {_pct(m['fpr'])} | {_pct(m['fnr'])} |"
            )
        misses = [p for p in r.predictions if p.predicted != p.expected]
        lines += ["", f"### Misclassified alerts ({len(misses)})", ""]
        for p in misses:
            lines.append(f"**{p.scenario_id} — {p.name}**: label {NAMES[p.expected]}, predicted {NAMES[p.predicted]} (score {p.score})")
            lines.append("")
            for contribution in p.breakdown:
                sign = "" if contribution["factor"] == "base_severity" else ("+" if contribution["points"] >= 0 else "")
                lines.append(f"- `{sign}{contribution['points']}` {contribution['factor']}: {contribution['detail']}")
            lines.append(f"- Rule: {p.priority_rule}")
            for tag in p.tags:
                lines.append(f"- Diagnosis: {tag}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1] if __doc__ else None)
    parser.add_argument("--out", help="write Markdown report to this path")
    parser.add_argument("--json", action="store_true", help="print JSON summary instead of Markdown")
    args = parser.parse_args(argv)
    results = asyncio.run(run_all())
    if args.json:
        payload = [{**r.summary(), "misclassified": [p.__dict__ for p in r.predictions if p.predicted != p.expected]}
                   for r in results]
        print(json.dumps(payload, indent=2))
        return 0
    report = to_markdown(results)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"wrote {args.out}", file=sys.stderr)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
