"""Evaluation harness for the GN Slop Detection engines.

Detection thresholds and signal weights across the project (burstiness,
MATTR, perplexity midpoints, per-signal weights, risk bands) were hand-tuned
against intuition, not measured against labeled human-vs-AI text. That makes
"is this good?" unanswerable and "is this state of the art?" unverifiable.

This package fixes the measurement gap. It is pure-Python (no numpy / sklearn /
pandas — same no-mandatory-dependency philosophy as the rest of the engine):

  * ``corpus``   — load a labeled JSONL corpus (text + human/ai label).
  * ``metrics``  — ROC-AUC, TPR@fixed-FPR, precision/recall/F1, ECE, Brier,
                   computed by hand so the numbers are auditable.
  * ``runner``   — score a corpus with any engine (text rule engine, a
                   ``ModelDetector``, the media engine) and emit a report.
  * ``calibrate``— fit a monotonic score->probability map (Platt scaling) so an
                   "uncalibrated heuristic" becomes a probability with a known
                   operating point.

Nothing here runs at request time; it is an offline analyst / CI tool.
"""

from __future__ import annotations

from app.eval.corpus import CorpusExample, load_corpus
from app.eval.metrics import (
    EvaluationReport,
    binary_metrics_at_threshold,
    evaluate_scores,
    roc_auc,
    tpr_at_fpr,
)

__all__ = [
    "CorpusExample",
    "EvaluationReport",
    "binary_metrics_at_threshold",
    "evaluate_scores",
    "load_corpus",
    "roc_auc",
    "tpr_at_fpr",
]
