"""Run detectors over a labeled corpus and produce metric reports.

A *scorer* is any callable ``CorpusExample -> float | None`` where the float is
in [0, 1] and higher means more machine-like. ``None`` means "this detector
could not produce a number for this example" (too short, model unavailable,
unsupported) — those rows are skipped and counted, never silently scored 0,
because a fabricated 0 would corrupt the false-positive rate.

Built-in scorers wrap the two text detectors that already exist:

  * ``rule_engine_scorer`` — the explainable ``SlopDetector`` composite score.
  * ``model_detector_scorer`` — a ``ModelDetector``'s ``ai_likelihood`` (the
    perplexity / Binoculars family).

The media engine is intentionally not wired here: it scores *bytes*, not the
text rows this corpus format carries, so it gets its own file-path corpus path
(documented in the eval README) rather than a forced, lossy text adapter.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from app.core.detector import SlopDetector
from app.core.model_detector import ModelDetector
from app.eval.corpus import CorpusExample
from app.eval.metrics import EvaluationReport, evaluate_scores

Scorer = Callable[[CorpusExample], float | None]


def rule_engine_scorer(profile: str = "general") -> Scorer:
    """Score with the explainable rule engine's composite [0,1] score."""
    detector = SlopDetector()

    def score(example: CorpusExample) -> float | None:
        # Honor a per-row profile if the corpus carries one in 'domain',
        # otherwise use the fixed profile. Unknown domains fall back to
        # 'general' inside analyze().
        chosen = example.domain if example.domain in {"soc", "marketing", "academic", "support"} else profile
        return detector.analyze(example.text, profile=chosen).score

    return score


def model_detector_scorer(detector: ModelDetector) -> Scorer:
    """Score with a ModelDetector's ai_likelihood; None when unavailable."""

    def score(example: CorpusExample) -> float | None:
        result = detector.analyze(example.text)
        if not result.available or result.ai_likelihood is None:
            return None
        return result.ai_likelihood

    return score


@dataclass
class RunResult:
    reports: list[EvaluationReport]

    def as_dict(self) -> dict:
        return {"reports": [report.as_dict() for report in self.reports]}


def run_scorers(
    examples: Sequence[CorpusExample],
    scorers: dict[str, Scorer],
    *,
    threshold: float = 0.5,
) -> RunResult:
    """Score the corpus with each named scorer and build per-scorer reports."""
    labels = [example.label for example in examples]
    reports: list[EvaluationReport] = []
    for name, scorer in scorers.items():
        scores: list[float] = []
        kept_labels: list[int] = []
        skipped = 0
        for example, label in zip(examples, labels, strict=True):
            value = scorer(example)
            if value is None:
                skipped += 1
                continue
            scores.append(float(value))
            kept_labels.append(label)
        notes: list[str] = []
        if skipped:
            notes.append(f"{skipped} example(s) skipped (detector returned no score)")
        if not scores:
            notes.append("no scorable examples — detector unavailable on this corpus")
            reports.append(
                EvaluationReport(
                    name=name,
                    n=0,
                    n_positive=0,
                    n_negative=0,
                    roc_auc=None,
                    tpr_at_1pct_fpr=None,
                    tpr_at_5pct_fpr=None,
                    tpr_at_10pct_fpr=None,
                    best_f1=None,
                    at_threshold=None,
                    ece=None,
                    brier=None,
                    n_skipped=skipped,
                    notes=notes,
                )
            )
            continue
        report = evaluate_scores(
            name, scores, kept_labels, threshold=threshold, n_skipped=skipped, notes=notes
        )
        reports.append(report)
    return RunResult(reports=reports)


def collect_scores(
    examples: Sequence[CorpusExample], scorer: Scorer
) -> tuple[list[float], list[int]]:
    """Score a corpus with one scorer, returning aligned (scores, labels).

    Skips rows the scorer cannot handle. Used by the calibration and
    weight-learning tools, which need the raw aligned arrays.
    """
    scores: list[float] = []
    labels: list[int] = []
    for example in examples:
        value = scorer(example)
        if value is None:
            continue
        scores.append(float(value))
        labels.append(example.label)
    return scores, labels
