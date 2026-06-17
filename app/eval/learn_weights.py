"""Learn glass-box per-signal weights from a labeled corpus.

The rule engine fires a set of named signals on a text; the hand-tuned scorer
combines them with fixed weights. This tool instead *fits* the weights: it
extracts, for each corpus example, the soft-saturated activation of every
signal, and fits a logistic regression with the signal activations as features.
The resulting coefficients are the learned per-signal weights — readable
numbers, not a black box — and drop into ``app/core/learned_weights.py`` via a
JSON file pointed to by ``SLOP_LEARNED_WEIGHTS``.

Important honesty note: fitting on a small corpus overfits. The output records
``trained_on`` (the corpus size) and a TRAIN AUC (optimistic by construction).
A real fit needs a real, held-out-evaluated corpus; treat the bundled seed as a
demonstration only. The learner deliberately defaults to strong L2
regularization so a tiny corpus produces shrunk, conservative weights rather
than wild ones.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from app.core.detector import SlopDetector
from app.core.learned_weights import scaled_activation
from app.eval.corpus import CorpusExample
from app.eval.logistic import fit_logistic
from app.eval.metrics import roc_auc


def extract_features(
    examples: Sequence[CorpusExample], detector: SlopDetector | None = None
) -> tuple[list[list[float]], list[int], list[str]]:
    """Build (feature_rows, labels, feature_names) from a corpus.

    A feature is one signal name; its value for an example is the signal's
    soft-saturated activation (0 if the signal did not fire). The feature space
    is the sorted union of every signal seen in the corpus, so coefficients map
    one-to-one onto signal names.
    """
    detector = detector or SlopDetector()
    per_example: list[dict[str, float]] = []
    seen_names: set[str] = set()
    labels: list[int] = []
    for example in examples:
        result = detector.analyze(example.text, profile=example.domain)
        activations = {
            signal.name: scaled_activation(signal.count) for signal in result.signals
        }
        per_example.append(activations)
        seen_names.update(activations)
        labels.append(example.label)
    feature_names = sorted(seen_names)
    rows = [
        [activations.get(name, 0.0) for name in feature_names]
        for activations in per_example
    ]
    return rows, labels, feature_names


@dataclass
class LearnedWeightsResult:
    bias: float
    weights: dict[str, float]
    trained_on: int
    train_auc: float | None
    l2: float

    def to_weights_file(self) -> dict:
        """The JSON shape ``LearnedWeights.from_dict`` expects."""
        return {
            "bias": round(self.bias, 6),
            "weights": {name: round(value, 6) for name, value in self.weights.items()},
            "trained_on": self.trained_on,
            "train_auc": None if self.train_auc is None else round(self.train_auc, 4),
            "l2": self.l2,
            "_note": (
                "Learned per-signal weights for SLOP_LEARNED_WEIGHTS. train_auc "
                "is optimistic (no held-out split). Refit on your own corpus."
            ),
        }


def learn_signal_weights(
    examples: Sequence[CorpusExample], *, l2: float = 2.0
) -> LearnedWeightsResult:
    """Fit the logistic and return readable weights + a (train) AUC."""
    rows, labels, feature_names = extract_features(examples)
    if not rows or not feature_names:
        raise ValueError("no signals fired across the corpus; nothing to learn")
    model = fit_logistic(rows, labels, feature_names=feature_names, l2=l2)
    train_scores = [model.predict_proba(row) for row in rows]
    return LearnedWeightsResult(
        bias=model.bias,
        weights=dict(zip(feature_names, model.coefficients, strict=True)),
        trained_on=len(examples),
        train_auc=roc_auc(train_scores, labels),
        l2=l2,
    )


def write_weights_file(result: LearnedWeightsResult, path: str | Path) -> None:
    Path(path).write_text(json.dumps(result.to_weights_file(), indent=2), encoding="utf-8")
