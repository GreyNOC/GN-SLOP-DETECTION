"""Turn raw detector scores into calibrated probabilities.

Several scores in this project are admittedly uncalibrated: the rule engine's
composite, and especially the perplexity->likelihood map in
``model_detector.py`` (its ``_PPL_MIDPOINT`` / ``_PPL_STEEPNESS`` are explicit
guesses). "Uncalibrated" means a 0.8 does not mean "80% likely AI" — it is just
an ordinal. Calibration fixes that against a labeled corpus so an operating
threshold means what it says.

Two fits are provided, both via the dependency-free logistic in ``logistic``:

  * ``fit_platt`` — generic Platt scaling: map any raw score to a probability.
  * ``fit_perplexity_mapping`` — recover the exact (midpoint, steepness) that
    ``model_detector._perplexity_to_likelihood`` already takes, so a fitted
    result drops straight into that function with no code change.

Both report calibration quality (ECE + Brier) before and after, so the analyst
can see whether calibration actually helped or the corpus was too small to fit.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from app.eval.logistic import LogisticModel, fit_logistic
from app.eval.metrics import brier_score, expected_calibration_error


@dataclass
class CalibrationResult:
    model: LogisticModel
    ece_before: float | None
    ece_after: float | None
    brier_before: float | None
    brier_after: float | None
    n: int

    def as_dict(self) -> dict:
        return {
            "model": self.model.as_dict(),
            "n": self.n,
            "ece_before": None if self.ece_before is None else round(self.ece_before, 4),
            "ece_after": None if self.ece_after is None else round(self.ece_after, 4),
            "brier_before": None if self.brier_before is None else round(self.brier_before, 4),
            "brier_after": None if self.brier_after is None else round(self.brier_after, 4),
        }


def fit_platt(
    scores: Sequence[float], labels: Sequence[int], *, l2: float = 1.0
) -> CalibrationResult:
    """Platt scaling: logistic map from a single raw score to a probability."""
    if len(scores) != len(labels):
        raise ValueError("scores/labels length mismatch")
    features = [[float(s)] for s in scores]
    model = fit_logistic(features, labels, feature_names=["score"], l2=l2)
    calibrated = [model.predict_proba([float(s)]) for s in scores]
    # ECE/Brier on the raw scores is only meaningful if they're already in
    # [0,1]; the helpers return None otherwise, which we surface honestly.
    return CalibrationResult(
        model=model,
        ece_before=expected_calibration_error(scores, labels),
        ece_after=expected_calibration_error(calibrated, labels),
        brier_before=brier_score(scores, labels),
        brier_after=brier_score(calibrated, labels),
        n=len(scores),
    )


@dataclass
class PerplexityMapping:
    midpoint: float
    steepness: float
    n: int
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "midpoint": round(self.midpoint, 4),
            "steepness": round(self.steepness, 4),
            "n": self.n,
            "note": self.note,
        }


def fit_perplexity_mapping(
    perplexities: Sequence[float], labels: Sequence[int], *, l2: float = 0.0
) -> PerplexityMapping | None:
    """Fit ``model_detector``'s ``(midpoint, steepness)`` from labeled perplexity.

    ``_perplexity_to_likelihood`` computes ``sigmoid((midpoint - ppl) / steep)``.
    A logistic fit on the single feature ``ppl`` gives
    ``sigmoid(bias + coef * ppl)``; matching the two forms yields
    ``steepness = -1 / coef`` and ``midpoint = -bias / coef``. The fit is only
    valid when ``coef < 0`` (lower perplexity really does map to more AI-like in
    this corpus); otherwise we return ``None`` rather than emit a backwards map.

    The goal here is exact coefficient *recovery*, not predictive shrinkage, so
    ``l2`` defaults to ``0.0`` — any nonzero penalty shrinks ``coef`` toward zero
    and so inflates ``steepness = -1/coef`` and biases ``midpoint = -bias/coef``.
    """
    if len(perplexities) != len(labels):
        raise ValueError("perplexities/labels length mismatch")
    if not perplexities:
        return None
    features = [[float(p)] for p in perplexities]
    model = fit_logistic(features, labels, feature_names=["perplexity"], l2=l2)
    coef = model.coefficients[0]
    if coef >= 0:
        return PerplexityMapping(
            midpoint=0.0,
            steepness=0.0,
            n=len(perplexities),
            note=(
                "fit failed: perplexity did not separate the classes in the "
                "expected direction (coef >= 0). Corpus too small or mismatched "
                "to the scoring model."
            ),
        )
    steepness = -1.0 / coef
    midpoint = -model.bias / coef
    return PerplexityMapping(
        midpoint=midpoint,
        steepness=steepness,
        n=len(perplexities),
        note="drop into model_detector._PPL_MIDPOINT / _PPL_STEEPNESS",
    )
