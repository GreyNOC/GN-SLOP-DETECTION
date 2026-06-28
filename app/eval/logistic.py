"""A tiny, dependency-free logistic regression.

Two places in the harness need to fit a logistic model and neither justifies
pulling in scikit-learn (which would violate the project's
no-mandatory-heavy-dependency rule and ship a 30 MB wheel for ~60 lines of
math):

  * **Platt scaling** (``calibrate.py``) — one feature (a raw detector score),
    mapping it to a calibrated probability.
  * **Glass-box signal weights** (``learn_weights.py``) — many features (the
    per-signal activations of the rule engine), learning interpretable
    coefficients.

The model is standardized full-batch gradient descent with L2 regularization.
It standardizes inputs internally for numerical stability but exposes
coefficients in the ORIGINAL feature space via ``raw_coefficients`` so the
learned weights stay human-readable. Determinism matters (CI must reproduce a
fit), so there is no randomness: weights start at zero and the data order is
the caller's.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass


def _sigmoid(z: float) -> float:
    # Numerically stable logistic.
    if z >= 0:
        ez = math.exp(-z)
        return 1.0 / (1.0 + ez)
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass
class LogisticModel:
    """A fitted logistic regression in the ORIGINAL feature space.

    ``predict_proba(x) = sigmoid(bias + sum_i coef[i] * x[i])``.
    """

    coefficients: list[float]
    bias: float
    feature_names: list[str]

    def predict_proba(self, features: Sequence[float]) -> float:
        if len(features) != len(self.coefficients):
            raise ValueError("feature length mismatch")
        z = self.bias + sum(c * x for c, x in zip(self.coefficients, features, strict=True))
        return _sigmoid(z)

    def as_dict(self) -> dict:
        return {
            "bias": round(self.bias, 6),
            "coefficients": {
                name: round(coef, 6)
                for name, coef in zip(self.feature_names, self.coefficients, strict=True)
            },
        }


def fit_logistic(
    features: Sequence[Sequence[float]],
    labels: Sequence[int],
    *,
    feature_names: Sequence[str] | None = None,
    l2: float = 1.0,
    learning_rate: float = 0.1,
    iterations: int = 2000,
) -> LogisticModel:
    """Fit an L2-regularized logistic regression with full-batch gradient descent.

    ``l2`` is the regularization strength (higher == stronger shrinkage toward
    zero, which is what keeps a tiny corpus from producing wild coefficients).
    The intercept is never regularized. Returns a model whose coefficients are
    expressed in the original (un-standardized) feature space.

    Note on the objective: both the data loss and the penalty are averaged over
    ``n`` (the gradient adds ``l2 * w_j / n``), so the effective penalty is
    ``l2/n`` — by design. Because the data term is a *mean* loss (O(1) in ``n``),
    this keeps the penalty's pull strongest exactly where it is needed, on tiny
    corpora, and lets it relax as more data accumulates. The trade-off is that a
    given ``l2`` is corpus-size relative, not absolute: re-tune it if you change
    ``n`` by an order of magnitude. The ``calibrate`` recovery path sidesteps
    this entirely by defaulting ``l2=0``.
    """
    n = len(labels)
    if n == 0:
        raise ValueError("cannot fit on an empty dataset")
    d = len(features[0])
    if any(len(row) != d for row in features):
        raise ValueError("all feature rows must have the same length")
    if feature_names is None:
        feature_names = [f"f{i}" for i in range(d)]
    if len(feature_names) != d:
        raise ValueError("feature_names length must match feature dimension")

    # Standardize each column (mean 0, std 1). Constant columns get std 1 so
    # they contribute only through the intercept and never blow up.
    means = [sum(row[j] for row in features) / n for j in range(d)]
    stds: list[float] = []
    for j in range(d):
        variance = sum((row[j] - means[j]) ** 2 for row in features) / n
        std = math.sqrt(variance)
        stds.append(std if std > 1e-12 else 1.0)
    standardized = [
        [(row[j] - means[j]) / stds[j] for j in range(d)] for row in features
    ]

    weights = [0.0] * d
    bias = 0.0
    for _ in range(iterations):
        grad_w = [0.0] * d
        grad_b = 0.0
        for row, label in zip(standardized, labels, strict=True):
            z = bias + sum(weights[j] * row[j] for j in range(d))
            error = _sigmoid(z) - label
            grad_b += error
            for j in range(d):
                grad_w[j] += error * row[j]
        # Mean gradient + L2 (intercept excluded from the penalty).
        for j in range(d):
            grad_w[j] = grad_w[j] / n + l2 * weights[j] / n
        grad_b /= n
        for j in range(d):
            weights[j] -= learning_rate * grad_w[j]
        bias -= learning_rate * grad_b

    # Un-standardize: w_orig[j] = w_std[j] / std[j];
    # bias_orig = bias_std - sum_j w_std[j] * mean[j] / std[j].
    raw_coefficients = [weights[j] / stds[j] for j in range(d)]
    raw_bias = bias - sum(weights[j] * means[j] / stds[j] for j in range(d))
    return LogisticModel(
        coefficients=raw_coefficients,
        bias=raw_bias,
        feature_names=list(feature_names),
    )
