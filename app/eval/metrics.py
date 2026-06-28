"""Hand-rolled detection metrics — no numpy, no sklearn.

Everything here operates on the standard convention used throughout this
package:

    label 1 == the POSITIVE class == "machine-generated / slop"
    label 0 == the NEGATIVE class == "human / authentic"
    score   == a real number where HIGHER means MORE machine-like.

The headline numbers for a text detector are deliberately chosen to match how
the detection literature reports results:

  * **ROC-AUC** — threshold-free separability.
  * **TPR @ fixed FPR** (1%, 5%, 10%) — the number that actually matters for a
    review tool. A detector that catches 95% of AI text while wrongly flagging
    20% of human writing is useless (and, per Liang et al. 2023, that human
    error lands hardest on non-native English writers). Reporting TPR at a
    pinned low FPR forces the false-positive cost into the open.
  * **Precision / recall / F1 / accuracy** at a chosen operating threshold.
  * **ECE / Brier** — calibration quality, for when a score is meant to be read
    as a probability.

The implementations favor clarity and correctness (average-rank AUC for ties,
explicit ROC sweep) over speed; corpora here are thousands of rows, not
millions.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

Number = float | int


def _validate(scores: Sequence[Number], labels: Sequence[int]) -> None:
    if len(scores) != len(labels):
        raise ValueError(f"scores/labels length mismatch: {len(scores)} != {len(labels)}")
    for label in labels:
        if label not in (0, 1):
            raise ValueError(f"labels must be 0 or 1, got {label!r}")
    # Reject NaN/inf up front. A NaN compares False to everything, so it would
    # silently corrupt rank-based AUC/ROC ordering and slip past the [0,1]
    # range guards in ECE/Brier — fail closed for every metric instead.
    for score in scores:
        if not math.isfinite(score):
            raise ValueError(f"scores must be finite, got {score!r}")


def roc_auc(scores: Sequence[Number], labels: Sequence[int]) -> float | None:
    """Area under the ROC curve via the Mann-Whitney U (rank-sum) identity.

    Ties are handled with average ranks, so AUC == 0.5 for constant scores.
    Returns ``None`` when the corpus has only one class (AUC undefined).
    """
    _validate(scores, labels)
    n_pos = sum(1 for label in labels if label == 1)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return None

    # Average ranks, 1-based, over scores sorted ascending.
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and scores[order[j + 1]] == scores[order[i]]:
            j += 1
        average_rank = (i + j) / 2.0 + 1.0  # midpoint of the tied block, 1-based
        for k in range(i, j + 1):
            ranks[order[k]] = average_rank
        i = j + 1

    rank_sum_pos = sum(ranks[i] for i in range(len(labels)) if labels[i] == 1)
    u_pos = rank_sum_pos - n_pos * (n_pos + 1) / 2.0
    return u_pos / (n_pos * n_neg)


@dataclass(frozen=True)
class RocPoint:
    threshold: float
    fpr: float
    tpr: float


def roc_curve(scores: Sequence[Number], labels: Sequence[int]) -> list[RocPoint]:
    """ROC curve as (threshold, fpr, tpr) points, fpr ascending.

    Decision rule at threshold ``t`` is ``score >= t -> positive``. The curve
    is anchored at (0,0) and (1,1) so interpolation is always well-defined.
    """
    _validate(scores, labels)
    n_pos = sum(1 for label in labels if label == 1)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return []

    # Sort by score descending; lowering the threshold reveals points in order.
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    points: list[RocPoint] = [RocPoint(threshold=float("inf"), fpr=0.0, tpr=0.0)]
    tp = 0
    fp = 0
    i = 0
    while i < len(order):
        threshold = float(scores[order[i]])
        # Consume every example tied at this score before recording a point,
        # otherwise the curve double-counts ties.
        while i < len(order) and scores[order[i]] == threshold:
            if labels[order[i]] == 1:
                tp += 1
            else:
                fp += 1
            i += 1
        points.append(RocPoint(threshold=threshold, fpr=fp / n_neg, tpr=tp / n_pos))
    return points


def tpr_at_fpr(scores: Sequence[Number], labels: Sequence[int], target_fpr: float) -> float | None:
    """Max TPR achievable without exceeding ``target_fpr``, linearly interpolated.

    This is the operating-point question a reviewer actually asks: "if I will
    tolerate flagging at most 5% of genuine human text, how much AI text do I
    catch?" Returns ``None`` if the corpus has only one class.
    """
    if not 0.0 <= target_fpr <= 1.0:
        raise ValueError("target_fpr must be in [0, 1]")
    curve = roc_curve(scores, labels)
    if not curve:
        return None
    best = 0.0
    prev = curve[0]
    for point in curve:
        if point.fpr <= target_fpr:
            best = max(best, point.tpr)
            prev = point
            continue
        # The target FPR falls between prev and point; interpolate the TPR so
        # we neither over- nor under-credit the detector at the exact budget.
        if point.fpr > prev.fpr:
            frac = (target_fpr - prev.fpr) / (point.fpr - prev.fpr)
            interpolated = prev.tpr + frac * (point.tpr - prev.tpr)
            best = max(best, interpolated)
        break
    return best


@dataclass(frozen=True)
class ThresholdMetrics:
    threshold: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    accuracy: float
    fpr: float

    def as_dict(self) -> dict[str, float]:
        return {
            "threshold": round(self.threshold, 4),
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
            "fpr": round(self.fpr, 4),
        }


def binary_metrics_at_threshold(
    scores: Sequence[Number], labels: Sequence[int], threshold: float
) -> ThresholdMetrics:
    """Confusion-matrix-derived metrics for ``score >= threshold -> positive``."""
    _validate(scores, labels)
    tp = fp = tn = fn = 0
    for score, label in zip(scores, labels, strict=True):
        predicted = 1 if score >= threshold else 0
        if predicted == 1 and label == 1:
            tp += 1
        elif predicted == 1 and label == 0:
            fp += 1
        elif predicted == 0 and label == 0:
            tn += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(labels) if labels else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return ThresholdMetrics(threshold, tp, fp, tn, fn, precision, recall, f1, accuracy, fpr)


def best_f1_threshold(scores: Sequence[Number], labels: Sequence[int]) -> ThresholdMetrics | None:
    """Sweep candidate thresholds and return the one with the highest F1.

    Candidate thresholds are the distinct scores (the only places the
    confusion matrix can change). Ties break toward the higher threshold
    (fewer positives), which is the conservative choice for a review tool.
    """
    _validate(scores, labels)
    if not scores:
        return None
    candidates = sorted(set(float(s) for s in scores), reverse=True)
    best: ThresholdMetrics | None = None
    for threshold in candidates:
        metrics = binary_metrics_at_threshold(scores, labels, threshold)
        if best is None or metrics.f1 > best.f1:
            best = metrics
    return best


def expected_calibration_error(
    scores: Sequence[Number], labels: Sequence[int], bins: int = 10
) -> float | None:
    """Expected Calibration Error over equal-width probability bins.

    Only meaningful when ``scores`` are intended as probabilities in [0,1]
    (e.g. after calibration). Returns ``None`` if any score is out of range so
    a caller never reads ECE off a raw, unbounded detector score by mistake.
    """
    _validate(scores, labels)
    if not scores or bins < 1:
        return None
    if any(score < 0.0 or score > 1.0 for score in scores):
        return None
    bin_total = [0] * bins
    bin_conf = [0.0] * bins
    bin_pos = [0] * bins
    for score, label in zip(scores, labels, strict=True):
        index = min(bins - 1, int(score * bins))
        bin_total[index] += 1
        bin_conf[index] += float(score)
        bin_pos[index] += label
    n = len(scores)
    ece = 0.0
    for index in range(bins):
        if bin_total[index] == 0:
            continue
        confidence = bin_conf[index] / bin_total[index]
        accuracy = bin_pos[index] / bin_total[index]
        ece += (bin_total[index] / n) * abs(confidence - accuracy)
    return ece


def brier_score(scores: Sequence[Number], labels: Sequence[int]) -> float | None:
    """Mean squared error between probability scores and labels."""
    _validate(scores, labels)
    if not scores:
        return None
    if any(score < 0.0 or score > 1.0 for score in scores):
        return None
    return sum((float(s) - label) ** 2 for s, label in zip(scores, labels, strict=True)) / len(scores)


@dataclass
class EvaluationReport:
    """The full metric picture for one detector over one corpus."""

    name: str
    n: int
    n_positive: int
    n_negative: int
    roc_auc: float | None
    tpr_at_1pct_fpr: float | None
    tpr_at_5pct_fpr: float | None
    tpr_at_10pct_fpr: float | None
    best_f1: ThresholdMetrics | None
    at_threshold: ThresholdMetrics | None
    ece: float | None
    brier: float | None
    n_skipped: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "n": self.n,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "n_skipped": self.n_skipped,
            "roc_auc": None if self.roc_auc is None else round(self.roc_auc, 4),
            "tpr_at_1pct_fpr": None if self.tpr_at_1pct_fpr is None else round(self.tpr_at_1pct_fpr, 4),
            "tpr_at_5pct_fpr": None if self.tpr_at_5pct_fpr is None else round(self.tpr_at_5pct_fpr, 4),
            "tpr_at_10pct_fpr": None if self.tpr_at_10pct_fpr is None else round(self.tpr_at_10pct_fpr, 4),
            "best_f1": None if self.best_f1 is None else self.best_f1.as_dict(),
            "at_threshold": None if self.at_threshold is None else self.at_threshold.as_dict(),
            "ece": None if self.ece is None else round(self.ece, 4),
            "brier": None if self.brier is None else round(self.brier, 4),
            "notes": self.notes,
        }


def evaluate_scores(
    name: str,
    scores: Sequence[Number],
    labels: Sequence[int],
    *,
    threshold: float = 0.5,
    n_skipped: int = 0,
    notes: Sequence[str] | None = None,
) -> EvaluationReport:
    """Compute the full report from aligned score/label sequences."""
    _validate(scores, labels)
    n_pos = sum(1 for label in labels if label == 1)
    n_neg = len(labels) - n_pos
    return EvaluationReport(
        name=name,
        n=len(labels),
        n_positive=n_pos,
        n_negative=n_neg,
        roc_auc=roc_auc(scores, labels),
        tpr_at_1pct_fpr=tpr_at_fpr(scores, labels, 0.01),
        tpr_at_5pct_fpr=tpr_at_fpr(scores, labels, 0.05),
        tpr_at_10pct_fpr=tpr_at_fpr(scores, labels, 0.10),
        best_f1=best_f1_threshold(scores, labels),
        at_threshold=binary_metrics_at_threshold(scores, labels, threshold) if scores else None,
        ece=expected_calibration_error(scores, labels),
        brier=brier_score(scores, labels),
        n_skipped=n_skipped,
        notes=list(notes or []),
    )
