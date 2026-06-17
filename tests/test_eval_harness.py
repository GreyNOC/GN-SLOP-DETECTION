"""Tests for the evaluation harness (app/eval).

The metric math is the load-bearing part — a wrong AUC silently corrupts every
calibration decision — so it is checked against hand-computed known answers,
not just "runs without error".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.eval.calibrate import fit_perplexity_mapping, fit_platt
from app.eval.corpus import CorpusError, load_corpus
from app.eval.logistic import fit_logistic
from app.eval.metrics import (
    binary_metrics_at_threshold,
    brier_score,
    evaluate_scores,
    expected_calibration_error,
    roc_auc,
    tpr_at_fpr,
)
from app.eval.runner import collect_scores, rule_engine_scorer, run_scorers

_SEED = Path(__file__).resolve().parents[1] / "app" / "eval" / "data" / "seed_corpus.jsonl"


# --- ROC-AUC known answers -------------------------------------------------

def test_auc_perfect_separation() -> None:
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [1, 1, 0, 0]
    assert roc_auc(scores, labels) == 1.0


def test_auc_perfectly_wrong() -> None:
    scores = [0.1, 0.2, 0.8, 0.9]
    labels = [1, 1, 0, 0]
    assert roc_auc(scores, labels) == 0.0


def test_auc_all_tied_is_half() -> None:
    scores = [0.5, 0.5, 0.5, 0.5]
    labels = [1, 0, 1, 0]
    assert roc_auc(scores, labels) == 0.5


def test_auc_single_class_is_none() -> None:
    assert roc_auc([0.1, 0.2, 0.3], [1, 1, 1]) is None


def test_auc_known_fractional() -> None:
    # pos={0.6, 0.4}, neg={0.5, 0.3}. Pairs: (.6>.5)1 (.6>.3)1 (.4<.5)0
    # (.4>.3)1 => 3/4 = 0.75.
    scores = [0.6, 0.4, 0.5, 0.3]
    labels = [1, 1, 0, 0]
    assert roc_auc(scores, labels) == 0.75


def test_auc_tie_across_classes_counts_half() -> None:
    # One positive and one negative tie at 0.5; that pair contributes 0.5.
    # pos={0.5}, neg={0.5} -> AUC 0.5.
    assert roc_auc([0.5, 0.5], [1, 0]) == 0.5


# --- TPR @ FPR -------------------------------------------------------------

def test_tpr_at_fpr_perfect() -> None:
    scores = [0.9, 0.8, 0.2, 0.1]
    labels = [1, 1, 0, 0]
    # Perfect separation: even at 0% FPR we catch everything.
    assert tpr_at_fpr(scores, labels, 0.0) == 1.0


def test_tpr_at_fpr_budget_limits_recall() -> None:
    # Scores interleave so catching the 2nd positive costs a false positive.
    scores = [0.9, 0.6, 0.7, 0.2]
    labels = [1, 1, 0, 0]
    # At 0% FPR, threshold just above 0.7 catches only the 0.9 positive -> 0.5.
    assert tpr_at_fpr(scores, labels, 0.0) == 0.5
    # Allowing 50% FPR lets the 0.6 positive through -> 1.0.
    assert tpr_at_fpr(scores, labels, 0.5) == 1.0


# --- threshold metrics -----------------------------------------------------

def test_binary_metrics_confusion() -> None:
    scores = [0.9, 0.4, 0.8, 0.2]
    labels = [1, 1, 0, 0]
    m = binary_metrics_at_threshold(scores, labels, 0.5)
    # >=0.5 predicts positive: 0.9(tp), 0.8(fp). 0.4(fn), 0.2(tn).
    assert (m.tp, m.fp, m.tn, m.fn) == (1, 1, 1, 1)
    assert m.precision == 0.5
    assert m.recall == 0.5
    assert m.fpr == 0.5


# --- calibration metrics ---------------------------------------------------

def test_ece_rejects_out_of_range_scores() -> None:
    assert expected_calibration_error([1.5, -0.2], [1, 0]) is None


def test_brier_perfect_is_zero() -> None:
    assert brier_score([1.0, 0.0], [1, 0]) == 0.0


def test_evaluate_scores_full_report() -> None:
    scores = [0.9, 0.8, 0.7, 0.2, 0.1, 0.05]
    labels = [1, 1, 1, 0, 0, 0]
    report = evaluate_scores("t", scores, labels)
    assert report.roc_auc == 1.0
    assert report.n_positive == 3
    assert report.best_f1 is not None and report.best_f1.f1 == 1.0


# --- logistic regression ---------------------------------------------------

def test_logistic_separable_learns_direction() -> None:
    features = [[x] for x in (-3, -2, -1, 1, 2, 3)]
    labels = [0, 0, 0, 1, 1, 1]
    model = fit_logistic(features, labels, feature_names=["x"], l2=0.01)
    assert model.coefficients[0] > 0  # higher x -> higher P(positive)
    assert model.predict_proba([3]) > model.predict_proba([-3])


def test_logistic_constant_feature_safe() -> None:
    # A constant column must not divide-by-zero; it just carries no signal.
    features = [[1.0, x] for x in (-2, -1, 1, 2)]
    labels = [0, 0, 1, 1]
    model = fit_logistic(features, labels, feature_names=["const", "x"])
    assert model.coefficients[1] > 0


# --- Platt + perplexity mapping --------------------------------------------

def test_platt_improves_calibration_on_miscalibrated_scores() -> None:
    # Scores are ordinally correct but compressed into [0.4, 0.6]; Platt should
    # spread them and reduce Brier.
    scores = [0.6, 0.58, 0.55, 0.45, 0.42, 0.4]
    labels = [1, 1, 1, 0, 0, 0]
    result = fit_platt(scores, labels, l2=0.01)
    assert result.brier_after is not None and result.brier_before is not None
    assert result.brier_after < result.brier_before


def test_perplexity_mapping_recovers_direction() -> None:
    # Low perplexity should map to AI (label 1). Fit must yield a usable map.
    perplexities = [10, 20, 30, 80, 100, 120]
    labels = [1, 1, 1, 0, 0, 0]
    mapping = fit_perplexity_mapping(perplexities, labels, l2=0.01)
    assert mapping is not None
    assert mapping.steepness > 0
    # Midpoint should sit between the two clusters.
    assert 30 < mapping.midpoint < 90


def test_perplexity_mapping_reports_backwards_fit() -> None:
    # Higher perplexity labeled AI is the wrong direction; fit must refuse.
    perplexities = [10, 20, 30, 80, 100, 120]
    labels = [0, 0, 0, 1, 1, 1]
    mapping = fit_perplexity_mapping(perplexities, labels, l2=0.01)
    assert mapping is not None
    assert mapping.steepness == 0.0 and "fit failed" in mapping.note


# --- corpus loading --------------------------------------------------------

def test_seed_corpus_loads_and_is_balanced() -> None:
    examples, stats = load_corpus(_SEED)
    assert stats.n >= 20
    # Reasonably balanced (within a couple rows).
    assert abs(stats.n_positive - stats.n_negative) <= 2
    assert stats.duplicate_texts == 0


def test_corpus_rejects_bad_label(tmp_path: Path) -> None:
    bad = tmp_path / "bad.jsonl"
    bad.write_text(json.dumps({"text": "hi there", "label": "spam"}) + "\n", encoding="utf-8")
    with pytest.raises(CorpusError):
        load_corpus(bad)


def test_corpus_lenient_skips_bad_rows(tmp_path: Path) -> None:
    path = tmp_path / "mixed.jsonl"
    path.write_text(
        json.dumps({"text": "a real human sentence here", "label": "human"})
        + "\n" + "{not json}\n"
        + json.dumps({"text": "clearly generated slop", "label": "ai"}) + "\n",
        encoding="utf-8",
    )
    examples, stats = load_corpus(path, lenient=True)
    assert len(examples) == 2
    assert stats.n_skipped == 1


# --- end-to-end runner -----------------------------------------------------

def test_rule_engine_separates_seed_corpus() -> None:
    examples, _ = load_corpus(_SEED)
    result = run_scorers(examples, {"rule_engine": rule_engine_scorer()})
    report = result.reports[0]
    # The seed corpus is deliberately easy; the engine should separate it well.
    assert report.roc_auc is not None and report.roc_auc > 0.85


def test_collect_scores_aligns_with_labels() -> None:
    examples, _ = load_corpus(_SEED)
    scores, labels = collect_scores(examples, rule_engine_scorer())
    assert len(scores) == len(labels) == len(examples)
    assert all(0.0 <= s <= 1.0 for s in scores)
