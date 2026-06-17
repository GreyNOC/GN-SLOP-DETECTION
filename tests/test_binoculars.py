"""Tests for the Binoculars detector (SOTA zero-shot, opt-in).

The two-model scoring needs torch + a network download, so the live path is
not exercised here; instead the pure score/likelihood math is checked against
known answers, and the detector contract is exercised by injecting synthetic
cross-entropies — exactly the pattern used for TransformersDetector.
"""

from __future__ import annotations

import pytest

from app.core.model_detector import (
    BinocularsDetector,
    ModelDetector,
    _binoculars_score,
    _binoculars_to_likelihood,
    _TokenizerMismatch,
    available_detectors,
    select_model_detector,
)

# ---------- pure score math ------------------------------------------------


def test_binoculars_score_is_the_ratio() -> None:
    assert _binoculars_score(0.8, 1.0) == pytest.approx(0.8)
    assert _binoculars_score(1.2, 1.0) == pytest.approx(1.2)


def test_binoculars_score_guards_zero_denominator() -> None:
    # Degenerate identical-distribution case -> "looks human" (inf), not a crash.
    assert _binoculars_score(0.5, 0.0) == float("inf")


def test_binoculars_likelihood_decreasing_and_bounded() -> None:
    low_b = _binoculars_to_likelihood(0.6)   # very machine-like
    mid_b = _binoculars_to_likelihood(0.9)   # midpoint
    high_b = _binoculars_to_likelihood(1.3)  # very human-like
    assert 0.0 <= high_b < mid_b < low_b <= 1.0
    assert mid_b == pytest.approx(0.5, abs=1e-9)


def test_binoculars_likelihood_clamps_extremes() -> None:
    assert _binoculars_to_likelihood(-100.0) == 1.0
    assert _binoculars_to_likelihood(100.0) == 0.0


# ---------- detector contract (no torch) -----------------------------------


def test_binoculars_low_score_reads_as_machine(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)
    # CE well below XCE -> B < midpoint -> machine-like.
    monkeypatch.setattr(det, "_cross_entropies", lambda text: (0.7, 1.0, 40))
    result = det.analyze("x")
    assert result.available is True
    assert result.ai_likelihood is not None and result.ai_likelihood > 0.5
    assert "binoculars_score" in result.extra
    assert result.extra["observer"] == "gpt2"


def test_binoculars_high_score_reads_as_human(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)
    monkeypatch.setattr(det, "_cross_entropies", lambda text: (1.2, 1.0, 40))
    result = det.analyze("x")
    assert result.available is True
    assert result.ai_likelihood is not None and result.ai_likelihood < 0.5


def test_binoculars_too_short_is_unavailable(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)
    monkeypatch.setattr(det, "_cross_entropies", lambda text: (0.7, 1.0, 5))
    result = det.analyze("hi")
    assert result.available is False
    assert result.ai_likelihood is None


def test_binoculars_tokenizer_mismatch_is_honest(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)

    def mismatched(text):  # noqa: ARG001
        raise _TokenizerMismatch("different vocab sizes")

    monkeypatch.setattr(det, "_cross_entropies", mismatched)
    result = det.analyze("x")
    assert result.available is False
    assert "vocab" in result.detail


def test_binoculars_scoring_failure_is_swallowed(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)

    def boom(text):  # noqa: ARG001
        raise RuntimeError("oom")

    monkeypatch.setattr(det, "_cross_entropies", boom)
    assert det.analyze("x").available is False


def test_binoculars_unavailable_without_deps(monkeypatch) -> None:
    det = BinocularsDetector()
    monkeypatch.setattr(det, "is_available", lambda: False)
    result = det.analyze("x")
    assert result.available is False
    assert result.ai_likelihood is None


# ---------- registry / selection -------------------------------------------


def test_binoculars_is_registered_and_conformant() -> None:
    assert "binoculars" in available_detectors()
    assert isinstance(BinocularsDetector(), ModelDetector)


def test_binoculars_env_selection(monkeypatch) -> None:
    monkeypatch.setenv("SLOP_MODEL_DETECTOR", "binoculars")
    assert select_model_detector(None).name == "binoculars"


def test_binoculars_model_pair_from_env(monkeypatch) -> None:
    monkeypatch.setenv("SLOP_BINOCULARS_OBSERVER", "falcon-7b")
    monkeypatch.setenv("SLOP_BINOCULARS_PERFORMER", "falcon-7b-instruct")
    det = BinocularsDetector()
    assert det._observer_id == "falcon-7b"
    assert det._performer_id == "falcon-7b-instruct"
