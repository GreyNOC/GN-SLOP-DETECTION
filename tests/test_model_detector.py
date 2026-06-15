"""Tests for the ModelDetector extension point (Track C).

The default is an honest "unavailable" detector that emits NO number; the
optional perplexity math is unit-tested without torch by feeding synthetic
log-probs. Wiring into the text engine and the API is additive — default
behavior is byte-unchanged.
"""

from __future__ import annotations

import pytest

from app.core.detector import SlopDetector
from app.core.model_detector import (
    ModelDetector,
    ModelDetectorResult,
    TransformersDetector,
    UnavailableModelDetector,
    _mean_token_log_prob,
    _perplexity_from_mean_logprob,
    _perplexity_to_likelihood,
    select_model_detector,
)

# ---------- result invariants ---------------------------------------------


def test_result_clamps_likelihood() -> None:
    assert ModelDetectorResult("m", True, 1.5).ai_likelihood == 1.0
    assert ModelDetectorResult("m", True, -0.5).ai_likelihood == 0.0


def test_result_rejects_available_without_number() -> None:
    with pytest.raises(ValueError):
        ModelDetectorResult("m", available=True)


def test_result_rejects_unavailable_with_number() -> None:
    with pytest.raises(ValueError):
        ModelDetectorResult("m", available=False, ai_likelihood=0.5)


# ---------- honest default ------------------------------------------------


def test_default_detector_is_unavailable_with_no_number() -> None:
    result = UnavailableModelDetector().analyze("some text")
    assert result.available is False
    assert result.ai_likelihood is None  # no fabricated score
    assert result.detail
    assert isinstance(UnavailableModelDetector(), ModelDetector)  # Protocol conformance


# ---------- perplexity -> likelihood math ---------------------------------


def test_perplexity_to_likelihood_is_monotonic_and_bounded() -> None:
    low_ppl = _perplexity_to_likelihood(10.0)
    mid_ppl = _perplexity_to_likelihood(60.0)
    high_ppl = _perplexity_to_likelihood(200.0)
    assert 0.0 <= high_ppl < mid_ppl < low_ppl <= 1.0
    assert mid_ppl == pytest.approx(0.5, abs=1e-9)  # midpoint crosses 0.5


def test_perplexity_helpers_compose() -> None:
    # Mean log-prob of -1.0 nat/token -> perplexity e^1 ~= 2.718.
    ppl = _perplexity_from_mean_logprob(_mean_token_log_prob([-1.0, -1.0, -1.0]))
    assert ppl == pytest.approx(2.718, abs=1e-2)


# ---------- transformers backend (no torch needed) ------------------------


def test_transformers_scores_from_injected_logprobs(monkeypatch) -> None:
    det = TransformersDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)
    # 30 very-predictable tokens (log-prob ~ -0.2 -> low perplexity).
    monkeypatch.setattr(det, "_token_log_probs", lambda text: [-0.2] * 30)
    result = det.analyze("x")
    assert result.available is True
    assert result.ai_likelihood is not None
    assert result.ai_likelihood > 0.5  # low perplexity -> more model-like
    assert "perplexity" in result.extra


def test_transformers_too_short_is_unavailable(monkeypatch) -> None:
    det = TransformersDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)
    monkeypatch.setattr(det, "_token_log_probs", lambda text: [-1.0, -1.0])
    result = det.analyze("hi")
    assert result.available is False
    assert result.ai_likelihood is None


def test_transformers_scoring_failure_is_swallowed(monkeypatch) -> None:
    det = TransformersDetector()
    monkeypatch.setattr(det, "is_available", lambda: True)

    def boom(text):  # noqa: ARG001
        raise RuntimeError("model exploded")

    monkeypatch.setattr(det, "_token_log_probs", boom)
    result = det.analyze("x")
    assert result.available is False


def test_transformers_unavailable_without_deps(monkeypatch) -> None:
    det = TransformersDetector()
    monkeypatch.setattr(det, "is_available", lambda: False)
    result = det.analyze("x")
    assert result.available is False
    assert result.ai_likelihood is None


# ---------- registry / selection ------------------------------------------


def test_selection_defaults_to_unavailable() -> None:
    assert select_model_detector(None).is_available() is False
    assert select_model_detector("does-not-exist").is_available() is False


def test_env_selection(monkeypatch) -> None:
    monkeypatch.setenv("SLOP_MODEL_DETECTOR", "transformers")
    assert select_model_detector(None).name == "transformers"


# ---------- text-engine wiring (additive) ---------------------------------


def test_default_analyze_leaves_result_unchanged() -> None:
    text = "The firewall blocked 42 SSH attempts from 203.0.113.10 at 14:05 UTC today."
    baseline = SlopDetector().analyze(text)
    assert baseline.model_detection is None

    with_det = SlopDetector().analyze(text, model_detector=UnavailableModelDetector())
    assert with_det.score == baseline.score
    assert [s.name for s in with_det.signals] == [s.name for s in baseline.signals]
    assert with_det.model_detection is not None
    assert with_det.model_detection.available is False


class _FakeDetector:
    name = "fake"

    def is_available(self) -> bool:
        return True

    def analyze(self, text: str) -> ModelDetectorResult:  # noqa: ARG002
        return ModelDetectorResult(method="fake", available=True, ai_likelihood=0.83, detail="x")


def test_injected_detector_flows_through() -> None:
    result = SlopDetector().analyze("hello world", model_detector=_FakeDetector())
    assert result.model_detection.available is True
    assert result.model_detection.ai_likelihood == 0.83


class _BoomDetector:
    name = "boom"

    def is_available(self) -> bool:
        return True

    def analyze(self, text: str) -> ModelDetectorResult:  # noqa: ARG002
        raise RuntimeError("backend exploded")


def test_raising_detector_is_swallowed() -> None:
    result = SlopDetector().analyze("hello there friend", model_detector=_BoomDetector())
    assert result.model_detection is None  # engine survives
    assert result.score >= 0.0


# ---------- /analyze API wiring -------------------------------------------


def test_analyze_api_default_has_null_model_detection() -> None:
    from fastapi.testclient import TestClient

    from app.main import app

    response = TestClient(app).post("/api/v1/analyze", json={"text": "A short normal note."})
    assert response.status_code == 200
    assert response.json()["model_detection"] is None


def test_analyze_api_surfaces_available_detector(monkeypatch) -> None:
    from fastapi.testclient import TestClient

    from app.api import routes as routes_module
    from app.main import app

    monkeypatch.setattr(routes_module, "_model_detector", _FakeDetector())
    response = TestClient(app).post("/api/v1/analyze", json={"text": "Some passage to score."})
    assert response.status_code == 200
    body = response.json()["model_detection"]
    assert body is not None
    assert body["available"] is True
    assert body["ai_likelihood"] == 0.83
