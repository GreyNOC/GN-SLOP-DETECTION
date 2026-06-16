"""Tests for learned, glass-box signal weights.

Covers the loader contract (never raises, default-off), the scoring math, the
learner, and the end-to-end learn -> load -> score path. The invariant that
matters most: with nothing configured, the engine is byte-identical to before.
"""

from __future__ import annotations

import json
from pathlib import Path

from app.core.detector import SlopDetector
from app.core.learned_weights import LearnedWeights, scaled_activation
from app.eval.corpus import load_corpus
from app.eval.learn_weights import extract_features, learn_signal_weights, write_weights_file

_SEED = Path(__file__).resolve().parents[1] / "app" / "eval" / "data" / "seed_corpus.jsonl"


class _Sig:
    def __init__(self, name: str, count: int) -> None:
        self.name = name
        self.count = count


# --- activation + scoring math ---------------------------------------------


def test_scaled_activation_matches_formula() -> None:
    assert scaled_activation(0) == 1.0
    assert scaled_activation(1) == 1.0
    assert scaled_activation(3) == 2.0
    assert scaled_activation(100) == 4.0  # capped


def test_learned_score_is_sigmoid_of_linear_combo() -> None:
    weights = LearnedWeights(bias=0.0, weights={"vague_language": 2.0})
    # One vague hit -> activation 1.0 -> sigmoid(2.0) ~= 0.881.
    score = weights.score([_Sig("vague_language", 1)])
    assert abs(score - 0.881) < 0.01
    # Unknown signal contributes nothing.
    assert weights.score([_Sig("unknown", 5)]) == 0.5


# --- loader contract (never raises) ----------------------------------------


def test_from_dict_valid() -> None:
    lw = LearnedWeights.from_dict({"bias": -1.0, "weights": {"a": 0.5}, "trained_on": 10})
    assert lw is not None and lw.bias == -1.0 and lw.weights["a"] == 0.5 and lw.trained_on == 10


def test_from_dict_rejects_malformed() -> None:
    assert LearnedWeights.from_dict({"bias": "x", "weights": {}}) is None
    assert LearnedWeights.from_dict({"weights": {"a": 1.0}}) is None  # no bias
    assert LearnedWeights.from_dict({"bias": 0.0, "weights": [1, 2]}) is None  # weights not a dict


def test_from_file_missing_returns_none(tmp_path: Path) -> None:
    assert LearnedWeights.from_file(tmp_path / "nope.json") is None


def test_from_file_malformed_returns_none(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    assert LearnedWeights.from_file(bad) is None


def test_from_env_unset_is_none(monkeypatch) -> None:
    monkeypatch.delenv("SLOP_LEARNED_WEIGHTS", raising=False)
    assert LearnedWeights.from_env() is None


# --- detector integration (default off) ------------------------------------


def test_detector_default_is_unchanged(monkeypatch) -> None:
    monkeypatch.delenv("SLOP_LEARNED_WEIGHTS", raising=False)
    detector = SlopDetector()
    assert detector._learned is None
    result = detector.analyze("A perfectly ordinary sentence with nothing special in it.")
    assert result.profile.algorithm == "rule-picture-v5"


def test_detector_uses_learned_weights_when_supplied() -> None:
    learned = LearnedWeights(bias=-3.0, weights={"vague_language": 5.0}, trained_on=1)
    detector = SlopDetector(learned_weights=learned)
    sloppy = (
        "This revolutionary, seamless, world-class, innovative, transformative "
        "solution is truly groundbreaking and holistic and scalable."
    )
    result = detector.analyze(sloppy)
    assert result.profile.algorithm == "rule-picture-v5+learned"
    assert 0.0 <= result.score <= 1.0


# --- learner ---------------------------------------------------------------


def test_extract_features_shapes_align() -> None:
    examples, _ = load_corpus(_SEED)
    rows, labels, names = extract_features(examples)
    assert len(rows) == len(labels) == len(examples)
    assert names == sorted(names)
    assert all(len(row) == len(names) for row in rows)


def test_learn_signal_weights_produces_readable_coefficients() -> None:
    examples, _ = load_corpus(_SEED)
    result = learn_signal_weights(examples, l2=2.0)
    assert result.trained_on == len(examples)
    assert result.weights  # non-empty
    # On the (easy) seed corpus the fit should separate the classes well.
    assert result.train_auc is not None and result.train_auc > 0.9


def test_end_to_end_learn_load_score(tmp_path: Path) -> None:
    examples, _ = load_corpus(_SEED)
    result = learn_signal_weights(examples)
    weights_path = tmp_path / "w.json"
    write_weights_file(result, weights_path)

    # The file matches the loader's expected shape.
    loaded = LearnedWeights.from_file(weights_path)
    assert loaded is not None and loaded.trained_on == len(examples)

    detector = SlopDetector(learned_weights=loaded)
    sloppy = next(e for e in examples if e.label == 1)
    human = next(e for e in examples if e.label == 0)
    assert detector.analyze(sloppy.text).score > detector.analyze(human.text).score


def test_weights_file_roundtrips_json(tmp_path: Path) -> None:
    examples, _ = load_corpus(_SEED)
    result = learn_signal_weights(examples)
    path = tmp_path / "w.json"
    write_weights_file(result, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert "bias" in data and "weights" in data and data["trained_on"] == len(examples)
