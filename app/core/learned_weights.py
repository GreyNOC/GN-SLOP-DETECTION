"""Optional learned, glass-box scoring for the text rule engine.

The rule engine's per-signal weights (``0.18`` for vague language, ``0.22`` for
unsupported claims, ...) are hand-tuned. That is honest and transparent but not
*fitted* — there is no guarantee the relative weights are optimal for telling
machine text from human text. This module lets an operator replace them with
weights LEARNED from a labeled corpus, while keeping the model fully
explainable: it is a plain logistic regression whose coefficients are readable
numbers you can inspect, diff, and reason about. No black box.

Design, in keeping with the project philosophy:

  * **Default off.** With no ``SLOP_LEARNED_WEIGHTS`` env var (or no readable
    file) this module contributes nothing and the engine scores exactly as
    before. The bundled default stays hand-tuned.
  * **Honest about provenance.** A learned file fit on a tiny corpus WILL
    overfit; the learner (app/eval/learn_weights.py) records the training set
    size so a reviewer can weigh it. Treat learned weights as something you fit
    on *your* corpus, not a shipped default.
  * **Never breaks the engine.** A missing, malformed, or stale weights file
    loads as "off", never as an exception.

The score becomes ``sigmoid(bias + sum_signal coef[signal] * activation)``,
where ``activation`` is the same soft-saturated count the additive scorer uses,
so a learned model and the hand-tuned model consume identical features.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


class _HasNameCount(Protocol):
    name: str
    count: int


def scaled_activation(count: int) -> float:
    """Soft-saturated per-signal activation, shared by every scorer.

    One hit counts fully; each further hit adds half the previous one, capped at
    4x, so a single noisy detector cannot dominate. This is the exact transform
    the additive scorer and the dimension roll-up use, factored out here so the
    learned model is fit on, and scores from, the same feature definition.
    """
    if count <= 1:
        return 1.0
    return min(1.0 + 0.5 * (count - 1), 4.0)


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    ez = math.exp(z)
    return ez / (1.0 + ez)


@dataclass(frozen=True)
class LearnedWeights:
    """A fitted, readable per-signal weight set for composite scoring."""

    bias: float
    weights: dict[str, float]
    trained_on: int = 0  # corpus size the weights were fit on, for honesty
    source: str = ""

    def score(self, signals: list[_HasNameCount]) -> float:
        z = self.bias + sum(
            self.weights.get(signal.name, 0.0) * scaled_activation(signal.count)
            for signal in signals
        )
        return round(_sigmoid(z), 3)

    @classmethod
    def from_dict(cls, data: dict, source: str = "") -> LearnedWeights | None:
        try:
            bias = float(data["bias"])
            raw_weights = data["weights"]
            if not isinstance(raw_weights, dict):
                return None
            weights = {str(name): float(value) for name, value in raw_weights.items()}
        except (KeyError, TypeError, ValueError):
            return None
        # A degenerate model (no coefficients, or all-zero) ignores every signal
        # and emits the constant sigmoid(bias) for all inputs — it cannot honestly
        # claim "+learned". Reject it so the engine falls back to the hand-tuned
        # additive scorer instead of advertising a learned tag for a no-op model.
        if not weights or all(value == 0.0 for value in weights.values()):
            return None
        # Reject non-finite bias/weights from a corrupted file rather than letting
        # NaN/inf propagate into a meaningless score.
        if not math.isfinite(bias) or any(not math.isfinite(v) for v in weights.values()):
            return None
        trained_on = int(data.get("trained_on", 0) or 0)
        return cls(bias=bias, weights=weights, trained_on=trained_on, source=source)

    @classmethod
    def from_file(cls, path: str | Path) -> LearnedWeights | None:
        """Load weights from a JSON file. Returns None on any problem."""
        try:
            file_path = Path(path)
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        return cls.from_dict(data, source=str(path))

    @classmethod
    def from_env(cls) -> LearnedWeights | None:
        """Load from ``SLOP_LEARNED_WEIGHTS`` if set; otherwise None."""
        path = os.environ.get("SLOP_LEARNED_WEIGHTS", "").strip()
        if not path:
            return None
        return cls.from_file(path)
