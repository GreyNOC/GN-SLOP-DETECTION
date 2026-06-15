"""Pluggable model-based AI-likelihood detector — the ``ModelDetector``
extension point named in ``docs/architecture.md``.

The rule engine in ``detector.py`` scores *style* (vagueness, repetition,
rhetorical tics). A genuinely model-based detector scores *predictability*:
how well a language model anticipates the text, which is the signal behind
DetectGPT / Fast-DetectGPT / Binoculars. That requires a model's token
probabilities — something the rule engine cannot compute.

HONESTY CONTRACT (the central design decision):
  * The DEFAULT is ``UnavailableModelDetector`` — it presents the full
    interface but emits NO number. A zero-dependency statistical proxy
    (zlib compression ratio, bundled unigram self-information) was
    considered and rejected: it would either re-measure the repetition the
    rule engine already captures (``_repetition_density`` / ``_mattr`` /
    ``_ngram_repetition``) or be a noisy, domain-mismatched stand-in for
    perplexity. Calling either an "AI-likelihood model score" would be
    dishonest, so the default stays explicitly unavailable.
  * A real backend (``TransformersDetector``) is provided but OPT-IN behind
    the ``[modeldetector]`` pip extra and the ``SLOP_MODEL_DETECTOR`` env
    var. torch/transformers are imported lazily, so importing this module
    has zero extra dependencies.
  * Anthropic exposes no token logprobs and current OpenAI chat models no
    longer return prompt-token logprobs via ``echo``, so a hosted
    log-likelihood backend is not shipped (it would imply a capability that
    does not exist).

The detector result is surfaced as explainable metadata only — it is
deliberately NOT folded into the rule-based composite score, which stays
fully explainable.
"""

from __future__ import annotations

import math
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from statistics import mean
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ModelDetectorResult:
    """Outcome of a model-based AI-likelihood estimate.

    ``ai_likelihood`` is ``None`` whenever the detector cannot produce a
    meaningful, model-derived number. ``available`` is the single source of
    truth for "did this produce a real estimate"; ``detail`` always explains
    why. The invariant (available ⇔ a number) is enforced so no detector can
    quietly fabricate a score.
    """

    method: str  # e.g. 'unavailable', 'perplexity', 'fast-detectgpt'
    available: bool
    ai_likelihood: float | None = None  # 0..1 (1 = more model-like); None when unavailable
    detail: str = ""
    extra: dict = field(default_factory=dict)  # backend diagnostics (e.g. raw perplexity)

    def __post_init__(self) -> None:
        if self.ai_likelihood is not None:
            object.__setattr__(self, "ai_likelihood", max(0.0, min(1.0, float(self.ai_likelihood))))
        if self.available and self.ai_likelihood is None:
            raise ValueError("an available detector must supply ai_likelihood")
        if not self.available and self.ai_likelihood is not None:
            raise ValueError("an unavailable detector must not supply ai_likelihood")


@runtime_checkable
class ModelDetector(Protocol):
    """A pluggable model-based detector.

    Implementations must never raise to the caller for expected failure
    modes (missing deps, network, bad key, too-short input) — they return an
    unavailable ``ModelDetectorResult`` instead.
    """

    name: str

    def analyze(self, text: str) -> ModelDetectorResult: ...

    def is_available(self) -> bool: ...


class UnavailableModelDetector:
    """Default detector: an honest "not configured". Emits no score."""

    name = "unavailable"

    def is_available(self) -> bool:
        return False

    def analyze(self, text: str) -> ModelDetectorResult:  # noqa: ARG002
        return ModelDetectorResult(
            method="unavailable",
            available=False,
            ai_likelihood=None,
            detail=(
                "No model backend configured. Install the optional extra "
                "(pip install '.[modeldetector]') and set SLOP_MODEL_DETECTOR="
                "transformers for a local perplexity score. The rule engine "
                "continues to provide explainable signals on its own."
            ),
        )


# --- perplexity -> likelihood math (pure, unit-tested without torch) -------

# Heuristic mapping constants. These are NOT calibrated against a labelled
# human-vs-AI corpus — the raw perplexity is always surfaced in ``extra`` so
# an analyst can judge for themselves. Lower perplexity (the model found the
# text predictable) maps to higher AI-likelihood. The midpoint is the
# perplexity at which likelihood crosses 0.5; steepness controls the slope.
_PPL_MIDPOINT: float = 60.0
_PPL_STEEPNESS: float = 20.0
_MIN_SCORED_TOKENS: int = 20


def _mean_token_log_prob(token_log_probs: list[float]) -> float:
    return mean(token_log_probs)


def _perplexity_from_mean_logprob(mean_logprob: float) -> float:
    return math.exp(-mean_logprob)


def _perplexity_to_likelihood(
    perplexity: float,
    midpoint: float = _PPL_MIDPOINT,
    steepness: float = _PPL_STEEPNESS,
) -> float:
    """Monotonic decreasing map perplexity -> [0,1]. 0.5 at the midpoint."""
    # likelihood = sigmoid((midpoint - perplexity) / steepness)
    z = (perplexity - midpoint) / max(steepness, 1e-6)
    # Guard against overflow in exp for extreme perplexities.
    if z > 60:
        return 0.0
    if z < -60:
        return 1.0
    return 1.0 / (1.0 + math.exp(z))


class TransformersDetector:
    """Local HuggingFace perplexity detector (opt-in, ``[modeldetector]`` extra).

    Computes a genuine model-derived signal — the mean token log-likelihood
    of the text under a causal LM, mapped to an AI-likelihood — which the
    rule engine cannot produce. torch/transformers are imported lazily, so
    this class is importable with zero extra dependencies; ``is_available``
    probes for them. The likelihood mapping is an explicit heuristic (see the
    constants above) and the raw perplexity is always returned in ``extra``.
    """

    name = "transformers"
    method = "perplexity"

    def __init__(self, model_id: str | None = None) -> None:
        self._model_id = model_id or os.environ.get("SLOP_MODEL_DETECTOR_MODEL", "distilgpt2")
        self._loaded: tuple | None = None  # (tokenizer, model), lazily built

    def is_available(self) -> bool:
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except Exception:
            return False
        return True

    def analyze(self, text: str) -> ModelDetectorResult:
        if not self.is_available():
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail="transformers/torch not installed (pip install '.[modeldetector]').",
            )
        try:
            log_probs = self._token_log_probs(text)
        except Exception as exc:  # download/OOM/runtime failure — never crash the engine
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail=f"model scoring failed: {type(exc).__name__}",
            )
        if len(log_probs) < _MIN_SCORED_TOKENS:
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail=f"text too short to score ({len(log_probs)} tokens; need {_MIN_SCORED_TOKENS}).",
            )
        perplexity = _perplexity_from_mean_logprob(_mean_token_log_prob(log_probs))
        likelihood = _perplexity_to_likelihood(perplexity)
        return ModelDetectorResult(
            method=self.method,
            available=True,
            ai_likelihood=likelihood,
            detail=(
                f"Mean-token perplexity under {self._model_id} = {perplexity:.1f}. "
                "Likelihood mapping is an uncalibrated heuristic; the raw "
                "perplexity is the load-bearing number."
            ),
            extra={"perplexity": round(perplexity, 3), "model": self._model_id},
        )

    def _token_log_probs(self, text: str) -> list[float]:
        """Per-token log p(token | preceding tokens) under the causal LM.

        Lazily loads the model on first use. Isolated from the scoring math
        above so the calibration is unit-testable without torch installed.
        """
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if self._loaded is None:
            # SLOP_MODEL_DETECTOR_MODEL is an operator-trust boundary: it
            # triggers a network download of the named repo. trust_remote_code
            # stays False so a repo's custom modeling code is never executed.
            tokenizer = AutoTokenizer.from_pretrained(self._model_id, trust_remote_code=False)
            model = AutoModelForCausalLM.from_pretrained(self._model_id, trust_remote_code=False)
            model.eval()
            self._loaded = (tokenizer, model)
        tokenizer, model = self._loaded

        encoded = tokenizer(text, return_tensors="pt", truncation=True, max_length=1024)
        input_ids = encoded["input_ids"]
        if input_ids.shape[1] < 2:
            return []
        with torch.no_grad():
            logits = model(**encoded).logits
        # Shift: token t is predicted from positions < t.
        shift_logits = logits[:, :-1, :]
        shift_labels = input_ids[:, 1:]
        log_probs = torch.log_softmax(shift_logits, dim=-1)
        token_lp = log_probs.gather(2, shift_labels.unsqueeze(-1)).squeeze(-1)
        return token_lp[0].tolist()


# --- registry + selection --------------------------------------------------

_REGISTRY: dict[str, Callable[[], ModelDetector]] = {}


def register(name: str, factory: Callable[[], ModelDetector]) -> None:
    _REGISTRY[name] = factory


def available_detectors() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def get_model_detector(name: str) -> ModelDetector:
    factory = _REGISTRY.get(name)
    if factory is None:
        return UnavailableModelDetector()
    return factory()


def select_default_from_env() -> ModelDetector:
    name = os.environ.get("SLOP_MODEL_DETECTOR", "").strip()
    if name:
        return get_model_detector(name)
    return UnavailableModelDetector()


def select_model_detector(name: str | None) -> ModelDetector:
    """Resolve a detector by explicit name, else the env default, else the
    honest unavailable detector. Never raises."""
    if name:
        return get_model_detector(name)
    return select_default_from_env()


register("unavailable", UnavailableModelDetector)
# The transformers backend self-registers; its deps are probed lazily in
# is_available(), so registering the factory pulls in nothing heavy.
register("transformers", TransformersDetector)
