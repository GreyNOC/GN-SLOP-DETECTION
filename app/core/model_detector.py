"""Pluggable model-based AI-likelihood detector — the ``ModelDetector``
extension point named in ``docs/architecture.md``.

The rule engine in ``detector.py`` scores *style* (vagueness, repetition,
rhetorical tics). A genuinely model-based detector scores *predictability*:
how well a language model anticipates the text, which is the signal behind
DetectGPT / Fast-DetectGPT / Binoculars. That requires a model's token
probabilities — something the rule engine cannot compute.

Two optional local backends are provided, weakest to strongest:
  * ``TransformersDetector`` — single-model mean-token perplexity. The simplest
    predictability signal; easy to fool and poorly calibrated on its own.
  * ``BinocularsDetector`` — the ratio of an observer model's perplexity to the
    cross-perplexity between two related models (Hans et al. 2024). This is the
    current best zero-shot method: it cancels the prompt/topic component that
    contaminates raw perplexity and needs no per-model threshold tuning.

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


# --- Binoculars score -> likelihood math (pure, unit-tested without torch) --
#
# Binoculars (Hans et al., 2024, "Spotting LLMs with Binoculars") is the
# current best ZERO-SHOT machine-text detector: no training, no per-model
# threshold tuning, and ~90%+ TPR at very low FPR in the paper. The insight is
# that single-model perplexity conflates two things — how surprising the text
# is, and how surprising *any* prompt would make it. Dividing an observer
# model's perplexity by the CROSS-perplexity between two closely related models
# cancels the prompt/topic component, leaving a much cleaner machine-vs-human
# signal:
#
#     B = CE_observer(text) / XCE(observer, performer)
#
# where CE_observer is the observer's mean negative log-likelihood on the
# actual tokens, and XCE is the mean cross-entropy H(p_observer, p_performer)
# over the *full* predicted distributions at each position. A LOW B means the
# text is much more predictable than two models disagree about — the hallmark
# of machine generation. The ratio is unit-invariant (nats vs bits cancel).
#
# Like the perplexity map above, the score->likelihood constants here are an
# explicit, UNCALIBRATED heuristic for the default small-model pair; the raw B
# is always surfaced in ``extra`` and is the load-bearing number. Calibrate
# against a labelled corpus (app/eval) for a real operating point. The default
# midpoint sits near the paper's accuracy threshold; steepness is intentionally
# shallow so a borderline B does not masquerade as a confident verdict.
_BINO_MIDPOINT: float = 0.9
_BINO_STEEPNESS: float = 0.04


def _binoculars_score(observer_cross_entropy: float, cross_perplexity: float) -> float:
    """B = observer cross-entropy / cross-perplexity. Lower == more machine-like.

    Both inputs are mean per-token cross-entropies in the same units (nats).
    Guards a zero/negative denominator (degenerate identical-distribution case)
    by returning a large score, i.e. "looks human", which is the safe default.
    """
    if cross_perplexity <= 1e-9:
        return float("inf")
    return observer_cross_entropy / cross_perplexity


def _binoculars_to_likelihood(
    score: float,
    midpoint: float = _BINO_MIDPOINT,
    steepness: float = _BINO_STEEPNESS,
) -> float:
    """Monotonic DECREASING map Binoculars score -> [0,1]. 0.5 at the midpoint."""
    # likelihood = sigmoid((midpoint - score) / steepness); lower B -> higher.
    z = (score - midpoint) / max(steepness, 1e-6)
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


class BinocularsDetector:
    """Zero-shot Binoculars detector (opt-in, ``[modeldetector]`` extra).

    Loads TWO causal LMs that share a tokenizer — an *observer* and a
    *performer* — and computes the Binoculars score ``B = CE_observer / XCE``
    (see the pure math above). This is a genuinely stronger signal than the
    single-model perplexity of ``TransformersDetector``: it is the current SOTA
    zero-shot method and needs no per-model threshold tuning.

    Defaults are the lightweight GPT-2 family pair (``gpt2`` + ``distilgpt2``),
    which share the GPT-2 BPE tokenizer so the two models score identical token
    ids. They demonstrate the method on a small download; the paper's headline
    numbers come from a larger same-family base/instruct pair (e.g. Falcon-7B /
    Falcon-7B-instruct), configurable via env. The default likelihood mapping
    is uncalibrated for this pair — calibrate with app/eval and the raw B is
    always in ``extra``.

    torch/transformers are imported lazily; importing this module pulls in
    nothing heavy. Like every detector here, it never raises to the caller for
    expected failures — it returns an unavailable result instead.
    """

    name = "binoculars"
    method = "binoculars"

    def __init__(self, observer_id: str | None = None, performer_id: str | None = None) -> None:
        self._observer_id = observer_id or os.environ.get("SLOP_BINOCULARS_OBSERVER", "gpt2")
        self._performer_id = performer_id or os.environ.get("SLOP_BINOCULARS_PERFORMER", "distilgpt2")
        self._loaded: tuple | None = None  # (tokenizer, observer, performer)

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
            observer_ce, cross_ppl, n_tokens = self._cross_entropies(text)
        except _TokenizerMismatch as exc:
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail=str(exc),
            )
        except Exception as exc:  # download/OOM/runtime — never crash the engine
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail=f"binoculars scoring failed: {type(exc).__name__}",
            )
        if n_tokens < _MIN_SCORED_TOKENS:
            return ModelDetectorResult(
                method=self.method,
                available=False,
                detail=f"text too short to score ({n_tokens} tokens; need {_MIN_SCORED_TOKENS}).",
            )
        score = _binoculars_score(observer_ce, cross_ppl)
        likelihood = _binoculars_to_likelihood(score)
        return ModelDetectorResult(
            method=self.method,
            available=True,
            ai_likelihood=likelihood,
            detail=(
                f"Binoculars score B={score:.4f} "
                f"({self._observer_id} vs {self._performer_id}); lower is more "
                "machine-like. Likelihood mapping is an uncalibrated heuristic "
                "for this model pair; B is the load-bearing number."
            ),
            extra={
                "binoculars_score": round(score, 5),
                "observer_cross_entropy": round(observer_ce, 5),
                "cross_perplexity": round(cross_ppl, 5),
                "observer": self._observer_id,
                "performer": self._performer_id,
                "n_tokens": n_tokens,
            },
        )

    def _cross_entropies(self, text: str) -> tuple[float, float, int]:
        """Return (observer CE on actual tokens, mean cross-entropy, n_tokens).

        Both means are in nats. The performer is fed the SAME token ids as the
        observer, so the pair must share a tokenizer; a vocab-size mismatch is
        detected and surfaced rather than silently producing garbage.
        """
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer

        if self._loaded is None:
            tokenizer = AutoTokenizer.from_pretrained(self._observer_id, trust_remote_code=False)
            observer = AutoModelForCausalLM.from_pretrained(self._observer_id, trust_remote_code=False)
            performer = AutoModelForCausalLM.from_pretrained(self._performer_id, trust_remote_code=False)
            observer.eval()
            performer.eval()
            self._loaded = (tokenizer, observer, performer)
        tokenizer, observer, performer = self._loaded

        encoded = tokenizer(text, return_tensors="pt", truncation=True, max_length=1024)
        input_ids = encoded["input_ids"]
        if input_ids.shape[1] < 2:
            return 0.0, 1.0, 0
        with torch.no_grad():
            logits_obs = observer(**encoded).logits
            logits_perf = performer(**encoded).logits
        if logits_obs.shape[-1] != logits_perf.shape[-1]:
            raise _TokenizerMismatch(
                f"observer ({self._observer_id}) and performer ({self._performer_id}) "
                "have different vocab sizes; Binoculars needs a shared tokenizer "
                "(e.g. gpt2 + distilgpt2, or a base/instruct pair from one family)."
            )
        # Shift so position t predicts token t+1.
        shift_obs = logits_obs[:, :-1, :]
        shift_perf = logits_perf[:, :-1, :]
        labels = input_ids[:, 1:]
        logp_obs = torch.log_softmax(shift_obs, dim=-1)
        logp_perf = torch.log_softmax(shift_perf, dim=-1)
        p_obs = logp_obs.exp()
        # Observer cross-entropy on the ACTUAL next tokens (its perplexity term).
        observer_ce = -logp_obs.gather(2, labels.unsqueeze(-1)).squeeze(-1).mean().item()
        # Cross-perplexity: mean over positions of H(p_obs, p_perf) across the
        # FULL vocab distribution, not just the realized token.
        cross_ppl = -(p_obs * logp_perf).sum(dim=-1).mean().item()
        n_tokens = int(labels.shape[1])
        return observer_ce, cross_ppl, n_tokens


class _TokenizerMismatch(RuntimeError):
    """Raised when the observer/performer pair do not share a tokenizer."""


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
# The local backends self-register; their deps are probed lazily in
# is_available(), so registering the factories pulls in nothing heavy.
# `transformers` = single-model perplexity (DetectGPT family, weaker baseline).
# `binoculars`   = two-model cross-perplexity (Hans et al. 2024, SOTA zero-shot).
register("transformers", TransformersDetector)
register("binoculars", BinocularsDetector)
