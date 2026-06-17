# GN Slop Detection Architecture

## Goal

Provide a small, explainable service that helps GreyNOC analysts identify suspiciously vague, repetitive, unsupported, or low-value content before it enters reports, tickets, knowledge bases, or public-facing communications.

## Components

1. FastAPI app: receives text or website analysis requests and returns structured scoring data.
2. Website ingest: fetches public HTTP(S) pages, limits response size, extracts readable text, and blocks private-network targets by default.
3. Rule engine: calculates explainable signals, dimension scores, profile metrics, and a normalized score.
4. Static dashboard: provides a square analyst console for text, URL, signal, dimension, and source review.
5. Electron shell: starts the local backend on a loopback port and loads the dashboard as a desktop app.
6. CLI: supports inline text, files, directories, and website URLs with the same engine as the API.
7. Tests and CI: protect the detector, CLI, and API contracts.

## Detection philosophy

The app should not claim that text is AI-generated. It should identify review-worthy signals and provide evidence for why the score was assigned.

The current algorithm builds a complete slop picture from:

- Signal categories: clarity, evidence, specificity, originality, manipulation, structure, and authenticity.
- Profile metrics: sentence count, average sentence length, specificity density, evidence density, repetition density, links, numeric details, and citations.
- Dimension scores: normalized review scores that help analysts see which part of the content needs attention.

## Model-based detection (ModelDetector)

The rule engine scores *style*. A model-based detector scores
*predictability* — how well a language model anticipates the text, the
signal behind DetectGPT / Fast-DetectGPT / Binoculars. The pluggable
`ModelDetector` interface lives in `app/core/model_detector.py`:

- **Default is honest.** `UnavailableModelDetector` ships as the default and
  emits **no** number. A zero-dependency statistical proxy was rejected
  because it would either re-measure repetition the rule engine already
  captures or be a noisy stand-in for perplexity — calling that an
  "AI-likelihood score" would be dishonest.
- **Optional local backends (weakest to strongest).**
  - `TransformersDetector` (`SLOP_MODEL_DETECTOR=transformers`) — single-model
    mean-token perplexity under a local causal LM. The simplest predictability
    signal; surfaces the raw perplexity, maps it to a likelihood via an
    explicit, uncalibrated heuristic.
  - `BinocularsDetector` (`SLOP_MODEL_DETECTOR=binoculars`) — the current best
    **zero-shot** method (Hans et al. 2024). It loads two same-tokenizer LMs (an
    observer and a performer) and scores `B = CE_observer / cross-perplexity`,
    which cancels the prompt/topic component that contaminates raw perplexity.
    Defaults to the lightweight `gpt2` + `distilgpt2` pair (shared GPT-2
    tokenizer); a larger same-family base/instruct pair (e.g. Falcon-7B /
    Falcon-7B-instruct) via `SLOP_BINOCULARS_OBSERVER` / `_PERFORMER` reaches the
    paper's numbers. Raw `B` is always surfaced; the likelihood mapping is an
    uncalibrated heuristic for the default pair — calibrate it with `app/eval`.
  - Both are opt-in behind the `[modeldetector]` pip extra
    (`pip install '.[modeldetector]'`); torch/transformers are imported lazily,
    so the default install carries no extra dependency.
- **No hosted backend.** Anthropic exposes no token logprobs, and current
  OpenAI chat models no longer return prompt-token logprobs via `echo`, so a
  hosted log-likelihood backend is intentionally not shipped.
- The estimate is surfaced as explainable metadata only — it is **not**
  folded into the rule-based composite score.

## Evaluation harness (app/eval)

Detection thresholds and signal weights were historically hand-tuned. The
`app/eval` package makes them **measurable** — it is pure-Python (no numpy /
sklearn), an offline analyst/CI tool, never invoked at request time:

- `corpus.py` loads a labeled JSONL corpus (`text` + `human`/`ai` label, with
  optional `domain` / `model` for slicing).
- `metrics.py` computes ROC-AUC, **TPR at fixed FPR** (1% / 5% / 10% — the
  number that matters for a review tool, since false positives on human writing
  are the cardinal error), precision/recall/F1, and calibration error
  (ECE/Brier), all by hand so the numbers are auditable.
- `runner.py` scores a corpus with any engine via adapters (the rule engine, a
  `ModelDetector`); `calibrate.py` fits Platt scaling and can recover the exact
  `(_PPL_MIDPOINT, _PPL_STEEPNESS)` for the perplexity map.
- A small **seed corpus** ships under `app/eval/data/` purely as a smoke test —
  it is NOT a benchmark (see its README). Run: `python -m app.eval report` /
  `calibrate` / `learn-weights`.

## Adversarial robustness (app/core/adversarial.py)

Character-level evasion (zero-width splices, Cyrillic/Greek homoglyphs, bidi
controls, exotic whitespace) defeats an exact-match lexicon while looking
unchanged to a reader. The module both **detects** the obfuscation (surfaced as
an `evasion_obfuscation` signal — mixed-script words and bidi controls are
near-zero-false-positive tells) and **defeats** it: the engine de-obfuscates
before matching, so the underlying slop signals still fire. NFKC does not fold
cross-script homoglyphs, so this is additive to the existing normalization.

## Learned glass-box weights (app/core/learned_weights.py)

The hand-tuned per-signal weights can be replaced by weights **learned** from a
labeled corpus while staying fully explainable — a plain logistic regression
whose coefficients are readable numbers. `python -m app.eval learn-weights`
fits them; pointing `SLOP_LEARNED_WEIGHTS` at the output JSON swaps the
composite's combination rule to the fitted logistic. Default (nothing
configured) is byte-identical to the hand-tuned engine. A fit on a small corpus
overfits, so the bundled default stays hand-tuned and the output records its
training-set size.

## Extension points

- Add hosted log-likelihood backends to `ModelDetector` if a provider
  exposes prompt-token logprobs.
- Add source reputation lookups for fetched domains.
- Store analysis events in Postgres or SQLite.
- Add analyst feedback to improve signal weighting.
- Add signed desktop release publishing for Windows, macOS, and Linux.
- Integrate with GreyNOC ticket, SOC, or report pipelines.
