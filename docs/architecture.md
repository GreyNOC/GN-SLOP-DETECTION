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
- **Optional local backend.** `TransformersDetector` computes a genuine
  mean-token perplexity under a local causal LM and maps it to a likelihood
  (an explicit, uncalibrated heuristic; the raw perplexity is always
  surfaced). It is opt-in behind the `[modeldetector]` pip extra
  (`pip install '.[modeldetector]'`) and the `SLOP_MODEL_DETECTOR=transformers`
  env var; torch/transformers are imported lazily, so the default install
  carries no extra dependency.
- **No hosted backend.** Anthropic exposes no token logprobs, and current
  OpenAI chat models no longer return prompt-token logprobs via `echo`, so a
  hosted log-likelihood backend is intentionally not shipped.
- The estimate is surfaced as explainable metadata only — it is **not**
  folded into the rule-based composite score.

## Extension points

- Add hosted log-likelihood backends to `ModelDetector` if a provider
  exposes prompt-token logprobs.
- Add source reputation lookups for fetched domains.
- Store analysis events in Postgres or SQLite.
- Add analyst feedback to improve signal weighting.
- Add signed desktop release publishing for Windows, macOS, and Linux.
- Integrate with GreyNOC ticket, SOC, or report pipelines.
