# GN Slop Detection Architecture

## Goal

Provide a small, explainable service that helps GreyNOC analysts identify suspiciously vague, repetitive, unsupported, or low-value content before it enters reports, tickets, knowledge bases, or public-facing communications.

## Components

1. FastAPI app: receives text or website analysis requests and returns structured scoring data.
2. Website ingest: fetches public HTTP(S) pages, limits response size, extracts readable text, and blocks private-network targets by default.
3. Rule engine: calculates explainable signals, dimension scores, profile metrics, and a normalized score.
4. Static dashboard: provides a square analyst console for text, URL, signal, dimension, and source review.
5. CLI scanner: supports local file and directory scanning.
6. Tests and CI: protect the detector and API contracts.

## Detection philosophy

The app should not claim that text is AI-generated. It should identify review-worthy signals and provide evidence for why the score was assigned.

The current algorithm builds a complete slop picture from:

- Signal categories: clarity, evidence, specificity, originality, manipulation, structure, and authenticity.
- Profile metrics: sentence count, average sentence length, specificity density, evidence density, repetition density, links, numeric details, and citations.
- Dimension scores: normalized review scores that help analysts see which part of the content needs attention.

## Extension points

- Add a `ModelDetector` interface for local or hosted ML models.
- Add source reputation lookups for fetched domains.
- Store analysis events in Postgres or SQLite.
- Add analyst feedback to improve signal weighting.
- Integrate with GreyNOC ticket, SOC, or report pipelines.
