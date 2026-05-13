# GN Slop Detection Architecture

## Goal

Provide a small, explainable service that helps GreyNOC analysts identify suspiciously vague, repetitive, unsupported, or low-value content before it enters reports, tickets, knowledge bases, or public-facing communications.

## Components

1. FastAPI app: receives analysis requests and returns structured scoring data.
2. Rule engine: calculates explainable signals and a normalized score.
3. CLI scanner: supports local file and directory scanning.
4. Tests and CI: protect the detector and API contracts.

## Detection philosophy

The app should not claim that text is AI-generated. It should identify review-worthy signals and provide evidence for why the score was assigned.

## Extension points

- Add a `ModelDetector` interface for local or hosted ML models.
- Store analysis events in Postgres or SQLite.
- Add analyst feedback to improve signal weighting.
- Integrate with GreyNOC ticket, SOC, or report pipelines.
