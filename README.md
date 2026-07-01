# GN Slop Detection

GN Slop Detection is a GreyNOC starter app for scoring text, tickets, reports, posts, or messages for low-quality "slop" indicators such as vague wording, repetitive phrasing, unsupported claims, keyword stuffing, and suspicious AI-generated patterns.

This repo is intentionally lightweight: it runs locally, exposes a FastAPI API, includes a CLI scanner, and ships with tests so it can be extended into a production GreyNOC service.

## Features

- FastAPI REST API for single, batch, and website URL analysis
- Rule-based scoring engine with explainable signals, dimension scores, and profile metrics
- Website fetching with readable text extraction and private-network blocking by default
- Square analyst dashboard for text and website review
- Electron desktop shell that launches the local analysis engine
- Working CLI for text, files, folders, and website URLs
- JSON output designed for SOC/analyst workflows
- Docker support
- Pytest test suite
- GitHub Actions CI
- Clean project layout for adding ML models later

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

- Dashboard: http://127.0.0.1:8000/
- API health: http://127.0.0.1:8000/health
- API docs: http://127.0.0.1:8000/docs

## Example API call

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"text":"This revolutionary solution leverages next-generation synergy to unlock unprecedented outcomes with no evidence provided."}'
```

Analyze a website:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze-url \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/article"}'
```

Website fetching accepts `http` and `https`, limits response size, extracts readable HTML/text, and blocks local, private, and reserved network addresses unless `ALLOW_PRIVATE_URLS=true` is set.

## CLI usage

Analyze inline text:

```bash
python -m app.cli text "This revolutionary solution is guaranteed." --pretty
```

Analyze one file:

```bash
python -m app.cli file examples/sample.txt --pretty
```

Analyze a folder:

```bash
python -m app.cli file ./docs --recursive
```

Analyze a website:

```bash
python -m app.cli url https://example.com --pretty
```

The legacy scanner still works:

```bash
python scripts/gn_slop_scan.py examples/sample.txt
```

After installing the package, the console script is available as:

```bash
gn-slop text "This article will explore a powerful next-generation solution."
```

### Portable CLI executable (Windows, no Python required)

Each Windows release ships a standalone `GreyNOC-Slop-Detection-CLI-<version>.exe`
on the [Releases page](https://github.com/GreyNOC/GN-SLOP-DETECTION/releases) — a
single, no-install executable that bundles the analysis engines. Download it and
run the same commands directly:

```text
GreyNOC-Slop-Detection-CLI-<version>.exe text "This guaranteed revolutionary solution" --pretty
GreyNOC-Slop-Detection-CLI-<version>.exe file report.txt
GreyNOC-Slop-Detection-CLI-<version>.exe url https://example.com
```

## Desktop app

Install Electron dependencies and start the desktop shell in development:

```bash
npm install
npm start
```

The Electron app starts a local FastAPI backend on an open loopback port, waits for `/health`, then loads the same analyst dashboard.

## Compile desktop builds

Run the compiler script for the OS you are building on:

```text
powershell -ExecutionPolicy Bypass -File scripts/compile-windows.ps1
scripts\compile-windows.bat
bash scripts/compile-mac.sh
bash scripts/compile-linux.sh
```

Each script installs Python build dependencies, creates a `gn-slop-backend` server executable and a standalone `gn-slop` CLI executable with PyInstaller, installs Electron dependencies, and writes packaged apps to `release/`. The Windows build produces a desktop installer, a portable desktop app, and a portable CLI executable.

## Score meaning

Scores range from `0.0` to `1.0`.

- `0.00 - 0.29`: low slop risk
- `0.30 - 0.59`: moderate slop risk
- `0.60 - 1.00`: high slop risk

The text and media engines use these bands. The code scanner uses a slightly
higher `high` cutoff of `0.65` (so its high band lines up with the "any critical
finding" floor); its `moderate` band still starts at `0.30`.

This app does not claim to prove whether content is AI-generated. It highlights quality and trust signals for human review.

Responses include a complete slop picture:

- `signals`: explainable findings with category, weight, count, and description
- `dimensions`: clarity, evidence, specificity, originality, manipulation, structure, and authenticity scores
- `profile`: sentence, specificity, evidence, repetition, link, number, and citation metrics

## Measuring and tuning detection quality

Detection quality is measurable, not vibes. The `app/eval` harness scores the
engine against a labeled JSONL corpus and reports the metrics the detection
literature uses — ROC-AUC, TPR at a fixed low false-positive rate, F1, and
calibration error. It is a pure-Python offline tool (no numpy/sklearn) and is
never invoked at request time.

```bash
# Score the rule engine against a corpus (defaults to the bundled seed set).
python -m app.eval report path/to/corpus.jsonl

# Fit Platt scaling so the score reads as a probability.
python -m app.eval calibrate path/to/corpus.jsonl

# Learn glass-box per-signal weights and save them.
python -m app.eval learn-weights path/to/corpus.jsonl -o weights.json
export SLOP_LEARNED_WEIGHTS=weights.json   # opt-in; default stays hand-tuned
```

Corpus format is one JSON object per line:

```json
{"text": "...", "label": "human"|"ai", "domain": "essay", "model": "gpt-4o"}
```

The bundled `app/eval/data/seed_corpus.jsonl` is a smoke-test set, **not** a
benchmark — replace it with real human/AI samples (its README explains how).

### Stronger AI-likelihood backends (optional)

The pluggable `ModelDetector` adds a model-based second opinion behind the
`[modeldetector]` extra (`pip install '.[modeldetector]'`):

- `SLOP_MODEL_DETECTOR=binoculars` — **Binoculars** cross-perplexity (Hans et
  al. 2024), the current best zero-shot method.
- `SLOP_MODEL_DETECTOR=transformers` — single-model perplexity baseline.

Both import torch/transformers lazily; the default install carries no extra
dependency, and the estimate is surfaced as explainable metadata, never folded
into the rule-based score.

### Evasion resistance

The text engine detects and normalizes character-level evasion (zero-width
characters, Cyrillic/Greek homoglyphs, bidi controls). Obfuscated text is both
flagged (`evasion_obfuscation` signal) and de-obfuscated before matching, so
hiding a flagged word behind lookalike characters no longer defeats detection.

## Post-quantum (PQ) readiness scanning

The code scanner includes a `pqc` rule pack that builds a crypto inventory for
the post-quantum transition: quantum-vulnerable primitives (RSA, ECDH/DH key
exchange, ECDSA/EdDSA/DSA signatures, pinned JWT algorithms), TLS/SSH configs
that pin classical-only groups (opting out of the hybrid key exchange modern
stacks negotiate by default), asymmetric keys ≤ 1024 bits, AES-128/192
selection, and — as positive signals — PQC adoption (ML-KEM, ML-DSA, SLH-DSA,
liboqs) plus parameter sets below NIST security category 3.

Severity is calibrated to migration urgency: key establishment scores
`medium` because recorded traffic is harvest-now-decrypt-later exposed, while
signatures score `low` (no retroactive break). Hybrid-aware configs (e.g.
`X25519MLKEM768`, `sntrup761x25519` — including multi-line group lists) are
not flagged. PQ inventory findings are dampened in the composite risk score:
a codebase full of today-standard RSA/ECDH stays in the low band, while
genuinely weak crypto (keys ≤ 1024 bits) counts at full weight.

Every scan response includes a `pq_readiness` roll-up:

```json
{
  "status": "quantum_vulnerable | migration_in_progress | pq_ready | symmetric_margin_only | no_crypto_detected",
  "hndl_exposure": 4,
  "classical_findings": 6,
  "pqc_findings": 0,
  "families": {"rsa": 2, "key_exchange_config": 1, "signature": 2},
  "recommendation": "..."
}
```

The CLI prints a one-line summary (`PQ readiness: quantum_vulnerable ...`)
and the findings flow into SARIF exports like every other rule pack.

## Project layout

```text
app/
  api/            API routes
  core/           detection engines, adversarial normalization, settings
  eval/           offline evaluation harness, calibration, weight learning
  models/         request/response schemas
electron/         Electron desktop app shell
scripts/          CLI utilities
tests/            unit/API tests
docs/             implementation notes
```

## Development

```bash
pip install -r requirements-dev.txt
pytest
ruff check .
npm start
```

## Docker

```bash
docker build -t gn-slop-detection .
docker run -p 8000:8000 gn-slop-detection
```

## Roadmap

- Assemble a real labeled evaluation corpus (real model outputs + non-native
  English human writing) to replace the seed set and calibrate thresholds
- Add authenticated analyst dashboard
- Add source reputation lookups
- Add SIEM/SOAR integrations
- Add evidence export for case notes

Done: pluggable ML detector interface (perplexity + Binoculars), evaluation
harness with calibration and learned weights, adversarial-evasion resistance,
post-quantum readiness scanning (`pqc` rule pack + `pq_readiness` roll-up).
