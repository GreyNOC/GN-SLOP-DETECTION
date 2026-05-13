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

Each script installs Python build dependencies, creates a `gn-slop-backend` executable with PyInstaller, installs Electron dependencies, and writes packaged apps to `release/`.

## Score meaning

Scores range from `0.0` to `1.0`.

- `0.00 - 0.29`: low slop risk
- `0.30 - 0.59`: moderate slop risk
- `0.60 - 1.00`: high slop risk

This app does not claim to prove whether content is AI-generated. It highlights quality and trust signals for human review.

Responses include a complete slop picture:

- `signals`: explainable findings with category, weight, count, and description
- `dimensions`: clarity, evidence, specificity, originality, manipulation, structure, and authenticity scores
- `profile`: sentence, specificity, evidence, repetition, link, number, and citation metrics

## Project layout

```text
app/
  api/            API routes
  core/           detection engine and settings
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

- Add authenticated analyst dashboard
- Add source reputation lookups
- Add pluggable ML detector interface
- Add SIEM/SOAR integrations
- Add evidence export for case notes
