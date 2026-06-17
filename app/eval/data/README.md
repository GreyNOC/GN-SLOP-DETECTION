# Seed corpus — what it is and what it is not

`seed_corpus.jsonl` is a **smoke-test corpus**, not a benchmark. It exists so
the evaluation harness has something to run against out of the box and so CI
can assert the pipeline end-to-end produces sane numbers. Do **not** read a
headline ROC-AUC off it and call the detector "state of the art" — the sample
is tiny (24 rows) and the two classes are deliberately easy to tell apart.

## Provenance (labeled honestly)

- **`human` rows** are either genuine **public-domain** text written long before
  LLMs existed (US Constitution, Federalist No. 10, Austen, Conan Doyle,
  Lincoln, Thoreau) or short notes **authored to read as ordinary human work**
  (a SOC incident note, a support reply, a bug report, a product review, a
  forum post). The `source` field records which.
- **`ai` rows** are **authored to be representative of generated slop**
  (`source: synthetic-style:authored-representative-generated-slop`). They are
  *not* sampled from a real model run. This is an honest proxy: it captures the
  rhetorical and structural tells (contrastive negation, rule-of-three, filler,
  emoji-bulleted markdown, assistant scaffolding) but it cannot capture the
  *distributional* signal that perplexity/Binoculars detectors key on.

## To turn this into a real evaluation

Replace this file with a corpus of **real** samples:

1. **Human**: pull from pre-2021 sources (so they predate ChatGPT) across the
   domains you actually review — pre-LLM tickets, reports, articles. Mind the
   documented bias risk (Liang et al. 2023): include **non-native-English**
   human writing so you measure, rather than ignore, your false-positive rate
   on it.
2. **AI**: generate from the models you care about (label the `model` field),
   across the same domains and lengths, including *lightly edited* and
   *paraphrased* AI text — that is where detectors fall apart (the RAID
   benchmark, Dugan et al. 2024).
3. Keep the classes **balanced** and **deduplicated** (the loader warns on
   duplicates because they inflate AUC).

## Format

One JSON object per line:

```json
{"id": "...", "text": "...", "label": "human"|"ai",
 "source": "...", "domain": "essay|marketing|soc|support|code|...",
 "model": "gpt-4o|claude-...|..."}
```

Only `text` and `label` are required. `domain` lets the runner apply the
matching rule-engine profile and lets you slice metrics by content type;
`model` lets you slice detection quality by generator.

## Run it

```bash
python -m app.eval report    app/eval/data/seed_corpus.jsonl
python -m app.eval calibrate app/eval/data/seed_corpus.jsonl
```
