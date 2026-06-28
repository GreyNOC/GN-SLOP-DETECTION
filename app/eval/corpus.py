"""Labeled-corpus loading for the evaluation harness.

The corpus format is newline-delimited JSON (JSONL), one example per line:

    {"id": "...", "text": "...", "label": "human"|"ai",
     "source": "...", "domain": "...", "model": "..."}

Only ``text`` and ``label`` are required. ``label`` is the ground truth:
``"ai"`` (machine-generated / slop) maps to the positive class (1) and
``"human"`` (authentic) to the negative class (0). The optional fields let an
analyst slice metrics by ``domain`` (essay / marketing / soc / support / code)
or by the generating ``model`` — the two axes detection quality varies most on.

The loader is deliberately strict about labels (a typo'd label silently
corrupts every metric downstream) but lenient about everything else: blank
lines are skipped, and a ``--lenient`` caller can keep going past malformed
rows. Duplicate texts are reported, never silently dropped, because a corpus
that accidentally repeats the same AI sample 50 times inflates AUC.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

_LABEL_TO_INT = {"human": 0, "ai": 1, "machine": 1, "authentic": 0}


@dataclass(frozen=True)
class CorpusExample:
    text: str
    label: int  # 1 == ai/slop (positive), 0 == human/authentic (negative)
    id: str = ""
    source: str = ""
    domain: str = "general"
    model: str = ""

    @property
    def label_name(self) -> str:
        return "ai" if self.label == 1 else "human"


@dataclass
class CorpusStats:
    n: int
    n_positive: int
    n_negative: int
    n_skipped: int
    duplicate_texts: int
    by_domain: dict[str, int] = field(default_factory=dict)
    by_model: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "n": self.n,
            "n_positive": self.n_positive,
            "n_negative": self.n_negative,
            "n_skipped": self.n_skipped,
            "duplicate_texts": self.duplicate_texts,
            "by_domain": dict(sorted(self.by_domain.items())),
            "by_model": dict(sorted(self.by_model.items())),
            "warnings": self.warnings,
        }


class CorpusError(ValueError):
    """Raised on a malformed corpus when not in lenient mode."""


def _parse_row(row: dict, line_no: int) -> CorpusExample:
    if "text" not in row or "label" not in row:
        raise CorpusError(f"line {line_no}: each row needs 'text' and 'label'")
    text = row["text"]
    if not isinstance(text, str) or not text.strip():
        raise CorpusError(f"line {line_no}: 'text' must be a non-empty string")
    raw_label = str(row["label"]).strip().lower()
    if raw_label not in _LABEL_TO_INT:
        raise CorpusError(
            f"line {line_no}: label {row['label']!r} is not one of "
            f"{sorted(set(_LABEL_TO_INT))}"
        )
    return CorpusExample(
        text=text,
        label=_LABEL_TO_INT[raw_label],
        id=str(row.get("id", "")),
        source=str(row.get("source", "")),
        domain=str(row.get("domain", "general")) or "general",
        model=str(row.get("model", "")),
    )


def _parse_line(line_no: int, stripped: str) -> CorpusExample:
    """Parse one non-blank JSONL line into a CorpusExample or raise CorpusError.

    Single home for the JSON-decode / non-dict / row-validation wording so the
    strict and lenient readers can never drift apart.
    """
    try:
        row = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise CorpusError(f"line {line_no}: invalid JSON ({exc.msg})") from exc
    if not isinstance(row, dict):
        raise CorpusError(f"line {line_no}: each row must be a JSON object")
    return _parse_row(row, line_no)


def iter_corpus(path: str | Path, *, lenient: bool = False) -> Iterator[CorpusExample]:
    """Yield ``CorpusExample`` rows from a JSONL file.

    Blank lines are skipped. In lenient mode, malformed rows are skipped with a
    warning to stderr instead of raising; otherwise the first bad row raises.
    """
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                example = _parse_line(line_no, stripped)
            except CorpusError:
                if lenient:
                    continue
                raise
            yield example


def load_corpus(
    path: str | Path, *, lenient: bool = False
) -> tuple[list[CorpusExample], CorpusStats]:
    """Load and validate a corpus, returning the rows plus summary stats."""
    examples: list[CorpusExample] = []
    skipped = 0
    seen_text: Counter[str] = Counter()
    by_domain: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
    warnings: list[str] = []

    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                example = _parse_line(line_no, stripped)
            except CorpusError as exc:
                if lenient:
                    skipped += 1
                    warnings.append(str(exc))
                    continue
                raise
            examples.append(example)
            seen_text[example.text.strip()] += 1
            by_domain[example.domain] += 1
            if example.model:
                by_model[example.model] += 1

    duplicate_texts = sum(count - 1 for count in seen_text.values() if count > 1)
    if duplicate_texts:
        warnings.append(f"{duplicate_texts} duplicate text(s) detected — these inflate AUC")

    n_pos = sum(1 for example in examples if example.label == 1)
    stats = CorpusStats(
        n=len(examples),
        n_positive=n_pos,
        n_negative=len(examples) - n_pos,
        n_skipped=skipped,
        duplicate_texts=duplicate_texts,
        by_domain=dict(by_domain),
        by_model=dict(by_model),
        warnings=warnings,
    )
    return examples, stats
