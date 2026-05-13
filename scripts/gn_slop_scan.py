#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.core.detector import SlopDetector  # noqa: E402


def iter_files(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    pattern = "**/*.txt" if recursive else "*.txt"
    return sorted(path.glob(pattern))


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan text files for slop indicators.")
    parser.add_argument("path", help="Text file or directory to scan")
    parser.add_argument("--recursive", action="store_true", help="Scan .txt files recursively")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(json.dumps({"error": f"Path not found: {path}"}), file=sys.stderr)
        return 1

    detector = SlopDetector()
    results = []
    for file_path in iter_files(path, args.recursive):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        result = detector.analyze(text)
        results.append(
            {
                "source": str(file_path),
                "score": result.score,
                "risk": result.risk,
                "word_count": result.word_count,
                "signals": [signal.__dict__ for signal in result.signals],
                "recommendation": result.recommendation,
            }
        )

    print(json.dumps({"results": results}, indent=2 if args.pretty else None))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
