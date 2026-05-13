#!/usr/bin/env python3
# ruff: noqa: E402, I001
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.cli import main


if __name__ == "__main__":
    raise SystemExit(main(["file", *sys.argv[1:]]))
