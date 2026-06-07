"""Local path source — point at a folder, scan it in-place."""

from __future__ import annotations

from pathlib import Path

from app.core.code_scanner.sources.base import ScanSource


class LocalPathSource(ScanSource):
    def _prepare(self) -> Path:
        path = Path(self.target).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Scan target does not exist: {self.target}")
        if path.is_file():
            # Single-file scan: walker still uses a directory, so we point
            # at the parent and apply an include glob via the request.
            # Returning the parent keeps the abstraction simple.
            return path.parent
        if not path.is_dir():
            raise NotADirectoryError(f"Scan target is not a directory: {self.target}")
        return path
