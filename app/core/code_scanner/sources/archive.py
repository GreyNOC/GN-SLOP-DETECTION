"""Archive source — extract an uploaded .zip / .tar.gz under a byte cap and scan.

The ``target`` is a local filesystem path to the archive. The API
endpoint accepts the upload, writes it to a tempfile, and constructs
an ArchiveSource pointing at that path. The source handles extraction
with strict path-traversal protection: any entry that resolves outside
the destination directory aborts the extraction.
"""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from pathlib import Path

from app.core.code_scanner.sources.base import ScanSource

# Hard cap on extracted bytes. Independent of the per-file cap because
# an archive could expand to many GB even with small per-file files.
_MAX_EXTRACTED_BYTES = 512 * 1024 * 1024


class ArchiveSource(ScanSource):
    def __init__(self, target: str) -> None:
        super().__init__(target)
        self._tempdir: tempfile.TemporaryDirectory[str] | None = None

    def _safe_join(self, dest: Path, member: str) -> Path:
        # Resolve the target without following symlinks the archive
        # provides. Anything that escapes the destination root is a
        # traversal attempt; the extractor aborts in that case.
        target = (dest / member).resolve()
        if not str(target).startswith(str(dest.resolve())):
            raise ValueError(f"Archive entry escapes destination: {member}")
        return target

    def _extract_zip(self, archive: Path, dest: Path) -> None:
        with zipfile.ZipFile(archive) as zf:
            total = 0
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive entry too large.")
                total += info.file_size
                if total > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Total extracted size exceeds cap.")
                target = self._safe_join(dest, info.filename)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open("wb") as out:
                    out.write(src.read())

    def _extract_tar(self, archive: Path, dest: Path) -> None:
        with tarfile.open(archive, "r:*") as tf:
            total = 0
            for member in tf.getmembers():
                if not (member.isfile() or member.isdir()):
                    # Drop symlinks, hardlinks, devices — never extract
                    # anything that could escape the tempdir.
                    continue
                if member.isdir():
                    continue
                if member.size > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Archive entry too large.")
                total += member.size
                if total > _MAX_EXTRACTED_BYTES:
                    raise ValueError("Total extracted size exceeds cap.")
                target = self._safe_join(dest, member.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                with target.open("wb") as out:
                    out.write(extracted.read())

    def _prepare(self) -> Path:
        archive = Path(self.target)
        if not archive.exists():
            raise FileNotFoundError(f"Archive not found: {self.target}")
        self._tempdir = tempfile.TemporaryDirectory(prefix="gn-archive-")
        dest = Path(self._tempdir.name) / "extracted"
        dest.mkdir(parents=True, exist_ok=True)
        suffix = archive.suffix.lower()
        try:
            if suffix == ".zip":
                self._extract_zip(archive, dest)
            else:
                # tarfile auto-detects .tar / .tar.gz / .tar.bz2 / .tar.xz.
                self._extract_tar(archive, dest)
        except Exception:
            if self._tempdir is not None:
                self._tempdir.cleanup()
                self._tempdir = None
            raise
        return dest

    def cleanup(self) -> None:
        if self._tempdir is not None:
            self._tempdir.cleanup()
            self._tempdir = None
