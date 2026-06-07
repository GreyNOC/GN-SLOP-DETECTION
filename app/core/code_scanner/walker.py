"""File walker used by the scanner.

Walks a directory tree, yielding ``(relative_path, absolute_path,
text)`` triples for files that pass the size, extension, and directory
filters. Binary files are skipped because the rule engine is regex/AST
on text — pushing bytes through it is just noise that hides real
findings.

The walker is deliberately conservative: a single file over the
per-file byte cap is dropped, not truncated, so a finding's line
numbers remain trustworthy.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Final

# Directories we never descend into. Vendored deps, build outputs, and
# VCS internals would explode scan time without adding signal.
_SKIP_DIRS: Final = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".idea",
        ".vscode",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".tox",
        "dist",
        "build",
        "out",
        "target",
        "bin",
        "obj",
        ".next",
        ".nuxt",
        ".cache",
        "vendor",
        "Pods",
        "DerivedData",
        ".gradle",
        ".electron-cache",
        ".electron-builder-cache",
    }
)

# Extensions whose payload is almost always binary, generated, or
# irrelevant to backdoor / exploit-primitive analysis.
_SKIP_EXTENSIONS: Final = frozenset(
    {
        # binaries
        ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tiff",
        ".pdf", ".psd", ".ai",
        ".mp3", ".mp4", ".m4v", ".mov", ".webm", ".wav", ".ogg", ".flac",
        ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".jar", ".war", ".ear",
        ".exe", ".dll", ".so", ".dylib", ".pyd", ".o", ".a", ".obj", ".lib",
        ".class", ".pyc",
        # lockfile / IDE / scratch
        ".lock", ".log", ".tmp", ".swp", ".bak",
        # rendered docs
        ".min.js", ".min.css", ".map",
    }
)

# Text extensions we explicitly recognize. The walker still ingests
# unknown text-shaped extensions (we read a probe and decode), but
# anything in this set is processed with no extra checks.
_TEXT_EXTENSIONS: Final = frozenset(
    {
        ".py", ".pyx", ".pyi",
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        ".sh", ".bash", ".zsh", ".fish", ".ksh",
        ".yml", ".yaml",
        ".toml", ".ini", ".cfg", ".conf",
        ".json", ".json5",
        ".go",
        ".rs",
        ".java", ".kt", ".kts",
        ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hh",
        ".cs", ".fs",
        ".rb", ".erb",
        ".php", ".phtml",
        ".swift", ".m", ".mm",
        ".lua",
        ".sql",
        ".html", ".htm", ".xml", ".svg",
        ".md", ".rst", ".txt",
        ".env", ".envrc",
        ".dockerfile", ".containerfile",
        ".tf", ".tfvars",
        ".gradle",
        ".pl", ".pm",
    }
)

# Bytes of a file we probe to decide whether the rest is plausibly text.
_PROBE_BYTES: Final = 4096


# Dotted directories that carry high-signal scan targets (CI workflows
# live in .github / .gitlab; some tools put policy in .circleci). We
# allow descent into these even though they start with a dot, but
# still respect explicit _SKIP_DIRS entries like ".git" / ".idea".
_DOT_ALLOWLIST: Final = frozenset({".github", ".gitlab", ".gitea", ".circleci", ".azure"})


@dataclass(frozen=True)
class WalkedFile:
    relative_path: str
    absolute_path: Path
    text: str
    byte_size: int


@dataclass(frozen=True)
class WalkStats:
    files_scanned: int
    files_skipped: int
    bytes_scanned: int
    skipped_examples: list[str]


def _is_probably_text(probe: bytes) -> bool:
    if not probe:
        return True
    if b"\x00" in probe:
        return False
    # If more than 30% of the probe is non-printable / non-whitespace,
    # treat the file as binary.
    printable = sum(1 for byte in probe if byte in (9, 10, 13) or 32 <= byte < 127)
    return printable / len(probe) >= 0.7


def _matches_any(path: str, globs: Iterable[str]) -> bool:
    return any(fnmatch(path, pattern) for pattern in globs)


def walk_tree(
    root: Path,
    *,
    max_bytes_per_file: int,
    max_total_bytes: int,
    max_files: int,
    include_globs: tuple[str, ...] = (),
    exclude_globs: tuple[str, ...] = (),
) -> Iterator[WalkedFile]:
    """Yield text files under `root`.

    The walker tracks byte / file counts via the stats dict
    placeholder returned through `walk_stats`, but to keep the API
    streaming the stats are exposed through `walk_collect` below.
    """
    root = root.resolve()
    if not root.is_dir():
        return

    skipped_examples: list[str] = []
    total_bytes = 0
    file_count = 0

    for current_dir, dirnames, filenames in os.walk(root):
        # In-place mutation of dirnames prunes the os.walk descent.
        dirnames[:] = [
            d
            for d in dirnames
            if d not in _SKIP_DIRS
            and (not d.startswith(".") or d in _DOT_ALLOWLIST)
        ]
        for filename in filenames:
            absolute = Path(current_dir) / filename
            try:
                relative = absolute.relative_to(root).as_posix()
            except ValueError:
                continue
            suffix = absolute.suffix.lower()
            if suffix in _SKIP_EXTENSIONS:
                if len(skipped_examples) < 20:
                    skipped_examples.append(f"{relative} (binary extension)")
                continue
            if include_globs and not _matches_any(relative, include_globs):
                continue
            if exclude_globs and _matches_any(relative, exclude_globs):
                continue

            try:
                size = absolute.stat().st_size
            except OSError:
                continue
            if size <= 0:
                continue
            if size > max_bytes_per_file:
                if len(skipped_examples) < 20:
                    skipped_examples.append(f"{relative} (too large: {size} bytes)")
                continue
            if total_bytes + size > max_total_bytes:
                if len(skipped_examples) < 20:
                    skipped_examples.append(f"{relative} (total byte cap reached)")
                continue
            if file_count >= max_files:
                if len(skipped_examples) < 20:
                    skipped_examples.append(f"{relative} (max file count reached)")
                return

            try:
                with absolute.open("rb") as handle:
                    probe = handle.read(_PROBE_BYTES)
                    if not _is_probably_text(probe):
                        if len(skipped_examples) < 20:
                            skipped_examples.append(f"{relative} (binary content)")
                        continue
                    rest = handle.read()
                raw = probe + rest
            except OSError:
                continue

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                # Fall back to latin-1 so we can still scan e.g. files
                # with embedded windows-1252 quote chars. We never lose
                # bytes — latin-1 is a total mapping — so finding line
                # numbers remain trustworthy.
                text = raw.decode("latin-1", errors="replace")

            file_count += 1
            total_bytes += size

            yield WalkedFile(
                relative_path=relative,
                absolute_path=absolute,
                text=text,
                byte_size=size,
            )

    # Attach a final stats record on the generator via attribute. The
    # collect helper below picks this up.
    walk_tree._last_stats = WalkStats(  # type: ignore[attr-defined]
        files_scanned=file_count,
        files_skipped=len(skipped_examples),
        bytes_scanned=total_bytes,
        skipped_examples=skipped_examples,
    )


def walk_collect(
    root: Path,
    *,
    max_bytes_per_file: int,
    max_total_bytes: int,
    max_files: int,
    include_globs: tuple[str, ...] = (),
    exclude_globs: tuple[str, ...] = (),
) -> tuple[list[WalkedFile], WalkStats]:
    """Convenience wrapper that materializes the walk and returns stats."""
    files = list(
        walk_tree(
            root,
            max_bytes_per_file=max_bytes_per_file,
            max_total_bytes=max_total_bytes,
            max_files=max_files,
            include_globs=include_globs,
            exclude_globs=exclude_globs,
        )
    )
    stats = getattr(walk_tree, "_last_stats", WalkStats(0, 0, 0, []))
    return files, stats


def detect_language(path: str) -> str:
    """Best-effort language tag from extension. Returns ``"text"`` if unknown."""
    suffix = Path(path).suffix.lower()
    mapping = {
        ".py": "python", ".pyx": "python", ".pyi": "python",
        ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
        ".ts": "typescript", ".tsx": "typescript",
        ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".fish": "shell", ".ksh": "shell",
        ".yml": "yaml", ".yaml": "yaml",
        ".toml": "toml", ".ini": "ini",
        ".json": "json",
        ".go": "go",
        ".rs": "rust",
        ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
        ".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp", ".cxx": "cpp", ".hh": "cpp",
        ".rb": "ruby",
        ".php": "php",
        ".sql": "sql",
        ".html": "html", ".htm": "html",
        ".xml": "xml",
        ".tf": "terraform", ".tfvars": "terraform",
    }
    return mapping.get(suffix, "text")


__all__ = [
    "WalkStats",
    "WalkedFile",
    "detect_language",
    "walk_collect",
    "walk_tree",
]
