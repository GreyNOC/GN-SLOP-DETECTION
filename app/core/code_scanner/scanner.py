"""Top-level scan orchestrator.

Dispatches the target to the right source adapter, walks the resulting
tree, applies every registered rule, and assembles a ``ScanResult``
with score, risk, and recommendation. The orchestrator never raises
for an unscannable file — those count toward ``files_skipped``.
"""

from __future__ import annotations

import time
from pathlib import Path

from app.core.code_scanner.model import ScanRequest, ScanResult, ScanTargetType
from app.core.code_scanner.rules import ALL_RULES
from app.core.code_scanner.sources import resolve_source
from app.core.code_scanner.walker import detect_language, walk_collect

ALGORITHM_VERSION = "code-picture-v1"


def scan_target(request: ScanRequest) -> ScanResult:
    """Scan ``request.target``. Returns a populated ``ScanResult`` even on failure."""
    start = time.monotonic()
    source = resolve_source(request)
    root: Path = source.root
    files, walk_stats = walk_collect(
        root,
        max_bytes_per_file=request.max_bytes_per_file,
        max_total_bytes=request.max_total_bytes,
        max_files=request.max_files,
        include_globs=request.include_globs,
        exclude_globs=request.exclude_globs,
    )

    findings = []
    for walked in files:
        language = detect_language(walked.relative_path)
        for rule in ALL_RULES:
            if not rule.applies_to(language, walked.relative_path):
                continue
            try:
                findings.extend(rule.scan(path=walked.relative_path, text=walked.text))
            except Exception:
                # A single broken rule shouldn't kill the whole scan; the
                # other rules still produce signal.
                continue

    elapsed = time.monotonic() - start
    result = ScanResult(
        target=request.target,
        target_type=request.target_type,
        algorithm=ALGORITHM_VERSION,
        files_scanned=walk_stats.files_scanned,
        files_skipped=walk_stats.files_skipped,
        bytes_scanned=walk_stats.bytes_scanned,
        elapsed_seconds=round(elapsed, 3),
        findings=list(findings),
        skipped_examples=list(walk_stats.skipped_examples),
        git_metadata=source.git_metadata,
    )
    result.compute_score()

    source.cleanup()
    if request.target_type == ScanTargetType.PATH:
        # Echo the resolved target back so the dashboard / CLI can show
        # what was actually scanned (absolute path).
        result.target = str(root)
    return result
