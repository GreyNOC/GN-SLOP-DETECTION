from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.core.code_scanner import ScanRequest, ScanTargetType, scan_target
from app.core.code_scanner.model import ScanResult
from app.core.code_scanner.sarif import to_sarif
from app.core.detector import DetectionResult, SlopDetector
from app.core.media_detector import MediaAnalysis, analyze_media
from app.core.web_ingest import FetchedWebsite, WebsiteFetchError, fetch_website_text

MEDIA_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".heic", ".heif", ".avif",
    ".mp4", ".m4v", ".mov", ".webm",
}

SPLASH = r"""
+------------------------------------------------------------------------------+
|                                                                              |
|                         G R E Y N O C   S L O P                              |
|                            D E T E C T I O N                                  |
|                                                                              |
|                                METATRON GRID                                  |
|                                                                              |
|                                  (  O  )                                      |
|                              .----/ | \----.                                  |
|                           .-'     / | \     '-.                               |
|                      (  O  )----(  O  )----(  O  )                            |
|                       / | \       / | \       / | \                            |
|                      /  |  \     /  |  \     /  |  \                           |
|                (  O  )--+---(  O  )---+--(  O  )                              |
|                   \      \   /   |   \   /      /                              |
|                    \      \ /    |    \ /      /                               |
|                     (  O  )----(  O  )----(  O  )                              |
|                    /      / \    |    / \      \                               |
|                   /      /   \   |   /   \      \                              |
|                (  O  )--+---(  O  )---+--(  O  )                              |
|                      \  |  /     \  |  /     \  |  /                           |
|                       \ | /       \ | /       \ | /                            |
|                      (  O  )----(  O  )----(  O  )                            |
|                           '-.     \ | /     .-'                               |
|                              '----\ | /----'                                  |
|                                  (  O  )                                      |
|                                                                              |
|                    GreyNOC analyst signal geometry                            |
|             Explainable slop scoring for text, files, and websites            |
|                                                                              |
+------------------------------------------------------------------------------+
""".strip("\n")

TAGLINE = "GreyNOC Slop Detection | Signal clarity for human analysts"


def iter_text_files(path: Path, recursive: bool) -> list[Path]:
    if path.is_file():
        return [path]
    pattern = "**/*.txt" if recursive else "*.txt"
    return sorted(path.glob(pattern))


def result_payload(
    result: DetectionResult,
    source: str | None,
    input_type: str,
    website: FetchedWebsite | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "source": source,
        "input_type": input_type,
        "score": result.score,
        "risk": result.risk,
        "word_count": result.word_count,
        "signals": [asdict(signal) for signal in result.signals],
        "dimensions": [asdict(dimension) for dimension in result.dimensions],
        "profile": asdict(result.profile),
        "recommendation": result.recommendation,
    }
    if website:
        payload["website"] = {
            "requested_url": website.requested_url,
            "final_url": website.final_url,
            "title": website.title,
            "status_code": website.status_code,
            "content_type": website.content_type,
            "byte_count": website.byte_count,
        }
    return payload


def print_json(payload: dict[str, Any], pretty: bool) -> None:
    print(json.dumps(payload, indent=2 if pretty else None))


def print_splash() -> None:
    print(SPLASH)
    print()
    print(TAGLINE)
    print()
    print("Quick commands:")
    print("  gn review greynoc.com")
    print("  gn review examples/sample.txt")
    print("  gn review ./docs --recursive")


def show_splash(args: argparse.Namespace) -> int:
    print_splash()
    return 0


def print_human_review(payload: dict[str, Any]) -> None:
    print(f"GreyNOC Review: {payload.get('source') or 'input'}")
    print(f"Type: {payload['input_type']}  Risk: {payload['risk'].upper()}  Score: {payload['score']:.3f}")
    print(f"Words: {payload['word_count']}  Signals: {len(payload['signals'])}")
    print(f"Recommendation: {payload['recommendation']}")
    if payload["signals"]:
        print("Signals:")
        for signal in payload["signals"][:8]:
            name = signal["name"].replace("_", " ").title()
            print(f"  - {name}: {signal['description']} x{signal['count']}")


def analyze_text(args: argparse.Namespace) -> int:
    result = SlopDetector().analyze(args.text)
    print_json(result_payload(result, args.source, "text"), args.pretty)
    return 0


def analyze_file_path(path: Path, recursive: bool) -> dict[str, Any]:
    detector = SlopDetector()
    results = []
    for file_path in iter_text_files(path, recursive):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        result = detector.analyze(text)
        results.append(result_payload(result, str(file_path), "file"))
    return {"results": results}


def analyze_files(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(json.dumps({"error": f"Path not found: {path}"}), file=sys.stderr)
        return 1

    print_json(analyze_file_path(path, args.recursive), args.pretty)
    return 0


def analyze_website_target(target: str, source: str | None) -> dict[str, Any]:
    website = fetch_website_text(target)
    result = SlopDetector().analyze(website.text)
    return result_payload(result, source or website.title or website.final_url, "website", website)


def media_payload(analysis: MediaAnalysis, source: str | None) -> dict[str, Any]:
    return {
        "source": source,
        "input_type": "media",
        "format": analysis.format.value,
        "kind": analysis.kind.value,
        "byte_size": analysis.byte_size,
        "algorithm": analysis.algorithm,
        "score": analysis.score,
        "risk": analysis.risk,
        "has_c2pa_manifest": analysis.has_c2pa_manifest,
        "has_jumbf_box": analysis.has_jumbf_box,
        "has_xmp_packet": analysis.has_xmp_packet,
        "has_synthid_marker": analysis.has_synthid_marker,
        "trailing_bytes": analysis.trailing_bytes,
        "generative_metadata_keys": list(analysis.generative_metadata_keys),
        "tool_fingerprints": list(analysis.tool_fingerprints),
        "findings": [
            {"marker": finding.marker, "confidence": finding.confidence, "detail": finding.detail}
            for finding in analysis.findings
        ],
        "recommendation": analysis.recommendation,
    }


def analyze_media_path(path: Path, source: str | None) -> dict[str, Any]:
    data = path.read_bytes()
    analysis = analyze_media(data)
    return media_payload(analysis, source or str(path))


def analyze_media_command(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists() or not path.is_file():
        print(json.dumps({"error": f"Media file not found: {path}"}), file=sys.stderr)
        return 1
    payload = analyze_media_path(path, args.source)
    print_json(payload, args.pretty)
    return 0


def _scan_result_to_payload(result: ScanResult) -> dict[str, Any]:
    return {
        "target": result.target,
        "target_type": result.target_type.value,
        "algorithm": result.algorithm,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "bytes_scanned": result.bytes_scanned,
        "elapsed_seconds": result.elapsed_seconds,
        "score": result.score,
        "risk": result.risk,
        "recommendation": result.recommendation,
        "pq_readiness": dict(result.pq_readiness),
        "git_metadata": dict(result.git_metadata),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "category": finding.category,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "line_end": finding.line_end,
                "snippet": finding.snippet,
                "remediation": finding.remediation,
            }
            for finding in result.findings
        ],
        "skipped_examples": list(result.skipped_examples),
    }


def scan_code_command(args: argparse.Namespace) -> int:
    target = args.target
    target_type = ScanTargetType(args.type)
    request = ScanRequest(
        target=target,
        target_type=target_type,
        include_globs=tuple(args.include or ()),
        exclude_globs=tuple(args.exclude or ()),
    )
    try:
        result = scan_target(request)
    except FileNotFoundError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    except (ValueError, NotADirectoryError, RuntimeError) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1

    if args.sarif:
        print(json.dumps(to_sarif(result), indent=2 if args.pretty else None))
        return 0

    payload = _scan_result_to_payload(result)
    if args.json:
        print_json(payload, args.pretty)
        return 0

    print(f"GreyNOC Code Scan: {result.target}")
    print(
        f"Files: {result.files_scanned}  Skipped: {result.files_skipped}  "
        f"Bytes: {result.bytes_scanned}  Time: {result.elapsed_seconds:.2f}s"
    )
    print(f"Risk: {result.risk.upper()}  Score: {result.score:.3f}")
    pq = result.pq_readiness
    if pq and pq.get("status") != "no_crypto_detected":
        print(
            f"PQ readiness: {pq.get('status')}  "
            f"(HNDL exposure: {pq.get('hndl_exposure', 0)}, "
            f"classical: {pq.get('classical_findings', 0)}, "
            f"PQC: {pq.get('pqc_findings', 0)})"
        )
    if result.findings:
        print("Findings:")
        for finding in result.findings[:25]:
            location = f"{finding.file_path}:{finding.line_start}"
            print(
                f"  [{finding.severity.value:>8}/{finding.confidence.value:>6}] "
                f"{finding.rule_id} — {finding.title}  ({location})"
            )
        if len(result.findings) > 25:
            print(f"  ... {len(result.findings) - 25} more")
    print(f"Recommendation: {result.recommendation}")
    return 0


def analyze_url(args: argparse.Namespace) -> int:
    try:
        payload = analyze_website_target(args.url, args.source)
    except WebsiteFetchError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1

    print_json(payload, args.pretty)
    return 0


def review_target(args: argparse.Namespace) -> int:
    target = args.target.strip()
    path = Path(target).expanduser()

    try:
        if path.exists():
            if path.is_file() and path.suffix.lower() in MEDIA_EXTENSIONS:
                payload = analyze_media_path(path, args.source or str(path))
                if args.json:
                    print_json(payload, args.pretty)
                else:
                    print(f"GreyNOC Media Review: {payload['source']}")
                    print(
                        f"Format: {payload['format']}  Kind: {payload['kind']}  "
                        f"Risk: {payload['risk'].upper()}  Score: {payload['score']:.3f}"
                    )
                    if payload["findings"]:
                        print("Findings:")
                        for finding in payload["findings"][:8]:
                            print(f"  - [{finding['confidence']}] {finding['marker']}")
                    print(f"Recommendation: {payload['recommendation']}")
                return 0

            payload = analyze_file_path(path, args.recursive)
            if args.json:
                print_json(payload, args.pretty)
            else:
                results = payload["results"]
                print(f"GreyNOC Review: {path}")
                print(f"Files reviewed: {len(results)}")
                for result in results:
                    print(
                        f"- {result['source']}: {result['risk'].upper()} "
                        f"score={result['score']:.3f} signals={len(result['signals'])}"
                    )
            return 0

        payload = analyze_website_target(target, args.source)
        if args.json:
            print_json(payload, args.pretty)
        else:
            print_human_review(payload)
        return 0
    except WebsiteFetchError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gn",
        description="GreyNOC review CLI. Use: gn review <website-or-file-path>",
        epilog="Legacy commands still work: text, file, url, splash.",
    )
    subparsers = parser.add_subparsers(dest="command")

    review_parser = subparsers.add_parser("review", help="Review a website, file, or folder.")
    review_parser.add_argument("target", help="Website/domain, file path, or folder path to review.")
    review_parser.add_argument("--source", help="Optional source label for website reviews.")
    review_parser.add_argument(
        "--recursive",
        action="store_true",
        help="Scan .txt files recursively for folder reviews.",
    )
    review_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON.")
    review_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output when using --json.")
    review_parser.set_defaults(handler=review_target)

    splash_parser = subparsers.add_parser("splash", help="Show the GreyNOC branded CLI splash screen.")
    splash_parser.set_defaults(handler=show_splash)

    text_parser = subparsers.add_parser("text", help="Analyze inline text.")
    text_parser.add_argument("text", help="Text to analyze.")
    text_parser.add_argument("--source", help="Optional source label.")
    text_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    text_parser.set_defaults(handler=analyze_text)

    file_parser = subparsers.add_parser("file", help="Analyze a text file or folder of .txt files.")
    file_parser.add_argument("path", help="Text file or directory to scan.")
    file_parser.add_argument("--recursive", action="store_true", help="Scan .txt files recursively.")
    file_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    file_parser.set_defaults(handler=analyze_files)

    url_parser = subparsers.add_parser("url", help="Fetch and analyze a website.")
    url_parser.add_argument("url", help="Website URL or plain domain to analyze.")
    url_parser.add_argument("--source", help="Optional source label.")
    url_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    url_parser.set_defaults(handler=analyze_url)

    media_parser = subparsers.add_parser("media", help="Scan an image or video for AI / provenance markers.")
    media_parser.add_argument("path", help="Path to an image or video file (.png, .jpg, .mp4, etc.).")
    media_parser.add_argument("--source", help="Optional source label.")
    media_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    media_parser.set_defaults(handler=analyze_media_command)

    scan_parser = subparsers.add_parser(
        "scan", help="Scan a code tree for backdoors, secrets, and exploit primitives."
    )
    scan_parser.add_argument(
        "target",
        help=(
            "Path to a directory (default), path to a git checkout (--type git_local), "
            "URL to a public git repo (--type git_remote), or path to a .zip / .tar.gz "
            "archive (--type archive)."
        ),
    )
    scan_parser.add_argument(
        "--type",
        choices=[t.value for t in ScanTargetType],
        default=ScanTargetType.PATH.value,
        help="Scan source type. Defaults to path.",
    )
    scan_parser.add_argument(
        "--include",
        action="append",
        help="fnmatch include pattern. May be supplied more than once.",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        help="fnmatch exclude pattern. May be supplied more than once.",
    )
    scan_parser.add_argument(
        "--json", action="store_true", help="Output the full JSON payload."
    )
    scan_parser.add_argument(
        "--sarif", action="store_true", help="Output SARIF v2.1.0 instead of the JSON payload."
    )
    scan_parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    scan_parser.set_defaults(handler=scan_code_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        print_splash()
        print()
        parser.print_help()
        return 0
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
