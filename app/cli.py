from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.core.detector import DetectionResult, SlopDetector
from app.core.web_ingest import FetchedWebsite, WebsiteFetchError, fetch_website_text

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
    review_parser.add_argument("--recursive", action="store_true", help="Scan .txt files recursively for folder reviews.")
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
