"""Command-line entry point for the evaluation harness.

    python -m app.eval report   [corpus.jsonl] [--profile P] [--threshold T] [--json]
    python -m app.eval calibrate [corpus.jsonl] [--json]

``report`` scores the corpus with the rule engine (and, if ``SLOP_MODEL_DETECTOR``
is configured, the model detector too) and prints ROC-AUC, TPR at fixed FPR,
F1, and calibration numbers. ``calibrate`` fits Platt scaling for the rule
engine score and prints the before/after calibration error.

With no corpus path it uses the bundled seed corpus — enough to smoke-test the
pipeline, but NOT a benchmark (see app/eval/data/README.md).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.core.model_detector import select_default_from_env
from app.eval.calibrate import fit_platt
from app.eval.corpus import CorpusError, load_corpus
from app.eval.metrics import EvaluationReport
from app.eval.runner import collect_scores, rule_engine_scorer, run_scorers

_SEED_CORPUS = Path(__file__).parent / "data" / "seed_corpus.jsonl"


def _format_report(report: EvaluationReport) -> str:
    lines = [f"  [{report.name}]"]
    if report.n == 0:
        lines.append(f"    no scorable examples (skipped {report.n_skipped})")
        for note in report.notes:
            lines.append(f"    note: {note}")
        return "\n".join(lines)

    def pct(value: float | None) -> str:
        return "n/a" if value is None else f"{value * 100:5.1f}%"

    lines.append(f"    n={report.n}  (ai={report.n_positive}, human={report.n_negative}, skipped={report.n_skipped})")
    lines.append(f"    ROC-AUC          : {pct(report.roc_auc)}")
    lines.append(f"    TPR @ 1% FPR     : {pct(report.tpr_at_1pct_fpr)}")
    lines.append(f"    TPR @ 5% FPR     : {pct(report.tpr_at_5pct_fpr)}")
    lines.append(f"    TPR @ 10% FPR    : {pct(report.tpr_at_10pct_fpr)}")
    if report.best_f1 is not None:
        bf = report.best_f1
        lines.append(
            f"    best F1          : {bf.f1:.3f} @ threshold {bf.threshold:.3f} "
            f"(P={bf.precision:.2f} R={bf.recall:.2f} FPR={bf.fpr:.2f})"
        )
    if report.at_threshold is not None:
        at = report.at_threshold
        lines.append(
            f"    @ threshold {at.threshold:.2f}   : F1={at.f1:.3f} "
            f"P={at.precision:.2f} R={at.recall:.2f} FPR={at.fpr:.2f}"
        )
    if report.ece is not None:
        lines.append(f"    ECE / Brier      : {report.ece:.4f} / {report.brier:.4f}")
    for note in report.notes:
        lines.append(f"    note: {note}")
    return "\n".join(lines)


def _load(path: Path, lenient: bool):
    try:
        return load_corpus(path, lenient=lenient)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    except FileNotFoundError:
        print(f"corpus not found: {path}", file=sys.stderr)
        raise SystemExit(2) from None


def _cmd_report(args: argparse.Namespace) -> int:
    path = Path(args.corpus) if args.corpus else _SEED_CORPUS
    examples, stats = _load(path, args.lenient)

    scorers = {"rule_engine": rule_engine_scorer(profile=args.profile)}
    model_detector = select_default_from_env()
    if model_detector.is_available():
        from app.eval.runner import model_detector_scorer

        scorers[f"model:{model_detector.name}"] = model_detector_scorer(model_detector)

    result = run_scorers(examples, scorers, threshold=args.threshold)

    if args.json:
        print(json.dumps({"corpus": stats.as_dict(), "reports": result.as_dict()["reports"]}, indent=2))
        return 0

    print(f"corpus: {path}")
    print(f"  {stats.n} examples (ai={stats.n_positive}, human={stats.n_negative})")
    if stats.by_domain:
        print(f"  by domain: {stats.as_dict()['by_domain']}")
    for warning in stats.warnings:
        print(f"  ! {warning}")
    print()
    for report in result.reports:
        print(_format_report(report))
        print()
    return 0


def _cmd_calibrate(args: argparse.Namespace) -> int:
    path = Path(args.corpus) if args.corpus else _SEED_CORPUS
    examples, _stats = _load(path, args.lenient)
    scores, labels = collect_scores(examples, rule_engine_scorer(profile=args.profile))
    if not scores:
        print("no scorable examples to calibrate", file=sys.stderr)
        return 2
    calibration = fit_platt(scores, labels)
    if args.json:
        print(json.dumps(calibration.as_dict(), indent=2))
        return 0
    data = calibration.as_dict()
    print(f"Platt scaling for rule_engine score (n={calibration.n}):")
    print(f"  calibrated_p = sigmoid({data['model']['bias']} + "
          f"{data['model']['coefficients']['score']} * score)")
    print(f"  ECE  : {data['ece_before']} -> {data['ece_after']}")
    print(f"  Brier: {data['brier_before']} -> {data['brier_after']}")
    return 0


def _cmd_learn_weights(args: argparse.Namespace) -> int:
    from app.eval.learn_weights import learn_signal_weights, write_weights_file

    path = Path(args.corpus) if args.corpus else _SEED_CORPUS
    examples, _stats = _load(path, args.lenient)
    try:
        result = learn_signal_weights(examples, l2=args.l2)
    except ValueError as exc:
        print(f"could not learn weights: {exc}", file=sys.stderr)
        return 2
    if args.output:
        write_weights_file(result, args.output)
    payload = result.to_weights_file()
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0
    print(f"Learned signal weights (n={result.trained_on}, l2={result.l2}):")
    print(f"  train AUC (optimistic): {payload['train_auc']}")
    print(f"  bias: {payload['bias']}")
    for name, value in sorted(result.weights.items(), key=lambda kv: -abs(kv[1])):
        print(f"    {name:30s} {value:+.4f}")
    if args.output:
        print(f"\nWrote {args.output}. Use it with SLOP_LEARNED_WEIGHTS={args.output}")
    else:
        print("\n(no --output given; weights not saved)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.eval", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    report = sub.add_parser("report", help="score a corpus and print metrics")
    report.add_argument("corpus", nargs="?", help="path to a JSONL corpus (default: bundled seed)")
    report.add_argument("--profile", default="general", help="rule-engine profile")
    report.add_argument("--threshold", type=float, default=0.5, help="operating threshold for P/R/F1")
    report.add_argument("--lenient", action="store_true", help="skip malformed rows instead of failing")
    report.add_argument("--json", action="store_true", help="emit JSON")
    report.set_defaults(func=_cmd_report)

    calibrate = sub.add_parser("calibrate", help="fit Platt scaling for the rule engine score")
    calibrate.add_argument("corpus", nargs="?", help="path to a JSONL corpus (default: bundled seed)")
    calibrate.add_argument("--profile", default="general", help="rule-engine profile")
    calibrate.add_argument("--lenient", action="store_true", help="skip malformed rows instead of failing")
    calibrate.add_argument("--json", action="store_true", help="emit JSON")
    calibrate.set_defaults(func=_cmd_calibrate)

    learn = sub.add_parser("learn-weights", help="fit glass-box per-signal weights from a corpus")
    learn.add_argument("corpus", nargs="?", help="path to a JSONL corpus (default: bundled seed)")
    learn.add_argument("-o", "--output", help="write the weights JSON here (for SLOP_LEARNED_WEIGHTS)")
    learn.add_argument("--l2", type=float, default=2.0, help="L2 regularization strength")
    learn.add_argument("--lenient", action="store_true", help="skip malformed rows instead of failing")
    learn.add_argument("--json", action="store_true", help="emit JSON")
    learn.set_defaults(func=_cmd_learn_weights)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
