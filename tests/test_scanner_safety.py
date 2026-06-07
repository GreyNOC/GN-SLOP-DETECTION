"""Safety / correctness tests for the code scanner core.

Covers single-file scoping, source-cleanup-on-failure, walker skip
counts, secret redaction, LLM verification serialization, suppression
comments, scoring floors, and rule-error capture.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.code_scanner import ScanRequest, ScanTargetType, scan_target
from app.core.code_scanner.model import (
    Confidence,
    Finding,
    LlmVerification,
    Severity,
)
from app.core.code_scanner.redaction import redact_finding_snippets
from app.core.code_scanner.suppression import is_suppressed
from app.main import app

client = TestClient(app)


def _write(tmp_path: Path, relative: str, content: str) -> None:
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")


# ---------- single-file scan -----------------------------------------------


def test_single_file_target_ignores_siblings(tmp_path: Path) -> None:
    _write(tmp_path, "safe.py", "print('ok')\n")
    _write(tmp_path, "danger.py", "eval(payload)\n")
    result = scan_target(
        ScanRequest(target=str(tmp_path / "safe.py"), target_type=ScanTargetType.PATH)
    )
    assert result.files_scanned == 1
    assert not any(f.file_path == "danger.py" for f in result.findings)


# ---------- cleanup-on-failure --------------------------------------------


def test_scan_target_always_calls_cleanup(monkeypatch, tmp_path: Path) -> None:
    """If the orchestrator blows up mid-scan, source.cleanup() still runs."""
    from app.core.code_scanner.sources import local as local_module

    cleanup_calls = {"count": 0}

    class BoomSource(local_module.LocalPathSource):
        def cleanup(self) -> None:
            cleanup_calls["count"] += 1

    # Patch the source resolver so we hand back our subclass.
    from app.core.code_scanner import sources as sources_pkg

    original = sources_pkg.resolve_source

    def fake_resolve(request):
        if request.target_type == ScanTargetType.PATH:
            return BoomSource(request.target)
        return original(request)

    monkeypatch.setattr(sources_pkg, "resolve_source", fake_resolve)
    # Also override the resolve_source imported into scanner.py at module load.
    from app.core.code_scanner import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "resolve_source", fake_resolve)

    # Cause the walker to raise mid-scan.
    monkeypatch.setattr(
        scanner_module,
        "walk_collect",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    try:
        scanner_module.scan_target(
            ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH)
        )
    except RuntimeError:
        pass

    assert cleanup_calls["count"] == 1


# ---------- walker stats --------------------------------------------------


def test_walker_files_skipped_is_true_count(tmp_path: Path) -> None:
    for index in range(40):
        (tmp_path / f"image{index}.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)
    (tmp_path / "ok.py").write_text("print(1)\n", encoding="utf-8")
    from app.core.code_scanner.walker import walk_collect

    files, stats = walk_collect(
        tmp_path,
        max_bytes_per_file=1_000_000,
        max_total_bytes=10_000_000,
        max_files=10_000,
    )
    # All 40 PNGs land in files_skipped; the example list is capped.
    assert stats.files_skipped == 40
    assert len(stats.skipped_examples) <= 20
    assert len(files) == 1


# ---------- secret redaction ----------------------------------------------


def test_secret_findings_redact_aws_key_in_snippet(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/secrets.py",
        "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n",
    )
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    target = next(f for f in result.findings if f.rule_id == "secret.aws-access-key-id")
    assert "AKIAIOSFODNN7EXAMPLE" not in target.snippet
    assert "REDACTED_SECRET" in target.snippet
    assert any(
        key.startswith("secret.aws-access-key-id@") for key in result.redacted_findings
    )


def test_secret_findings_redact_in_api_response(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/secrets.py",
        "GH_TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD'\n",
    )
    response = client.post(
        "/api/v1/scan-code",
        json={"target": str(tmp_path), "target_type": "path"},
    )
    body = response.json()
    raw = response.text
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD" not in raw
    target = next(f for f in body["findings"] if f["rule_id"] == "secret.github-pat")
    assert target["redacted"] is True


def test_redaction_helper_handles_pem_block() -> None:
    finding = Finding(
        rule_id="secret.private-key-pem",
        title="Private key",
        description="d",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="secret",
        file_path="x.pem",
        line_start=1,
        line_end=3,
        snippet="-----BEGIN RSA PRIVATE KEY-----\nMIIBOQIB...AAAAAA==\n-----END RSA PRIVATE KEY-----",
    )
    out, _redacted = redact_finding_snippets([finding])
    assert "MIIBOQIB" not in out[0].snippet
    assert "REDACTED_PRIVATE_KEY_BLOCK" in out[0].snippet


# ---------- LLM verification wiring ---------------------------------------


def test_llm_scan_all_files_honors_single_file_target(tmp_path: Path, monkeypatch) -> None:
    """A single-file PATH target with whole-file LLM mode must not ship siblings to the LLM.

    Codex P1 review: previously ``_apply_llm`` re-resolved the source via
    ``LocalPathSource(result.target).root`` and re-walked the *parent*
    directory with the original empty include_globs, defeating the
    single-file privacy/cost fix.
    """
    _write(tmp_path, "safe.py", "eval(payload)\n")
    _write(tmp_path, "secret.py", "eval(secret_payload)\n")

    from app.api import routes as routes_module

    sent_paths: list[str] = []

    def fake_scan_whole_file(config, path, code):  # noqa: ARG001
        sent_paths.append(path)
        return []

    monkeypatch.setattr(routes_module, "scan_whole_file", fake_scan_whole_file)

    response = client.post(
        "/api/v1/scan-code",
        json={
            "target": str(tmp_path / "safe.py"),
            "target_type": "path",
            "llm": {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "fake-key",
                "mode": "scan_all_files",
            },
        },
    )
    assert response.status_code == 200
    # Only the targeted file should have been sent to the LLM.
    assert sent_paths == ["safe.py"]
    assert "secret.py" not in sent_paths


def test_llm_verification_serializes_into_response(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path, "src/x.py", "eval(payload)\n")

    # Mock the LLM verifier so no network calls happen.
    fake_verification = LlmVerification(
        provider="openai",
        model="gpt-4o-mini",
        verdict="likely_true_positive",
        rationale="DSL parser is intentionally dynamic.",
    )
    from app.api import routes as routes_module

    def fake_verify(config, finding, code):  # noqa: ARG001
        return fake_verification

    monkeypatch.setattr(routes_module, "verify_finding", fake_verify)
    response = client.post(
        "/api/v1/scan-code",
        json={
            "target": str(tmp_path),
            "target_type": "path",
            "llm": {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "fake-key",
                "mode": "verify_findings",
            },
        },
    )
    body = response.json()
    target = next(f for f in body["findings"] if f["rule_id"] == "py.eval-on-input")
    assert target["llm_verdict"] == "likely_true_positive"
    assert "DSL parser" in target["llm_rationale"]


# ---------- suppression ---------------------------------------------------


def test_suppression_comment_on_same_line(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/danger.py",
        "x = eval(payload)  # gn-slop: ignore py.eval-on-input reason=\"DSL\"\n",
    )
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    assert result.suppressed_count == 1
    assert not any(f.rule_id == "py.eval-on-input" for f in result.findings)


def test_suppression_comment_on_previous_line(tmp_path: Path) -> None:
    body = (
        "# gn-slop: ignore py.eval-on-input reason=\"sandboxed test fixture\"\n"
        "eval(payload)\n"
    )
    _write(tmp_path, "src/danger.py", body)
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    assert result.suppressed_count >= 1
    assert not any(f.rule_id == "py.eval-on-input" for f in result.findings)


def test_is_suppressed_with_mismatched_rule_id() -> None:
    body = "eval(payload)  # gn-slop: ignore js.eval"
    assert is_suppressed(body, "py.eval-on-input", 1) is False
    assert is_suppressed(body, "js.eval", 1) is True


# ---------- scoring floors ------------------------------------------------


def test_high_confidence_secret_floors_high_risk(tmp_path: Path) -> None:
    # Build a 20-file repo, only one of which has a real secret. Without
    # the floor the sqrt(20) normalizer dilutes the composite below the
    # high threshold; with the floor we still land on HIGH.
    for index in range(20):
        _write(tmp_path, f"src/safe_{index}.py", f"# clean file {index}\nprint({index})\n")
    _write(
        tmp_path,
        "src/leak.py",
        "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n",
    )
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    assert result.risk == "high"


def test_critical_backdoor_floors_high_risk(tmp_path: Path) -> None:
    for index in range(20):
        _write(tmp_path, f"src/safe_{index}.py", "print(1)\n")
    body = (
        "import pickle, requests\n"
        "out = pickle.loads(requests.get(url).content)\n"
    )
    _write(tmp_path, "src/payload.py", body)
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    assert result.risk == "high"


# ---------- rule_errors collection ----------------------------------------


def test_rule_errors_capture(tmp_path: Path, monkeypatch) -> None:
    _write(tmp_path, "src/x.py", "print(1)\n")
    # Inject a synthetic rule into the registry that always raises.
    from app.core.code_scanner import rules as rules_module
    from app.core.code_scanner import scanner as scanner_module
    from app.core.code_scanner.rules.base import Rule

    class _AlwaysBoomRule(Rule):
        def __init__(self) -> None:
            super().__init__(
                rule_id="test.always-boom",
                title="boom",
                description="d",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                category="test",
            )

        def scan(self, *, path: str, text: str):  # type: ignore[override]
            raise RuntimeError("simulated")

    monkeypatch.setattr(
        scanner_module,
        "ALL_RULES",
        (*rules_module.ALL_RULES, _AlwaysBoomRule()),
    )
    result = scan_target(ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH))
    assert any(error["rule_id"] == "test.always-boom" for error in result.rule_errors)
    assert result.files_scanned == 1
