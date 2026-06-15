"""Tests for the v0.5.1 security hardening pass.

Covers universal snippet redaction, LLM base_url validation, archive
extraction tightening, request body cap middleware, and the optional
CODE_SCAN_BASE_PATH containment.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.code_scanner import ScanRequest, ScanTargetType, scan_target
from app.core.code_scanner import llm as llm_module
from app.core.code_scanner.llm import (
    LlmBaseUrlError,
    LlmConfig,
    _post_json,
    _resolve_pinned_ip,
    _validate_base_url,
    verify_finding,
)
from app.core.code_scanner.model import Confidence, Finding, Severity
from app.core.code_scanner.redaction import redact_finding_snippets
from app.core.code_scanner.sources.archive import ArchiveSource
from app.main import app

client = TestClient(app)


# ---------- universal snippet redaction ----------------------------------


def test_universal_redaction_runs_on_non_secret_rules() -> None:
    finding = Finding(
        rule_id="backdoor.env-var-trigger",
        title="env-var trigger",
        description="d",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="backdoor",
        file_path="src/leak.py",
        line_start=1,
        line_end=1,
        snippet="if os.environ.get('AKIAIOSFODNN7EXAMPLE'): run_payload()",
    )
    redacted, redacted_map = redact_finding_snippets([finding])
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted[0].snippet
    assert "REDACTED_SECRET" in redacted[0].snippet
    assert redacted_map


def test_universal_redaction_leaves_clean_findings_intact() -> None:
    finding = Finding(
        rule_id="py.eval-on-input",
        title="eval",
        description="d",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        category="injection",
        file_path="src/x.py",
        line_start=1,
        line_end=1,
        snippet="eval(user_input)",
    )
    redacted, redacted_map = redact_finding_snippets([finding])
    assert redacted[0].snippet == "eval(user_input)"
    assert not redacted_map


# ---------- LLM base_url validation --------------------------------------


def test_llm_base_url_validation_accepts_https_public() -> None:
    assert _validate_base_url("https://api.openai.com") == "https://api.openai.com"


def test_llm_base_url_validation_accepts_loopback_http() -> None:
    assert _validate_base_url("http://localhost:1234") == "http://localhost:1234"


def test_llm_base_url_validation_rejects_plain_http_remote() -> None:
    with pytest.raises(LlmBaseUrlError):
        _validate_base_url("http://api.example.com")


def test_llm_base_url_validation_rejects_private_ip() -> None:
    with pytest.raises(LlmBaseUrlError):
        _validate_base_url("https://192.168.1.5")


def test_llm_base_url_validation_rejects_metadata_service() -> None:
    with pytest.raises(LlmBaseUrlError):
        _validate_base_url("https://169.254.169.254")


def test_llm_base_url_validation_rejects_userinfo() -> None:
    with pytest.raises(LlmBaseUrlError):
        _validate_base_url("https://user:pw@api.openai.com")


def _fake_getaddrinfo(ip: str):
    import socket as _socket

    def _inner(*_args, **_kwargs):
        return [(_socket.AF_INET, _socket.SOCK_STREAM, 6, "", (ip, 0))]

    return _inner


def test_resolve_pinned_ip_returns_public_address(monkeypatch) -> None:
    monkeypatch.setattr(llm_module.socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    assert _resolve_pinned_ip("example.com", "https") == "93.184.216.34"


def test_resolve_pinned_ip_rejects_private_address(monkeypatch) -> None:
    monkeypatch.setattr(llm_module.socket, "getaddrinfo", _fake_getaddrinfo("10.0.0.5"))
    with pytest.raises(LlmBaseUrlError):
        _resolve_pinned_ip("evil.example", "https")


def test_resolve_pinned_ip_allows_loopback_name() -> None:
    assert _resolve_pinned_ip("localhost", "http") == "127.0.0.1"


def test_post_json_does_not_connect_on_dns_rebind(monkeypatch) -> None:
    # A host that resolves to a private/metadata address must be refused at
    # connect time — the socket is pinned to the validated IP, so a rebind to
    # 169.254.169.254 never gets a connection.
    monkeypatch.setattr(llm_module.socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    connected: list = []

    def _no_connect(*args, **kwargs):  # noqa: ANN002, ANN003
        connected.append(args)
        raise AssertionError("must not connect to a rebound address")

    monkeypatch.setattr(llm_module.socket, "create_connection", _no_connect)
    result = _post_json("https://evil.example/v1/messages", {"x": 1}, {"x-api-key": "secret"})
    assert isinstance(result, str)
    assert result.startswith("URLError")
    assert connected == []  # no socket was ever opened


def test_llm_verify_finding_returns_error_for_bad_base_url() -> None:
    config = LlmConfig(
        provider="openai",
        model="gpt-4o-mini",
        api_key="fake",
        base_url="http://192.168.1.5",
    )
    finding = Finding(
        rule_id="py.eval-on-input",
        title="t",
        description="d",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="injection",
        file_path="x.py",
        line_start=1,
        line_end=1,
        snippet="eval(payload)",
    )
    out = verify_finding(config, finding, "eval(payload)")
    assert out.verdict == "error"
    assert "base_url" in out.rationale


# ---------- archive extraction hardening ---------------------------------


def test_archive_traversal_via_double_dot_is_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../escaped.txt", "owned")
    with pytest.raises(ValueError):
        scan_target(ScanRequest(target=str(archive), target_type=ScanTargetType.ARCHIVE))


def test_archive_absolute_path_member_is_blocked(tmp_path: Path) -> None:
    archive = tmp_path / "abs.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("/etc/passwd", "owned")
    with pytest.raises(ValueError):
        scan_target(ScanRequest(target=str(archive), target_type=ScanTargetType.ARCHIVE))


def test_tar_symlink_member_is_dropped(tmp_path: Path) -> None:
    archive = tmp_path / "link.tar"
    target_outside = tmp_path / "outside_target.txt"
    target_outside.write_text("DO NOT TOUCH", encoding="utf-8")
    with tarfile.open(archive, "w") as tf:
        info = tarfile.TarInfo("link_to_outside")
        info.type = tarfile.SYMTYPE
        info.linkname = str(target_outside)
        tf.addfile(info)
        real_data = b"print(1)\n"
        real_info = tarfile.TarInfo("ok.py")
        real_info.size = len(real_data)
        tf.addfile(real_info, io.BytesIO(real_data))
    result = scan_target(ScanRequest(target=str(archive), target_type=ScanTargetType.ARCHIVE))
    assert result.files_scanned >= 1


def test_archive_extraction_rejects_oversized_member(monkeypatch, tmp_path: Path) -> None:
    from app.core.code_scanner.sources import archive as archive_module

    monkeypatch.setattr(archive_module, "_MAX_EXTRACTED_BYTES", 64)
    archive = tmp_path / "big.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("big.txt", b"x" * 200)
    source = ArchiveSource(str(archive))
    with pytest.raises(ValueError):
        _ = source.root


# ---------- request body cap middleware ----------------------------------


def test_body_cap_rejects_oversize_announced_content_length(monkeypatch) -> None:
    from app import main as app_main

    monkeypatch.setattr(app_main.settings, "max_request_body_bytes", 1024)
    response = client.post(
        "/api/v1/analyze",
        json={"text": "x"},
        headers={"Content-Length": "1048576"},
    )
    assert response.status_code == 413
    assert "cap" in response.json()["detail"]


def test_body_cap_is_a_no_op_when_disabled(monkeypatch) -> None:
    from app import main as app_main

    monkeypatch.setattr(app_main.settings, "max_request_body_bytes", 0)
    response = client.post(
        "/api/v1/analyze",
        json={"text": "hello"},
    )
    assert response.status_code == 200


# ---------- code-scan target containment ---------------------------------


def _settings_stub(base: str):
    class _S:
        code_scan_base_path = base
    return _S()


def test_scan_outside_base_path_is_forbidden(monkeypatch, tmp_path: Path) -> None:
    base = tmp_path / "allowed"
    base.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "x.py").write_text("print(1)\n", encoding="utf-8")

    from app.core.code_scanner import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_settings", lambda: _settings_stub(str(base)))

    with pytest.raises(scanner_module.ScanTargetForbidden):
        scan_target(ScanRequest(target=str(elsewhere), target_type=ScanTargetType.PATH))


def test_scan_inside_base_path_is_allowed(monkeypatch, tmp_path: Path) -> None:
    base = tmp_path / "allowed"
    base.mkdir()
    (base / "x.py").write_text("print(1)\n", encoding="utf-8")

    from app.core.code_scanner import scanner as scanner_module

    monkeypatch.setattr(scanner_module, "get_settings", lambda: _settings_stub(str(base)))

    result = scan_target(ScanRequest(target=str(base), target_type=ScanTargetType.PATH))
    assert result.files_scanned == 1


# ---------- same-origin / CSRF guard -------------------------------------


def test_same_origin_blocks_cross_origin_post() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"text": "hello"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "Cross-origin" in response.json()["detail"]


def test_same_origin_allows_no_origin_header() -> None:
    # CLI / curl / server-to-server case — no Origin, no Referer.
    response = client.post("/api/v1/analyze", json={"text": "hello"})
    assert response.status_code == 200


def test_same_origin_allows_matching_origin() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"text": "hello"},
        headers={"Origin": "http://testserver"},
    )
    assert response.status_code == 200


def test_same_origin_can_be_disabled_via_setting(monkeypatch) -> None:
    from app import main as app_main

    monkeypatch.setattr(app_main.settings, "enforce_same_origin", False)
    response = client.post(
        "/api/v1/analyze",
        json={"text": "hello"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 200


def test_same_origin_honors_extra_trusted_origins(monkeypatch) -> None:
    from app import main as app_main

    monkeypatch.setattr(app_main.settings, "extra_trusted_origins", "https://app.example")
    response = client.post(
        "/api/v1/analyze",
        json={"text": "hello"},
        headers={"Origin": "https://app.example"},
    )
    assert response.status_code == 200


# ---------- LLM rationale redaction --------------------------------------


def test_llm_verify_finding_redacts_rationale(monkeypatch) -> None:
    """If the LLM echoes a credential back, it must be redacted on response."""
    from app.core.code_scanner import llm as llm_module

    # Pretend the LLM responded with a rationale containing an AWS key.
    fake_message = (
        '{"verdict": "likely_true_positive", '
        '"rationale": "Looks like AKIAIOSFODNN7EXAMPLE leaked"}'
    )

    def fake_post_json(url, body, headers):  # noqa: ARG001
        return {"choices": [{"message": {"content": fake_message}}]}

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="openai", model="gpt-4o-mini", api_key="x" * 40)
    finding = Finding(
        rule_id="py.eval-on-input",
        title="t",
        description="d",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="injection",
        file_path="x.py",
        line_start=1,
        line_end=1,
        snippet="eval(payload)",
    )
    verification = verify_finding(config, finding, "eval(payload)")
    assert "AKIAIOSFODNN7EXAMPLE" not in verification.rationale
    assert "REDACTED_SECRET" in verification.rationale


# ---------- schema validation of LlmCheckConfig --------------------------


def test_llm_config_rejects_short_api_key() -> None:
    response = client.post(
        "/api/v1/scan-code",
        json={
            "target": ".",
            "target_type": "path",
            "llm": {
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "tiny",
                "mode": "verify_findings",
            },
        },
    )
    assert response.status_code == 422


def test_llm_config_rejects_unknown_provider() -> None:
    response = client.post(
        "/api/v1/scan-code",
        json={
            "target": ".",
            "target_type": "path",
            "llm": {
                "provider": "imaginary",
                "model": "x",
                "api_key": "x" * 40,
                "mode": "off",
            },
        },
    )
    assert response.status_code == 422


def test_llm_config_rejects_unknown_mode() -> None:
    response = client.post(
        "/api/v1/scan-code",
        json={
            "target": ".",
            "target_type": "path",
            "llm": {
                "provider": "openai",
                "model": "x",
                "api_key": "x" * 40,
                "mode": "scan_my_email",
            },
        },
    )
    assert response.status_code == 422
