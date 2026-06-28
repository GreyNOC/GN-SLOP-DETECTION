"""Regression tests for the QA/QC + red-team hardening pass.

Each test pins a specific fix from the audit so the hole cannot silently
reopen. Grouped by the subsystem it guards.
"""

from __future__ import annotations

import io
import ipaddress
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

import app.main as app_main
from app.main import app

client = TestClient(app)


# --------------------------------------------------------------------------
# netguard — transitional IPv6 SSRF classification (#28)
# --------------------------------------------------------------------------
from app.core.netguard import ip_is_blocked  # noqa: E402


@pytest.mark.parametrize(
    "addr",
    [
        "127.0.0.1",
        "169.254.169.254",          # cloud metadata
        "10.0.0.5",
        "::1",
        "::ffff:127.0.0.1",          # IPv4-mapped loopback
        "::ffff:10.0.0.1",           # IPv4-mapped private
        "2002:7f00:0001::",          # 6to4 of 127.0.0.1
        "2002:a9fe:a9fe::",          # 6to4 of 169.254.169.254
        "::0a00:0001",               # IPv4-compatible 10.0.0.1
    ],
)
def test_netguard_blocks_private_and_transitional(addr):
    assert ip_is_blocked(ipaddress.ip_address(addr)) is True


@pytest.mark.parametrize("addr", ["8.8.8.8", "93.184.216.34", "2002:0808:0808::"])
def test_netguard_allows_public(addr):
    assert ip_is_blocked(ipaddress.ip_address(addr)) is False


# --------------------------------------------------------------------------
# web_ingest — DNS-rebind / TOCTOU IP pinning (#1/#4/#13)
# --------------------------------------------------------------------------
from app.core import web_ingest  # noqa: E402
from app.core.web_ingest import WebsiteFetchError, _resolve_pinned_ip, fetch_website_text  # noqa: E402


def _gai(ip: str):
    return [(2, 1, 6, "", (ip, 0))]


class _FakeSock:
    """Minimal socket http.client can drive, returning a canned response."""

    def __init__(self, response: bytes) -> None:
        self._buf = io.BytesIO(response)

    def makefile(self, *a, **k):
        return self._buf

    def sendall(self, data):  # noqa: ANN001
        return None

    def settimeout(self, t):  # noqa: ANN001
        return None

    def close(self):
        return None


def test_resolve_pinned_ip_returns_public(monkeypatch):
    monkeypatch.setattr(web_ingest.socket, "getaddrinfo", lambda *a, **k: _gai("93.184.216.34"))
    assert _resolve_pinned_ip("good.example", allow_private_urls=False) == "93.184.216.34"


def test_resolve_pinned_ip_rejects_private(monkeypatch):
    monkeypatch.setattr(web_ingest.socket, "getaddrinfo", lambda *a, **k: _gai("127.0.0.1"))
    with pytest.raises(WebsiteFetchError):
        _resolve_pinned_ip("evil.example", allow_private_urls=False)


def test_resolve_pinned_ip_rejects_mixed_records(monkeypatch):
    # A rebind can return one good and one bad record — reject the whole host.
    monkeypatch.setattr(
        web_ingest.socket,
        "getaddrinfo",
        lambda *a, **k: _gai("93.184.216.34") + _gai("127.0.0.1"),
    )
    with pytest.raises(WebsiteFetchError):
        _resolve_pinned_ip("evil.example", allow_private_urls=False)


def test_fetch_connects_to_the_validated_ip(monkeypatch):
    """The socket is opened to the resolved+validated IP, never re-resolved."""
    monkeypatch.setattr(web_ingest.socket, "getaddrinfo", lambda *a, **k: _gai("93.184.216.34"))
    connected: list[tuple] = []
    body = b"<html><body><p>pinned host body text here</p></body></html>"
    resp = (
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )

    def fake_create_connection(address, timeout=None):  # noqa: ANN001
        connected.append(address)
        return _FakeSock(resp)

    monkeypatch.setattr(web_ingest.socket, "create_connection", fake_create_connection)
    result = fetch_website_text("http://good.example/")
    assert connected == [("93.184.216.34", 80)]
    assert "pinned host body text here" in result.text


def test_fetch_rejects_rebind_to_private_at_connect(monkeypatch):
    """getaddrinfo flips public->private between validation and the pin: rejected."""
    calls = {"n": 0}

    def flipping_gai(*a, **k):
        calls["n"] += 1
        return _gai("93.184.216.34") if calls["n"] == 1 else _gai("127.0.0.1")

    monkeypatch.setattr(web_ingest.socket, "getaddrinfo", flipping_gai)
    connected: list[tuple] = []
    monkeypatch.setattr(
        web_ingest.socket,
        "create_connection",
        lambda address, timeout=None: connected.append(address) or _FakeSock(b""),
    )
    with pytest.raises(WebsiteFetchError):
        fetch_website_text("http://evil.example/")
    assert connected == []  # never connected


def test_fetch_blocks_redirect_to_private(monkeypatch):
    monkeypatch.setattr(web_ingest.socket, "getaddrinfo", lambda *a, **k: _gai("93.184.216.34"))
    resp = b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1/\r\nContent-Length: 0\r\n\r\n"
    monkeypatch.setattr(
        web_ingest.socket,
        "create_connection",
        lambda address, timeout=None: _FakeSock(resp),
    )
    with pytest.raises(WebsiteFetchError):
        fetch_website_text("http://good.example/")


# --------------------------------------------------------------------------
# llm — redaction on non-JSON replies + base_url 6to4 (#3)
# --------------------------------------------------------------------------
from app.core.code_scanner import llm as llm_mod  # noqa: E402
from app.core.code_scanner.llm import LlmConfig, judge_text, verify_finding  # noqa: E402
from app.core.code_scanner.model import Confidence, Finding, Severity  # noqa: E402

_LEAKY_SECRET = "AKIAIOSFODNN7EXAMPLE"


def _cfg() -> LlmConfig:
    return LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="k" * 24)


def test_verify_finding_redacts_secret_in_nonjson_reply(monkeypatch):
    monkeypatch.setattr(
        llm_mod,
        "_call_provider",
        lambda *a, **k: f"I refuse. Your key {_LEAKY_SECRET} is invalid.",
    )
    finding = Finding(
        rule_id="secret.aws", title="t", description="d",
        severity=Severity.HIGH, confidence=Confidence.HIGH, category="secret",
        file_path="a.py", line_start=1, line_end=1, snippet="x", remediation="r",
    )
    out = verify_finding(_cfg(), finding, "code")
    assert out.verdict == "error"
    assert _LEAKY_SECRET not in out.rationale


def test_judge_text_redacts_secret_in_nonjson_reply(monkeypatch):
    monkeypatch.setattr(
        llm_mod, "_call_provider", lambda *a, **k: f"garbage {_LEAKY_SECRET} not json"
    )
    out = judge_text(_cfg(), "some prose")
    assert out.ai_likelihood == "error"
    assert _LEAKY_SECRET not in out.rationale


# --------------------------------------------------------------------------
# routes — llm.scan snippet redaction (#6) and /analyze-url clamp (#10)
# --------------------------------------------------------------------------
import app.api.routes as routes  # noqa: E402
from app.core.code_scanner import ScanRequest, ScanTargetType, scan_target  # noqa: E402
from app.models.schemas import MAX_TEXT_LENGTH, LlmCheckConfig  # noqa: E402


def test_llm_scan_snippet_is_redacted(tmp_path, monkeypatch):
    target = tmp_path / "creds.py"
    target.write_text(f"api_key = '{_LEAKY_SECRET}'\nmore = 1\n", encoding="utf-8")
    monkeypatch.setattr(
        routes,
        "scan_whole_file",
        lambda config, path, code: [
            {"title": "planted key", "line": 1, "rationale": "looks bad", "severity": "high"}
        ],
    )
    scan_req = ScanRequest(target=str(target), target_type=ScanTargetType.PATH)
    result = scan_target(scan_req)
    payload = LlmCheckConfig(
        provider="anthropic", model="claude-opus-4-8", api_key="k" * 24, mode="scan_all_files"
    )
    routes._apply_llm(result, payload, scan_req)
    llm_findings = [f for f in result.findings if f.rule_id == "llm.scan"]
    assert llm_findings, "expected an llm.scan finding"
    for f in llm_findings:
        assert _LEAKY_SECRET not in f.snippet
    assert any(k.startswith("llm.scan@") for k in result.redacted_findings)


def test_analyze_url_large_page_does_not_500(monkeypatch):
    big = "word " * (MAX_TEXT_LENGTH // 2)  # > MAX_TEXT_LENGTH chars
    fetched = web_ingest.FetchedWebsite(
        requested_url="http://x/", final_url="http://x/", title="t",
        text=big, status_code=200, content_type="text/html", byte_count=len(big),
    )
    monkeypatch.setattr(routes, "fetch_website_text", lambda url: fetched)
    resp = client.post("/api/v1/analyze-url", json={"url": "http://example.com/"})
    assert resp.status_code == 200


# --------------------------------------------------------------------------
# archive — entry-count cap (#8) and zip symlink drop (#30)
# --------------------------------------------------------------------------
from app.core.code_scanner.sources.archive import ArchiveSource  # noqa: E402


def _write_zip(path, members: dict[str, str], symlinks: dict[str, str] | None = None):
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in members.items():
            zf.writestr(name, content)
        for name, target in (symlinks or {}).items():
            zi = zipfile.ZipInfo(name)
            zi.external_attr = 0o120777 << 16  # S_IFLNK
            zf.writestr(zi, target)


def test_archive_entry_count_cap(tmp_path, monkeypatch):
    monkeypatch.setattr("app.core.code_scanner.sources.archive._MAX_ENTRIES", 3)
    zpath = tmp_path / "many.zip"
    _write_zip(zpath, {f"f{i}.txt": "x" for i in range(6)})
    src = ArchiveSource(str(zpath))
    with pytest.raises(ValueError, match="too many entries"):
        src._prepare()
    src.cleanup()


def test_archive_drops_zip_symlink_member(tmp_path):
    zpath = tmp_path / "link.zip"
    _write_zip(zpath, {"real.txt": "hello"}, symlinks={"evil": "/etc/passwd"})
    src = ArchiveSource(str(zpath))
    dest = src._prepare()
    extracted = {p.name for p in dest.rglob("*") if p.is_file()}
    assert "real.txt" in extracted
    assert "evil" not in extracted  # symlink member skipped, not materialized
    src.cleanup()


# --------------------------------------------------------------------------
# walker — symlink-out-of-tree skip (#31)
# --------------------------------------------------------------------------
from app.core.code_scanner.walker import walk_collect  # noqa: E402


def test_walker_skips_symlink_escaping_root(tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("AKIA-out-of-tree-secret", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("print('ok')\n", encoding="utf-8")
    link = root / "leak.py"
    try:
        os.symlink(secret, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    files, _stats = walk_collect(
        root, max_bytes_per_file=1_000_000, max_total_bytes=10_000_000, max_files=100
    )
    names = {f.relative_path for f in files}
    assert "ok.py" in names
    assert "leak.py" not in names


# --------------------------------------------------------------------------
# git_remote — URL allowlist / scheme / creds (#21)
# --------------------------------------------------------------------------
from app.core.code_scanner.sources.git_remote import _validate_url  # noqa: E402


def test_git_remote_accepts_allowlisted_host():
    assert _validate_url("https://github.com/org/repo.git") == "https://github.com/org/repo.git"


@pytest.mark.parametrize(
    "url",
    [
        "https://evil.example/repo.git",
        "git://github.com/x",
        "file:///etc/passwd",
        "ssh://github.com/x",
        "https://attacker@github.com/org/repo",
        "https://u:p@github.com/org/repo",
    ],
)
def test_git_remote_rejects_bad_urls(url):
    with pytest.raises(ValueError):
        _validate_url(url)


# --------------------------------------------------------------------------
# detector — burstiness/specificity/contrastive/evidence/learned (#15/#38/#39/#16/#14)
# --------------------------------------------------------------------------
from app.core.detector import CONTRASTIVE_NEGATION_DASH_RE, SlopDetector  # noqa: E402
from app.core.learned_weights import LearnedWeights  # noqa: E402

_DET = SlopDetector()


def test_low_burstiness_fires_on_uniform_sentences():
    # 10 sentences, each exactly 9 words => perfectly uniform => burstiness 0.0.
    sentence = "alpha beta gamma delta epsilon zeta eta theta iota"
    text = ". ".join([sentence] * 10) + "."
    result = _DET.analyze(text)
    assert any(s.name == "low_burstiness" for s in result.signals)


def test_specificity_ratio_never_exceeds_one():
    dense = "Visit https://a.io/1 CVE-2021-1 v1.2.3 port 8080 192.168.1.1 ticket JIRA-12 3.5GB."
    result = _DET.analyze(dense * 3)
    assert 0.0 <= result.profile.specificity_ratio <= 1.0


def test_contrastive_dash_matches_tight_hyphen_not_compound():
    assert CONTRASTIVE_NEGATION_DASH_RE.search("not just fast-it's reliable")
    assert CONTRASTIVE_NEGATION_DASH_RE.search("not really fast - but slow")
    assert not CONTRASTIVE_NEGATION_DASH_RE.search("the well-being of our users")


def test_titlecase_pair_is_not_evidence():
    title_only = "Our Platform is guaranteed to boost results."
    with_digit = "Our Platform is guaranteed to boost results in 2024."
    with_org = "Acme Corp is guaranteed to boost results."
    assert _DET._unsupported_claim_sentences([title_only]) == 1
    assert _DET._unsupported_claim_sentences([with_digit]) == 0
    assert _DET._unsupported_claim_sentences([with_org]) == 0


def test_degenerate_learned_weights_load_as_off():
    assert LearnedWeights.from_dict({"bias": 0.5, "weights": {}}) is None
    assert LearnedWeights.from_dict({"bias": 0.5, "weights": {"a": 0.0, "b": 0.0}}) is None
    assert LearnedWeights.from_dict({"bias": 0.5, "weights": {"a": float("nan")}}) is None
    ok = LearnedWeights.from_dict({"bias": 0.0, "weights": {"vague_language": 1.2}})
    assert ok is not None


# --------------------------------------------------------------------------
# metrics — NaN/inf rejected (#40/#41)
# --------------------------------------------------------------------------
from app.eval.metrics import brier_score, expected_calibration_error, roc_auc  # noqa: E402


def test_metrics_reject_nan():
    with pytest.raises(ValueError):
        roc_auc([0.1, float("nan")], [0, 1])
    with pytest.raises(ValueError):
        expected_calibration_error([0.1, float("inf")], [0, 1])
    with pytest.raises(ValueError):
        brier_score([float("nan"), 0.2], [1, 0])


# --------------------------------------------------------------------------
# media — trailing-byte steganography across all formats (#18/#19/#27/#43)
# --------------------------------------------------------------------------
from app.core.media_detector import analyze_media  # noqa: E402

_PNG_SIG = b"\x89PNG\r\n\x1a\n"


def _png_chunk(ctype: bytes, payload: bytes) -> bytes:
    import zlib

    return (
        len(payload).to_bytes(4, "big") + ctype + payload + zlib.crc32(ctype + payload).to_bytes(4, "big")
    )


def test_png_trailing_detected_without_iend():
    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    # No IEND chunk; append a payload whose leading bytes won't parse as a chunk.
    data = _PNG_SIG + _png_chunk(b"IHDR", ihdr) + b"PK\x03\x04" + b"X" * 3000
    analysis = analyze_media(data)
    assert analysis.trailing_bytes > 1024


def test_jpeg_trailing_not_evaded_by_appended_ffd9():
    out = io.BytesIO()
    out.write(b"\xff\xd8")  # SOI
    out.write(b"\xff\xda\x00\x02")  # SOS, len 2 (no scan body)
    out.write(b"\xff\xd9")  # genuine EOI
    out.write(b"Z" * 3000 + b"\xff\xd9")  # payload that itself ends in FF D9
    analysis = analyze_media(out.getvalue())
    assert analysis.trailing_bytes > 1024


def test_gif_trailing_detected():
    gif = b"GIF89a" + b"\x01\x00\x01\x00" + b"\x00\x00\x00"  # 6 sig + 7 LSD, no GCT
    gif += b"\x3b"  # trailer
    gif += b"Y" * 3000  # appended payload
    analysis = analyze_media(gif)
    assert analysis.trailing_bytes > 1024


def test_webp_trailing_detected():
    inner = b"WEBP" + b"VP8 " + (10).to_bytes(4, "little") + b"\x00" * 10
    webp = b"RIFF" + len(inner).to_bytes(4, "little") + inner
    webp += b"Q" * 3000  # appended past the declared RIFF size
    analysis = analyze_media(webp)
    assert analysis.trailing_bytes > 1024


def test_isobmff_size0_filler_box_trailer_detected():
    ftyp_payload = b"isomavc1"
    ftyp = (len(ftyp_payload) + 8).to_bytes(4, "big") + b"ftyp" + ftyp_payload
    # free box with declared size 0 (extends to EOF) burying a payload.
    free = (0).to_bytes(4, "big") + b"free" + b"Z" * 3000
    analysis = analyze_media(ftyp + free)
    assert analysis.trailing_bytes > 1024


# --------------------------------------------------------------------------
# code rules — eval/yaml/crypto false-positive fixes (#9/#32/#34)
# --------------------------------------------------------------------------


def _scan_files(tmp_path, files: dict[str, str]):
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    req = ScanRequest(target=str(tmp_path), target_type=ScanTargetType.PATH)
    return scan_target(req)


def test_eval_member_access_not_flagged_but_bareword_is(tmp_path):
    result = _scan_files(
        tmp_path,
        {
            "ok.py": "import pandas as pd\nx = df.eval('a + b')\ny = obj.exec(q)\n",
            "bad.py": "eval(payload)\nexec(code)\n",
        },
    )
    bad = {f.file_path for f in result.findings if f.rule_id == "py.eval-on-input"}
    assert any(p.endswith("bad.py") for p in bad)
    assert not any(p.endswith("ok.py") for p in bad)


def test_yaml_safeloader_not_flagged(tmp_path):
    result = _scan_files(
        tmp_path,
        {
            "okyaml.py": "import yaml\nyaml.load(f, Loader=SafeLoader, x=1)\n",
            "badyaml.py": "import yaml\nyaml.load(stream, Loader=yaml.FullLoader)\n",
        },
    )
    flagged = {os.path.basename(f.file_path) for f in result.findings if f.rule_id == "py.yaml-unsafe-load"}
    assert "badyaml.py" in flagged
    assert "okyaml.py" not in flagged


def test_crypto_iv_salt_identifier_suffix_not_flagged(tmp_path):
    result = _scan_files(
        tmp_path,
        {
            "ok.py": "default_salt = \"justaconfigname\"\nmotiv = \"description here\"\n",
            "bad.py": "iv = \"AAAAAAAAAAAA\"\n",
        },
    )
    flagged = {f.file_path for f in result.findings if f.rule_id == "crypto.hardcoded-iv-or-salt"}
    assert any(p.endswith("bad.py") for p in flagged)
    assert not any(p.endswith("ok.py") for p in flagged)


# --------------------------------------------------------------------------
# api — batch work budget (#36)
# --------------------------------------------------------------------------


def test_batch_total_char_budget_enforced():
    big = "x" * 200_000
    resp = client.post("/api/v1/batch", json={"items": [{"text": big} for _ in range(6)]})
    assert resp.status_code == 422


def test_chunked_body_without_content_length_is_capped(monkeypatch):
    # A chunked body (iterator content => no Content-Length) larger than the cap
    # must still be rejected by the streamed byte counter, not just the header.
    monkeypatch.setattr(app_main.settings, "max_request_body_bytes", 2_000)

    def gen():
        yield b"x" * 6_000

    resp = client.post("/api/v1/analyze", content=gen())
    assert resp.status_code == 413
