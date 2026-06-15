"""Tests for the optional frontier vision pass (Track B).

All network egress is mocked at app.core.code_scanner.llm._post_json — no
real API calls. Covers fusion, the anti-domination cap, honest skips
(openai / unsupported format / oversize / bad base_url), the 400 retry,
rationale redaction, and the multipart /analyze-media wiring.
"""

from __future__ import annotations

import zlib

from fastapi.testclient import TestClient

from app.core.code_scanner import llm as llm_module
from app.core.code_scanner.llm import LlmConfig
from app.core.media_detector import MediaFormat, analyze_media
from app.core.media_vision import (
    _VISION_MAX_BYTES,
    fuse_vision_into_analysis,
    judge_media_image,
)
from app.main import app

client = TestClient(app)


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    length = len(payload).to_bytes(4, "big")
    crc = zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    return length + chunk_type + payload + crc


def _png_bytes() -> bytes:
    header = b"\x89PNG\r\n\x1a\n"
    ihdr = (1).to_bytes(4, "big") + (1).to_bytes(4, "big") + bytes([8, 2, 0, 0, 0])
    return header + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IEND", b"")


def _anthropic_text(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _cfg(provider: str = "anthropic", base_url: str = "") -> LlmConfig:
    return LlmConfig(
        provider=provider, model="claude-opus-4-8", api_key="x" * 40, base_url=base_url
    )


# ---------- fusion + scoring ----------------------------------------------


def test_vision_ai_verdict_fuses_into_score(monkeypatch) -> None:
    def fake_post_json(url, body, headers):  # noqa: ARG001
        blocks = body["messages"][0]["content"]
        assert blocks[0]["type"] == "image"
        assert blocks[0]["source"]["media_type"] == "image/png"
        assert "data" in blocks[0]["source"]
        return _anthropic_text(
            '{"verdict": "likely_ai_generated", "confidence": "high", '
            '"ai_artifacts": ["six-fingered hand"], "rationale": "Malformed hand."}'
        )

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    data = _png_bytes()
    analysis = analyze_media(data)
    base_score = analysis.score
    judgment = judge_media_image(_cfg(), data, MediaFormat.PNG)
    assert judgment.verdict == "likely_ai_generated"
    fuse_vision_into_analysis(analysis, judgment)
    assert analysis.score > base_score
    assert any(
        f.category == "synthetic_generation" and "Vision" in f.marker
        for f in analysis.findings
    )


def test_vision_cannot_alone_force_high_risk(monkeypatch) -> None:
    monkeypatch.setattr(
        llm_module,
        "_post_json",
        lambda u, b, h: _anthropic_text(
            '{"verdict": "likely_ai_generated", "confidence": "high", '
            '"ai_artifacts": [], "rationale": "x"}'
        ),
    )
    data = _png_bytes()
    analysis = analyze_media(data)
    fuse_vision_into_analysis(analysis, judge_media_image(_cfg(), data, MediaFormat.PNG))
    # The one-notch downgrade (high -> medium = 0.18) keeps a clean file under
    # the 0.30 moderate floor: vision corroborates, it never convicts alone.
    assert analysis.risk == "low"
    assert analysis.score < 0.30


def test_authentic_verdict_does_not_change_score(monkeypatch) -> None:
    monkeypatch.setattr(
        llm_module,
        "_post_json",
        lambda u, b, h: _anthropic_text(
            '{"verdict": "likely_authentic", "confidence": "high", '
            '"ai_artifacts": [], "rationale": "looks real"}'
        ),
    )
    data = _png_bytes()
    analysis = analyze_media(data)
    before = analysis.score
    fuse_vision_into_analysis(analysis, judge_media_image(_cfg(), data, MediaFormat.PNG))
    assert analysis.score == before  # add-only fusion never suppresses metadata


# ---------- honest skips (no network) -------------------------------------


def test_unsupported_format_skips_without_network(monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        llm_module, "_post_json", lambda u, b, h: called.__setitem__("n", called["n"] + 1)
    )
    out = judge_media_image(_cfg(), b"\x00" * 64, MediaFormat.HEIC)
    assert out.status == "unsupported"
    assert called["n"] == 0


def test_openai_provider_skips_without_network(monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        llm_module, "_post_json", lambda u, b, h: called.__setitem__("n", called["n"] + 1)
    )
    out = judge_media_image(_cfg(provider="openai"), _png_bytes(), MediaFormat.PNG)
    assert out.status == "skipped_provider"
    assert called["n"] == 0


def test_oversize_skips_without_network(monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        llm_module, "_post_json", lambda u, b, h: called.__setitem__("n", called["n"] + 1)
    )
    out = judge_media_image(_cfg(), b"\x00" * (_VISION_MAX_BYTES + 1), MediaFormat.PNG)
    assert out.status == "oversize"
    assert called["n"] == 0


def test_bad_base_url_is_rejected_without_network(monkeypatch) -> None:
    called = {"n": 0}
    monkeypatch.setattr(
        llm_module, "_post_json", lambda u, b, h: called.__setitem__("n", called["n"] + 1)
    )
    out = judge_media_image(_cfg(base_url="http://169.254.169.254"), _png_bytes(), MediaFormat.PNG)
    assert out.status == "error"
    assert "base_url" in out.rationale
    assert called["n"] == 0


# ---------- robustness -----------------------------------------------------


def test_vision_400_triggers_minimal_retry(monkeypatch) -> None:
    bodies: list[dict] = []

    def fake_post_json(url, body, headers):  # noqa: ARG001
        bodies.append(body)
        if len(bodies) == 1:
            return "HTTPError 400: unexpected output_config"
        return _anthropic_text(
            '{"verdict": "uncertain", "confidence": "low", '
            '"ai_artifacts": [], "rationale": "retry ok"}'
        )

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    out = judge_media_image(_cfg(), _png_bytes(), MediaFormat.PNG)
    assert len(bodies) == 2
    assert "thinking" not in bodies[1]
    assert "output_config" not in bodies[1]
    assert "temperature" not in bodies[1]
    assert out.status == "ok"


def test_vision_rationale_and_artifacts_are_redacted(monkeypatch) -> None:
    monkeypatch.setattr(
        llm_module,
        "_post_json",
        lambda u, b, h: _anthropic_text(
            '{"verdict": "uncertain", "confidence": "low", '
            '"ai_artifacts": ["AKIAIOSFODNN7EXAMPLE"], '
            '"rationale": "key AKIAIOSFODNN7EXAMPLE here"}'
        ),
    )
    out = judge_media_image(_cfg(), _png_bytes(), MediaFormat.PNG)
    assert "AKIAIOSFODNN7EXAMPLE" not in out.rationale
    assert "AKIAIOSFODNN7EXAMPLE" not in " ".join(out.ai_artifacts)


# ---------- /analyze-media route wiring ------------------------------------


def test_route_surfaces_vision_block(monkeypatch) -> None:
    from app.api import routes as routes_module
    from app.core.media_vision import MediaVisionJudgment

    def fake_judge(config, data, fmt):  # noqa: ARG001
        return MediaVisionJudgment(
            provider="anthropic",
            model="claude-opus-4-8",
            verdict="likely_ai_generated",
            confidence="medium",
            ai_artifacts=["garbled text"],
            rationale="Nonsense fine print.",
            status="ok",
        )

    monkeypatch.setattr(routes_module, "judge_media_image", fake_judge)
    response = client.post(
        "/api/v1/analyze-media",
        files={"file": ("x.png", _png_bytes(), "image/png")},
        data={
            "llm_provider": "anthropic",
            "llm_model": "claude-opus-4-8",
            "llm_api_key": "x" * 40,
            "llm_mode": "vision",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["vision"]["verdict"] == "likely_ai_generated"
    assert any("Vision" in f["marker"] for f in body["findings"])


def test_route_without_llm_fields_leaves_vision_null() -> None:
    response = client.post(
        "/api/v1/analyze-media",
        files={"file": ("x.png", _png_bytes(), "image/png")},
    )
    assert response.status_code == 200
    assert response.json()["vision"] is None


def test_route_rejects_invalid_llm_fields() -> None:
    # mode=vision with a too-short api_key must 422 via the same LlmCheckConfig
    # validators the JSON path uses — not silently proceed.
    response = client.post(
        "/api/v1/analyze-media",
        files={"file": ("x.png", _png_bytes(), "image/png")},
        data={
            "llm_provider": "anthropic",
            "llm_model": "claude-opus-4-8",
            "llm_api_key": "short",
            "llm_mode": "vision",
        },
    )
    assert response.status_code == 422
