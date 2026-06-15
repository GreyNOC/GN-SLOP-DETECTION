"""Tests for the frontier-model LLM seam modernization (Track A).

Covers:
  * The temperature-400 fix: adaptive-thinking Claude models omit
    ``temperature`` and send adaptive thinking + structured output, while
    legacy models keep the classic ``temperature`` body.
  * The single 400 retry that self-heals a model-style misclassification.
  * Robust text-block extraction past a leading thinking block.
  * The new ``judge_text`` text-engine seam, including rationale redaction.
  * The optional /analyze wiring.

All network egress is monkeypatched at ``_post_json`` (or the route's
``judge_text``); no real API calls happen.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.code_scanner import llm as llm_module
from app.core.code_scanner.llm import LlmConfig, judge_text, verify_finding
from app.core.code_scanner.model import Confidence, Finding, Severity
from app.main import app

client = TestClient(app)


def _finding() -> Finding:
    return Finding(
        rule_id="py.eval-on-input",
        title="eval on input",
        description="d",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category="injection",
        file_path="x.py",
        line_start=1,
        line_end=1,
        snippet="eval(payload)",
    )


def _anthropic_text(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


# ---------- temperature-400 fix / request shaping -------------------------


def test_frontier_model_omits_temperature_and_sends_modern_fields(monkeypatch) -> None:
    captured: dict = {}

    def fake_post_json(url, body, headers):  # noqa: ARG001
        captured.update(body)
        return _anthropic_text('{"verdict": "uncertain", "rationale": "ok"}')

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    out = verify_finding(config, _finding(), "eval(payload)")

    assert out.verdict == "uncertain"
    # The live bug: Opus 4.8 rejects temperature with a 400.
    assert "temperature" not in captured
    assert captured["thinking"] == {"type": "adaptive"}
    assert "format" in captured["output_config"]
    # Thinking needs output headroom.
    assert captured["max_tokens"] >= 4096


def test_legacy_model_keeps_temperature_and_skips_thinking(monkeypatch) -> None:
    captured: dict = {}

    def fake_post_json(url, body, headers):  # noqa: ARG001
        captured.update(body)
        return _anthropic_text('{"verdict": "likely_true_positive", "rationale": "ok"}')

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(
        provider="anthropic", model="claude-3-5-sonnet-20241022", api_key="x" * 40
    )
    out = verify_finding(config, _finding(), "eval(payload)")

    assert out.verdict == "likely_true_positive"
    assert captured["temperature"] == 0.0
    assert "thinking" not in captured
    assert "output_config" not in captured


def test_400_triggers_minimal_retry(monkeypatch) -> None:
    bodies: list[dict] = []

    def fake_post_json(url, body, headers):  # noqa: ARG001
        bodies.append(body)
        if len(bodies) == 1:
            return "HTTPError 400: unexpected output_config"
        return _anthropic_text('{"verdict": "uncertain", "rationale": "second try"}')

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    out = verify_finding(config, _finding(), "eval(payload)")

    assert len(bodies) == 2
    # The retry body strips every model-gated field.
    assert "temperature" not in bodies[1]
    assert "thinking" not in bodies[1]
    assert "output_config" not in bodies[1]
    assert out.verdict == "uncertain"


def test_non_400_error_does_not_retry(monkeypatch) -> None:
    calls = {"n": 0}

    def fake_post_json(url, body, headers):  # noqa: ARG001
        calls["n"] += 1
        return "HTTPError 401: Unauthorized"

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    out = verify_finding(config, _finding(), "eval(payload)")

    assert calls["n"] == 1  # auth errors are not retried
    assert out.verdict == "error"


def test_thinking_block_is_skipped_when_reading_response(monkeypatch) -> None:
    def fake_post_json(url, body, headers):  # noqa: ARG001
        return {
            "content": [
                {"type": "thinking", "thinking": "let me reason..."},
                {"type": "text", "text": '{"verdict": "likely_false_positive", "rationale": "safe"}'},
            ]
        }

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    out = verify_finding(config, _finding(), "eval(payload)")

    assert out.verdict == "likely_false_positive"


# ---------- judge_text text-engine seam -----------------------------------


def test_judge_text_returns_structured_judgment(monkeypatch) -> None:
    def fake_post_json(url, body, headers):  # noqa: ARG001
        return _anthropic_text(
            '{"ai_likelihood": "high", "slop_verdict": "slop", "rationale": "Generic filler."}'
        )

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    judgment = judge_text(config, "This revolutionary synergy is guaranteed.")

    assert judgment.ai_likelihood == "high"
    assert judgment.slop_verdict == "slop"
    assert "filler" in judgment.rationale.lower()


def test_judge_text_redacts_rationale(monkeypatch) -> None:
    def fake_post_json(url, body, headers):  # noqa: ARG001
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"ai_likelihood": "low", "slop_verdict": "review", '
                            '"rationale": "Leaked AKIAIOSFODNN7EXAMPLE here"}'
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="openai", model="gpt-4o-mini", api_key="x" * 40)
    judgment = judge_text(config, "some passage")

    assert "AKIAIOSFODNN7EXAMPLE" not in judgment.rationale
    assert "REDACTED_SECRET" in judgment.rationale


def test_judge_text_rejects_bad_base_url() -> None:
    config = LlmConfig(
        provider="anthropic",
        model="claude-opus-4-8",
        api_key="x" * 40,
        base_url="http://169.254.169.254",
    )
    judgment = judge_text(config, "passage")
    assert judgment.ai_likelihood == "error"
    assert "base_url" in judgment.rationale


def test_judge_text_clamps_unknown_enum_values(monkeypatch) -> None:
    def fake_post_json(url, body, headers):  # noqa: ARG001
        return _anthropic_text('{"ai_likelihood": "banana", "slop_verdict": "weird", "rationale": "x"}')

    monkeypatch.setattr(llm_module, "_post_json", fake_post_json)
    config = LlmConfig(provider="anthropic", model="claude-opus-4-8", api_key="x" * 40)
    judgment = judge_text(config, "passage")
    assert judgment.ai_likelihood == "medium"
    assert judgment.slop_verdict == "review"


# ---------- /analyze API wiring -------------------------------------------


def test_analyze_runs_text_judge_when_requested(monkeypatch) -> None:
    from app.api import routes as routes_module
    from app.core.code_scanner.llm import LlmTextJudgment

    def fake_judge_text(config, text):  # noqa: ARG001
        return LlmTextJudgment(
            provider="anthropic",
            model="claude-opus-4-8",
            ai_likelihood="high",
            slop_verdict="slop",
            rationale="Looks generated.",
        )

    monkeypatch.setattr(routes_module, "judge_text", fake_judge_text)
    response = client.post(
        "/api/v1/analyze",
        json={
            "text": "This revolutionary, world-class synergy is guaranteed.",
            "llm": {
                "provider": "anthropic",
                "model": "claude-opus-4-8",
                "api_key": "x" * 40,
                "mode": "judge_text",
            },
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["llm"]["ai_likelihood"] == "high"
    assert body["llm"]["slop_verdict"] == "slop"


def test_analyze_without_llm_block_has_null_judgment() -> None:
    response = client.post("/api/v1/analyze", json={"text": "A short normal sentence."})
    assert response.status_code == 200
    assert response.json()["llm"] is None
