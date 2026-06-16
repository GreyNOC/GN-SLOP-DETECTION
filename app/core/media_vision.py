"""Optional frontier-vision pass for the media engine.

The static media detector (``app/core/media_detector.py``) is pure-bytes:
it reads container structure and metadata but never decodes a pixel. That
makes it precise when provenance metadata survives, and blind the moment a
file is screenshotted, re-encoded, or scrubbed of metadata.

This module adds an OPT-IN second opinion: it hands the actual image to a
frontier vision model and asks for pixel-level AI-generation artifacts
(malformed hands/text, impossible reflections, inconsistent lighting,
tiled textures). It reuses the hardened BYO-LLM seam in
``app/core/code_scanner/llm.py`` so there is no second, less-careful
network path: same SSRF base-URL validation, same bounded egress, same
structured-output + 400-retry plumbing, same rationale redaction.

Design guarantees, in keeping with the project philosophy:
  * No new runtime dependency — stdlib ``base64`` plus the existing urllib
    seam.
  * Strictly opt-in — no API key means zero network.
  * Anthropic-only and image-only. OpenAI, video (MP4/MOV), and HEIC/AVIF
    (which the API cannot decode and which would need a forbidden decoder
    dependency to transcode) return a clear *skip* status, never an error.
  * Honest fusion — a vision verdict enters scoring as ONE capped
    ``synthetic_generation`` finding, deliberately downgraded one
    confidence notch so a single vision call can corroborate but never
    single-handedly push a clean file to high risk.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Final

from app.core.code_scanner import llm as _llm
from app.core.code_scanner.llm import LlmBaseUrlError, LlmConfig, _validate_base_url
from app.core.code_scanner.redaction import redact_text
from app.core.media_detector import MediaAnalysis, MediaFinding, MediaFormat, reclassify

# Anthropic vision accepts exactly these four media types. HEIC/AVIF are not
# decodable by the API; MP4/MOV would need a frame-extraction dependency we
# forbid. Everything not in this map is an honest skip.
_ANTHROPIC_VISION_MEDIA_TYPES: Final[dict[MediaFormat, str]] = {
    MediaFormat.PNG: "image/png",
    MediaFormat.JPEG: "image/jpeg",
    MediaFormat.GIF: "image/gif",
    MediaFormat.WEBP: "image/webp",
}

# Tighter cap than settings.media_max_bytes (64 MiB) so a vision pass never
# base64-ships a huge image (base64 inflates ~4/3, so 5 MiB raw -> ~6.7 MiB
# on the wire, plus image tokens scale with resolution). Oversize images are
# skipped, not downscaled — downscaling needs Pillow, which we avoid.
_VISION_MAX_BYTES: Final = 5 * 1024 * 1024

_VISION_SYSTEM_PROMPT = (
    "You are a forensic image analyst. You will receive ONE image — it may be a "
    "photograph, a digital render, a logo, or graphic art. Judge whether it was "
    "AI-generated, looking for tells across BOTH categories:\n"
    "  Photographic tells: malformed hands or fingers, garbled or nonsensical "
    "text and fine print, impossible reflections, inconsistent lighting or "
    "shadows, repeated or tiled textures, melted or fused objects, anatomically "
    "impossible geometry.\n"
    "  Art / render / graphic-design tells: unnaturally perfect symmetry or "
    "radial patterns, airbrushed 'synthwave' / 'concept-art' gradients, "
    "plasticky or uniform surface sheen, decorative-but-meaningless equations, "
    "glyphs, UI, gauges, or labels, hallucinated or inconsistent typography, and "
    "a generic glossy 'AI house style'.\n"
    "Be conservative: real photos have sensor noise and motion blur, and skilled "
    "human artists can produce clean, symmetric work — neither alone proves AI. "
    "Weigh the overall balance of evidence. 'likely_authentic' means a human-made "
    "or camera-captured image; 'likely_ai_generated' means a model produced it. "
    "Respond with JSON only, matching this schema exactly:\n"
    '{"verdict": "likely_ai_generated"|"likely_authentic"|"uncertain", '
    '"confidence": "low"|"medium"|"high", '
    '"ai_artifacts": ["<short artifact phrase>", ...], '
    '"rationale": "<one or two short sentences>"}\n'
    "ai_artifacts lists the specific visual tells you actually saw (empty if "
    "none). Do not output anything outside the JSON object."
)

_MEDIA_VISION_OUTPUT_SCHEMA: Final = {
    "type": "json_schema",
    "schema": {
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["likely_ai_generated", "likely_authentic", "uncertain"],
            },
            "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
            "ai_artifacts": {"type": "array", "items": {"type": "string"}},
            "rationale": {"type": "string"},
        },
        "required": ["verdict", "confidence", "ai_artifacts", "rationale"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True)
class MediaVisionJudgment:
    provider: str
    model: str
    # "likely_ai_generated" | "likely_authentic" | "uncertain" | "error"
    verdict: str
    confidence: str  # low | medium | high | error
    ai_artifacts: list[str] = field(default_factory=list)
    rationale: str = ""
    # "ok" | "skipped_provider" | "unsupported" | "oversize" | "error"
    status: str = "ok"


def _skip(config: LlmConfig, status: str, reason: str) -> MediaVisionJudgment:
    return MediaVisionJudgment(
        provider=config.provider,
        model=config.model,
        verdict="uncertain",
        confidence="error" if status == "error" else "low",
        ai_artifacts=[],
        rationale=reason[:240],
        status=status,
    )


def judge_media_image(config: LlmConfig, data: bytes, fmt: MediaFormat) -> MediaVisionJudgment:
    """Optional frontier vision pass. Anthropic + image only; never raises."""
    if config.provider != "anthropic":
        # OpenAI-compatible vision uses a different envelope we deliberately do
        # not support here. Honest skip, not an error.
        return _skip(config, "skipped_provider", f"vision is anthropic-only; got {config.provider}")
    media_type = _ANTHROPIC_VISION_MEDIA_TYPES.get(fmt)
    if media_type is None:
        return _skip(
            config,
            "unsupported",
            f"vision does not support {fmt.value}; supported: png/jpeg/gif/webp",
        )
    if len(data) > _VISION_MAX_BYTES:
        return _skip(
            config,
            "oversize",
            f"image is {len(data)} bytes; vision cap is {_VISION_MAX_BYTES}",
        )
    try:
        _validate_base_url(config.base_url)
    except LlmBaseUrlError as error:
        return _skip(config, "error", f"base_url rejected: {error}")

    b64 = base64.standard_b64encode(data).decode("ascii")
    content_blocks = [
        {"type": "image", "source": {"type": "base64", "media_type": media_type, "data": b64}},
        {"type": "text", "text": "Analyze this image for AI-generation artifacts."},
    ]
    response = _llm._call_anthropic_vision(
        config, _VISION_SYSTEM_PROMPT, content_blocks, output_schema=_MEDIA_VISION_OUTPUT_SCHEMA
    )
    parsed = _llm._extract_first_json(response)
    if not isinstance(parsed, dict):
        return _skip(config, "error", str(response))

    verdict = str(parsed.get("verdict", "")).lower()
    if verdict not in {"likely_ai_generated", "likely_authentic", "uncertain"}:
        verdict = "uncertain"
    confidence = str(parsed.get("confidence", "")).lower()
    if confidence not in {"low", "medium", "high"}:
        confidence = "low"
    raw_artifacts = parsed.get("ai_artifacts", [])
    artifacts: list[str] = []
    if isinstance(raw_artifacts, list):
        for item in raw_artifacts[:8]:
            safe, _ = redact_text(str(item)[:120])
            artifacts.append(safe)
    safe_rationale, _ = redact_text(str(parsed.get("rationale", ""))[:240])
    return MediaVisionJudgment(
        provider=config.provider,
        model=config.model,
        verdict=verdict,
        confidence=confidence,
        ai_artifacts=artifacts,
        rationale=safe_rationale,
        status="ok",
    )


# How much a vision verdict is allowed to move the score. We deliberately
# downgrade by one confidence notch so a single vision call cannot dominate
# the composite (see _confidence_weight in media_detector: high=0.32,
# medium=0.18, low=0.08): even a "high" vision verdict enters scoring as
# "medium" = 0.18, under the 0.30 moderate floor. Vision corroborates; it
# does not get to convict on its own.
_VISION_CONFIDENCE_DOWNGRADE: Final = {"high": "medium", "medium": "low", "low": "low"}


def fuse_vision_into_analysis(analysis: MediaAnalysis, judgment: MediaVisionJudgment) -> None:
    """Fold a vision verdict into the metadata analysis, then re-score.

    Only an affirmative ``likely_ai_generated`` verdict adds a finding —
    absence of artifacts is weak evidence and we refuse to oversell it by
    letting a ``likely_authentic`` verdict suppress a real metadata signal.
    The category stays honest: this is ``synthetic_generation`` evidence
    about the pixels, distinct from provenance metadata.
    """
    if judgment.status != "ok" or judgment.verdict != "likely_ai_generated":
        return
    fused_confidence = _VISION_CONFIDENCE_DOWNGRADE.get(judgment.confidence, "low")
    artifacts = ", ".join(judgment.ai_artifacts[:5]) or "unspecified visual artifacts"
    detail = (
        f"A frontier vision model ({judgment.model}) flagged pixel-level "
        f"AI-generation artifacts: {artifacts}. Vision can be wrong on stylized "
        f"or low-quality real photos; treat as corroborating, not conclusive. "
        f"Model note: {judgment.rationale}"
    )[:480]
    analysis.findings.append(
        MediaFinding(
            marker="Vision model: likely AI-generated (pixel artifacts)",
            confidence=fused_confidence,
            detail=detail,
            category="synthetic_generation",
        )
    )
    reclassify(analysis)
