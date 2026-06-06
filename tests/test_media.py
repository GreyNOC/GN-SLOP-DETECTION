"""Tests for the media slop detector.

Fixtures are synthesized from raw bytes so the test suite stays
dependency-free. Each helper builds the smallest possible file that the
parser will accept; we don't need a valid IDAT/SOS payload because the
analyzer is metadata-only.
"""

from __future__ import annotations

import io
import zlib

from fastapi.testclient import TestClient

from app.core.media_detector import MediaFormat, MediaKind, analyze_media, detect_format
from app.main import app

client = TestClient(app)


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    length = len(payload).to_bytes(4, "big")
    crc = zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    return length + chunk_type + payload + crc


def synth_png(text_chunks: list[tuple[str, str]] | None = None, trailing: bytes = b"") -> bytes:
    """Build a synthetic PNG with the requested tEXt chunks and optional trailing bytes."""
    out = io.BytesIO()
    out.write(PNG_SIGNATURE)
    # Minimal IHDR: 1x1, bit depth 8, color type 2 (RGB)
    ihdr_payload = (
        (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + bytes([8, 2, 0, 0, 0])
    )
    out.write(_png_chunk(b"IHDR", ihdr_payload))
    for keyword, text in text_chunks or []:
        payload = keyword.encode("latin-1") + b"\x00" + text.encode("latin-1")
        out.write(_png_chunk(b"tEXt", payload))
    out.write(_png_chunk(b"IEND", b""))
    out.write(trailing)
    return out.getvalue()


def synth_jpeg_with_jumbf(payload: bytes = b"c2pa.org claim_generator: Adobe Firefly") -> bytes:
    """Build a minimal JPEG with an APP11 JUMBF segment."""
    out = io.BytesIO()
    out.write(b"\xff\xd8")  # SOI
    identifier = b"JP\x00"
    body = identifier + payload
    seg_len = len(body) + 2
    out.write(b"\xff\xeb" + seg_len.to_bytes(2, "big") + body)
    # Trivial SOS + minimal scan so the JPEG terminates cleanly.
    sos_body = b"\x00\x00"  # placeholder bytes for the scan header
    sos_len = len(sos_body) + 2
    out.write(b"\xff\xda" + sos_len.to_bytes(2, "big") + sos_body)
    out.write(b"\x00")
    out.write(b"\xff\xd9")  # EOI
    return out.getvalue()


def synth_jpeg_with_xmp(packet: str) -> bytes:
    """Build a JPEG carrying an APP1 XMP packet."""
    out = io.BytesIO()
    out.write(b"\xff\xd8")
    identifier = b"http://ns.adobe.com/xap/1.0/\x00"
    body = identifier + packet.encode("utf-8")
    seg_len = len(body) + 2
    out.write(b"\xff\xe1" + seg_len.to_bytes(2, "big") + body)
    sos_body = b"\x00\x00"
    sos_len = len(sos_body) + 2
    out.write(b"\xff\xda" + sos_len.to_bytes(2, "big") + sos_body)
    out.write(b"\x00")
    out.write(b"\xff\xd9")
    return out.getvalue()


def _iso_box(box_type: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + box_type + payload


def synth_mp4_with_c2pa_uuid() -> bytes:
    """Minimal MP4 with an ftyp box and a top-level uuid box carrying the C2PA UUID."""
    ftyp = _iso_box(b"ftyp", b"isom" + (512).to_bytes(4, "big") + b"isomavc1mp42")
    c2pa_uuid = bytes.fromhex("d8fec7104c164e808a2a6ce2ed758d5b")
    uuid_body = c2pa_uuid + b"content credentials by c2pa.org claim_generator Runway gen-3"
    uuid_box = _iso_box(b"uuid", uuid_body)
    return ftyp + uuid_box


# ---------- unit tests ----------------------------------------------------


def test_detect_format_recognises_png_jpeg_mp4_webp():
    assert detect_format(synth_png()) == MediaFormat.PNG
    assert detect_format(synth_jpeg_with_jumbf()) == MediaFormat.JPEG
    assert detect_format(synth_mp4_with_c2pa_uuid()) == MediaFormat.MP4
    # WebP: minimal RIFF header
    webp = b"RIFF" + (4).to_bytes(4, "little") + b"WEBP"
    assert detect_format(webp) == MediaFormat.WEBP
    assert detect_format(b"") == MediaFormat.UNKNOWN
    assert detect_format(b"x" * 4) == MediaFormat.UNKNOWN


def test_png_text_chunk_surfaces_stable_diffusion_fingerprint():
    data = synth_png(
        text_chunks=[
            ("parameters", "Steps: 25, Sampler: Euler a, CFG scale: 7, Seed: 42"),
        ]
    )
    analysis = analyze_media(data)
    assert analysis.format == MediaFormat.PNG
    assert "parameters" in analysis.generative_metadata_keys
    assert any("Stable Diffusion" in name for name in analysis.tool_fingerprints)
    assert analysis.score > 0.0


def test_png_trailing_bytes_are_flagged():
    data = synth_png(text_chunks=[("Software", "ComfyUI 0.3")], trailing=b"X" * 2048)
    analysis = analyze_media(data)
    assert analysis.trailing_bytes >= 2048
    assert any("trailing" in finding.marker.lower() for finding in analysis.findings)


def test_jpeg_jumbf_segment_marks_c2pa():
    data = synth_jpeg_with_jumbf()
    analysis = analyze_media(data)
    assert analysis.format == MediaFormat.JPEG
    assert analysis.has_c2pa_manifest
    assert analysis.has_jumbf_box
    assert any("C2PA" in finding.marker for finding in analysis.findings)
    assert analysis.score >= 0.30


def test_jpeg_xmp_synthid_is_detected():
    packet = '<x:xmpmeta xmlns:x="adobe:ns:meta/">SynthID watermark v1</x:xmpmeta>'
    data = synth_jpeg_with_xmp(packet)
    analysis = analyze_media(data)
    assert analysis.has_xmp_packet
    assert analysis.has_synthid_marker
    assert any("SynthID" in finding.marker for finding in analysis.findings)


def test_mp4_uuid_box_marks_c2pa_and_fingerprints_runway():
    data = synth_mp4_with_c2pa_uuid()
    analysis = analyze_media(data)
    assert analysis.format == MediaFormat.MP4
    assert analysis.kind == MediaKind.VIDEO
    assert analysis.has_c2pa_manifest
    assert any("Runway" in name for name in analysis.tool_fingerprints)


def synth_sora_shaped_mov() -> bytes:
    """A QuickTime .mov with the canonical Sora export shape:

    - ftyp brand 'qt  '
    - one video track (hdlr handler_type 'vide'), no audio track
    - udta with a single \xa9swr (writer) atom whose payload is 'Lavf<x.y.z>'
    - no Apple capture metadata atoms
    """
    # ftyp: 'qt  ' major brand, no compatible brands
    ftyp_payload = b"qt  " + (0).to_bytes(4, "big") + b"qt  "
    ftyp = _iso_box(b"ftyp", ftyp_payload)

    # hdlr inside mdia: handler_type 'vide'
    hdlr_payload = b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"vide" + (b"\x00" * 12) + b"VideoHandler\x00"
    hdlr = _iso_box(b"hdlr", hdlr_payload)
    mdia = _iso_box(b"mdia", hdlr)
    trak = _iso_box(b"trak", mdia)

    # udta with \xa9swr writer atom — locale prefix then 'Lavf61.7.100'.
    swr_inner = b"\x00\x0c\x55\xc4" + b"Lavf61.7.100"
    swr = _iso_box(b"\xa9swr", swr_inner)
    udta = _iso_box(b"udta", swr)

    moov = _iso_box(b"moov", trak + udta)
    mdat = _iso_box(b"mdat", b"\x00" * 128)
    return ftyp + moov + mdat


def test_sora_shaped_mov_is_flagged_high_risk():
    """The exact shape of a ChatGPT/Sora .mov export should land at high risk."""
    data = synth_sora_shaped_mov()
    analysis = analyze_media(data)
    assert analysis.format == MediaFormat.MOV
    assert analysis.kind == MediaKind.VIDEO
    assert analysis.ftyp_brand == "qt"
    assert analysis.video_track_count == 1
    assert analysis.audio_track_count == 0
    assert any("FFmpeg" in name for name in analysis.tool_fingerprints)
    assert any("AI-video pipeline shape" in finding.marker for finding in analysis.findings)
    assert any(
        "no audio track" in finding.marker.lower() for finding in analysis.findings
    )
    assert analysis.score >= 0.60
    assert analysis.risk == "high"


def test_camera_style_mov_with_lavf_does_not_escalate_to_high():
    """A re-encoded but otherwise camera-shaped .mov should NOT trigger the
    composite AI-video-pipeline finding."""
    ftyp_payload = b"qt  " + (0).to_bytes(4, "big") + b"qt  "
    ftyp = _iso_box(b"ftyp", ftyp_payload)

    # Two tracks: video and audio.
    vide_hdlr = _iso_box(
        b"hdlr",
        b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"vide" + (b"\x00" * 12) + b"VideoHandler\x00",
    )
    soun_hdlr = _iso_box(
        b"hdlr",
        b"\x00\x00\x00\x00" + b"\x00\x00\x00\x00" + b"soun" + (b"\x00" * 12) + b"SoundHandler\x00",
    )
    vide_trak = _iso_box(b"trak", _iso_box(b"mdia", vide_hdlr))
    soun_trak = _iso_box(b"trak", _iso_box(b"mdia", soun_hdlr))

    # udta with both writer atom AND Apple-style ©day / com.apple.* metadata.
    swr_inner = b"\x00\x0c\x55\xc4" + b"Lavf61.7.100"
    swr = _iso_box(b"\xa9swr", swr_inner)
    apple_meta = _iso_box(b"meta", b"com.apple.quicktime.make: Apple\x00")
    udta = _iso_box(b"udta", swr + apple_meta)

    moov = _iso_box(b"moov", vide_trak + soun_trak + udta)
    mdat = _iso_box(b"mdat", b"\x00" * 128)
    data = ftyp + moov + mdat

    analysis = analyze_media(data)
    assert analysis.video_track_count == 1
    assert analysis.audio_track_count == 1
    # FFmpeg fingerprint may still fire (it's a real signal), but the
    # high-confidence composite finding must NOT fire because capture
    # metadata is present and audio track exists.
    assert not any(
        "AI-video pipeline shape" in finding.marker for finding in analysis.findings
    )
    assert analysis.risk != "high"


def test_analyze_media_handles_empty_and_unknown_input():
    empty = analyze_media(b"")
    assert empty.format == MediaFormat.UNKNOWN
    assert empty.score == 0.0
    unknown = analyze_media(b"not actually a media file " * 4)
    assert unknown.format == MediaFormat.UNKNOWN


# ---------- API endpoint tests -------------------------------------------


def test_analyze_media_endpoint_returns_high_risk_for_c2pa_jpeg():
    data = synth_jpeg_with_jumbf()
    response = client.post(
        "/api/v1/analyze-media",
        files={"file": ("ai.jpg", data, "image/jpeg")},
        data={"source": "case-1"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["format"] == "jpeg"
    assert body["has_c2pa_manifest"] is True
    assert body["risk"] in {"moderate", "high"}
    assert body["source"] == "case-1"


def test_analyze_media_endpoint_rejects_empty_upload():
    response = client.post(
        "/api/v1/analyze-media",
        files={"file": ("empty.png", b"", "image/png")},
    )
    assert response.status_code == 422


def test_analyze_media_endpoint_enforces_size_cap(monkeypatch):
    from app.core import settings as settings_module

    settings_module.get_settings.cache_clear()
    monkeypatch.setenv("MEDIA_MAX_BYTES", "1024")
    settings_module.get_settings.cache_clear()
    try:
        # 2 KB of bytes — clearly over the 1 KB cap.
        oversized = synth_png(text_chunks=[("k", "v" * 4096)])
        response = client.post(
            "/api/v1/analyze-media",
            files={"file": ("big.png", oversized, "image/png")},
        )
        assert response.status_code == 413
    finally:
        settings_module.get_settings.cache_clear()
