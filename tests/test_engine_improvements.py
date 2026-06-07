"""Behavioral tests for the text, media, and web-ingest improvements."""

from __future__ import annotations

import zlib

from app.core.detector import SlopDetector
from app.core.media_detector import MediaFormat, analyze_media

# ---------- text engine ---------------------------------------------------


def test_detector_supports_profile_kwarg() -> None:
    text = (
        "In today's fast-paced world, this revolutionary seamless synergy is "
        "guaranteed and best-in-class. Marketers depend on it daily. "
    ) * 4
    general = SlopDetector().analyze(text, profile="general")
    marketing = SlopDetector().analyze(text, profile="marketing")
    # The marketing profile downweights vague language; the composite
    # score should land lower than the general profile on the same input.
    assert marketing.score <= general.score
    assert marketing.content_profile == "marketing"


def test_detector_specificity_v2_counts_ip_and_cve() -> None:
    text = (
        "Following CVE-2024-31497, the host 198.51.100.42 was rate-limited at port 443 "
        "between 14:05 and 14:10 UTC. Patch applied at 2024-02-09T14:05 in 12 seconds. "
        "Investigators reviewed example.com endpoints."
    )
    result = SlopDetector().analyze(text)
    assert result.profile.specificity_ratio > 0.30


def test_detector_sample_quality_for_short_text() -> None:
    result = SlopDetector().analyze("Tiny note.")
    assert result.sample_quality == "low"
    assert result.confidence < 0.6


def test_detector_signals_include_match_excerpts() -> None:
    result = SlopDetector().analyze(
        "This revolutionary product is guaranteed to deliver synergy."
    )
    target = next(
        (s for s in result.signals if s.name == "vague_language"), None
    )
    assert target is not None
    assert target.matches  # match excerpts populated


# ---------- media engine --------------------------------------------------


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    length = len(payload).to_bytes(4, "big")
    crc = zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    return length + chunk_type + payload + crc


def _png_with_chunks(chunks: list[bytes]) -> bytes:
    header = b"\x89PNG\r\n\x1a\n"
    ihdr_payload = (
        (1).to_bytes(4, "big")
        + (1).to_bytes(4, "big")
        + bytes([8, 2, 0, 0, 0])
    )
    return header + _png_chunk(b"IHDR", ihdr_payload) + b"".join(chunks) + _png_chunk(b"IEND", b"")


def test_png_ztxt_decompression_surfaces_generator_metadata() -> None:
    keyword = "parameters"
    payload_text = "Steps: 40, Sampler: Euler a, CFG: 7.0, Seed: 1234"
    compressed = zlib.compress(payload_text.encode("latin-1"))
    ztxt_payload = keyword.encode("latin-1") + b"\x00" + b"\x00" + compressed
    chunk = _png_chunk(b"zTXt", ztxt_payload)
    data = _png_with_chunks([chunk])
    result = analyze_media(data)
    assert result.format == MediaFormat.PNG
    assert any("Stable Diffusion" in name for name in result.tool_fingerprints)


def test_c2pa_alone_is_categorised_provenance_not_high_risk() -> None:
    # Build a JPEG with an APP1 XMP packet that mentions c2pa.org but no
    # synthetic-generation signals.
    import io

    out = io.BytesIO()
    out.write(b"\xff\xd8")
    identifier = b"http://ns.adobe.com/xap/1.0/\x00"
    packet = (
        b'<x:xmpmeta xmlns:x="adobe:ns:meta/">c2pa.org Content Credentials valid</x:xmpmeta>'
    )
    body = identifier + packet
    seg_len = len(body) + 2
    out.write(b"\xff\xe1" + seg_len.to_bytes(2, "big") + body)
    out.write(b"\xff\xda" + (4).to_bytes(2, "big") + b"\x00\x00")
    out.write(b"\x00")
    out.write(b"\xff\xd9")
    result = analyze_media(out.getvalue())
    assert result.has_c2pa_manifest
    c2pa_finding = next(
        f for f in result.findings if "C2PA" in f.marker and "manifest" in f.marker.lower()
    )
    assert c2pa_finding.category == "provenance"
    assert result.risk != "high"


def test_unsupported_media_format_sets_parse_status() -> None:
    result = analyze_media(b"NOT-A-RECOGNIZED-FORMAT" * 4)
    assert result.parse_status == "unsupported"
    assert result.parse_warning is not None


def test_webp_extracts_xmp_chunk() -> None:
    # Minimal WebP: RIFF + 4-byte size (little-endian) + WEBP + XMP chunk.
    xmp_payload = b"c2pa.org Content Credentials in WebP packet"
    xmp_chunk = b"XMP " + len(xmp_payload).to_bytes(4, "little") + xmp_payload
    # We don't strictly need a VP8 chunk for the parser, just enough header.
    body = b"WEBP" + b"VP8 " + b"\x00\x00\x00\x00" + xmp_chunk
    riff = b"RIFF" + len(body).to_bytes(4, "little") + body
    result = analyze_media(riff)
    assert result.format == MediaFormat.WEBP
    assert result.has_c2pa_manifest


def test_gif_extracts_comment_extension() -> None:
    # Smallest GIF with a comment block: GIF89a + LSD + zero GCT +
    # extension introducer + comment label + sub-blocks + trailer.
    header = b"GIF89a"
    lsd = b"\x01\x00\x01\x00\x00\x00\x00"
    comment_text = b"Made with ChatGPT image generator"
    comment_block = b"\x21\xFE" + bytes([len(comment_text)]) + comment_text + b"\x00"
    trailer = b"\x3b"
    data = header + lsd + comment_block + trailer
    result = analyze_media(data)
    assert result.format == MediaFormat.GIF
    assert "ChatGPT" in result.decoded_text_sample or "chatgpt" in result.decoded_text_sample.lower()


# ---------- web ingest (parser-only; no network) -------------------------


def test_html_parser_collects_meta_and_og() -> None:
    from app.core.web_ingest import ReadableHTMLParser

    parser = ReadableHTMLParser()
    html = (
        "<html><head>"
        "<title>The Page</title>"
        '<meta name="description" content="Definitive description here.">'
        '<meta property="og:title" content="OG Title">'
        '<meta property="og:description" content="OG description blob.">'
        "</head><body><p>Body paragraph.</p></body></html>"
    )
    parser.feed(html)
    assert parser.meta_description == "Definitive description here."
    assert parser.open_graph_title == "OG Title"
    assert parser.open_graph_description == "OG description blob."
    assert "Body paragraph." in parser.text
