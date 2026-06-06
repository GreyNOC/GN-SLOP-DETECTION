"""Binary media slop detector.

Ported from the GreyNOC Aegis Android engine
(src/media/binaryImageAnalysis.ts) and extended with an ISO Base Media File
Format (MP4/MOV/HEIC) box walker for video provenance scanning.

This module is pure-bytes: it does not depend on Pillow, ffmpeg, or any
model. It reads format-specific structures that EXIF dictionaries miss:

  * PNG chunks (tEXt / iTXt / zTXt) — Stable Diffusion WebUI, ComfyUI,
    InvokeAI, and SDXL write generation parameters here.
  * JPEG segments:
      APP1   EXIF + Adobe XMP packet (XMP often carries C2PA refs)
      APP11  JUMBF — the container format C2PA Content Credentials live in
      APP13  Photoshop IRB — carries IPTC + edit history
      COM    JPEG comment — some generators stash parameters here
  * ISO Base Media File Format boxes (MP4/MOV/HEIC/AVIF):
      ftyp brand sniff, walk into moov → udta → meta, look for the C2PA
      uuid box, harvest printable user-data strings for fingerprint match.
  * Trailing bytes past the format terminator (steganographic appends).

Everything is conservative: failures (truncated files, unknown formats)
return an empty analysis rather than raising, so the caller can treat
"no findings" as the default state.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Final


class MediaFormat(str, Enum):
    PNG = "png"
    JPEG = "jpeg"
    WEBP = "webp"
    GIF = "gif"
    HEIC = "heic"
    AVIF = "avif"
    MP4 = "mp4"
    MOV = "mov"
    UNKNOWN = "unknown"


class MediaKind(str, Enum):
    IMAGE = "image"
    VIDEO = "video"
    UNKNOWN = "unknown"


_KIND_BY_FORMAT: Final[dict[MediaFormat, MediaKind]] = {
    MediaFormat.PNG: MediaKind.IMAGE,
    MediaFormat.JPEG: MediaKind.IMAGE,
    MediaFormat.WEBP: MediaKind.IMAGE,
    MediaFormat.GIF: MediaKind.IMAGE,
    MediaFormat.HEIC: MediaKind.IMAGE,
    MediaFormat.AVIF: MediaKind.IMAGE,
    MediaFormat.MP4: MediaKind.VIDEO,
    MediaFormat.MOV: MediaKind.VIDEO,
    MediaFormat.UNKNOWN: MediaKind.UNKNOWN,
}


@dataclass(frozen=True)
class MediaFinding:
    marker: str
    confidence: str  # "low" | "medium" | "high"
    detail: str | None = None


@dataclass
class MediaAnalysis:
    format: MediaFormat
    kind: MediaKind
    byte_size: int
    generative_metadata_keys: list[str] = field(default_factory=list)
    tool_fingerprints: list[str] = field(default_factory=list)
    has_c2pa_manifest: bool = False
    has_jumbf_box: bool = False
    has_xmp_packet: bool = False
    has_synthid_marker: bool = False
    trailing_bytes: int = 0
    findings: list[MediaFinding] = field(default_factory=list)
    decoded_text_sample: str = ""
    score: float = 0.0
    risk: str = "low"
    recommendation: str = ""
    algorithm: str = "media-picture-v1"


_MAX_DECODED_TEXT: Final = 8 * 1024
_PNG_SIGNATURE: Final = b"\x89PNG\r\n\x1a\n"
_PNG_SIGNATURE_LEN: Final = len(_PNG_SIGNATURE)

# The C2PA JUMBF UUID for top-level uuid boxes in ISO BMFF.
# 0xD8FEC710_4C16_4E80_8A2A_6CE2ED758D5B
_C2PA_UUID: Final = bytes.fromhex("d8fec7104c164e808a2a6ce2ed758d5b")

# Box types we walk into rather than treat as leaves. Adding a container
# here lets us harvest text/UUIDs nested deeper without an explosion of
# parsing code.
_ISOBMFF_CONTAINER_BOXES: Final = frozenset(
    {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"udta", b"meta", b"ilst", b"edts"}
)

# Bundled-in list of generators / tools we recognize in decoded binary
# text. Kept tight: the goal is to enrich `tool_fingerprints` so the report
# can say "Stable Diffusion WebUI" instead of generically "AI markers
# found".  The patterns mirror Aegis BINARY_TOOL_PATTERNS plus video-side
# generator names that show up in MP4 metadata.
_TOOL_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    ("Stable Diffusion WebUI (A1111)", re.compile(r"Steps:\s*\d+,\s*Sampler|sd[-_]?metadata", re.IGNORECASE)),
    ("ComfyUI", re.compile(r"ComfyUI|\"workflow\"\s*:", re.IGNORECASE)),
    ("InvokeAI", re.compile(r"invokeai_metadata|invoke[-_]?ai", re.IGNORECASE)),
    ("DALL-E / OpenAI", re.compile(r"dall[\-·]?e|openai", re.IGNORECASE)),
    ("Midjourney", re.compile(r"midjourney|--ar\s+\d", re.IGNORECASE)),
    ("Adobe Firefly", re.compile(r"firefly|adobe\s*firefly", re.IGNORECASE)),
    ("Google SynthID", re.compile(r"synthid|generative.?ai.?(provenance|watermark)", re.IGNORECASE)),
    (
        "C2PA Content Credentials",
        re.compile(r"c2pa\.org|c2pa\.claim_generator|content\s*credentials|contentauth", re.IGNORECASE),
    ),
    ("Adobe Photoshop", re.compile(r"photoshop|adobe\s*xmp\s*core|xmp:CreatorTool", re.IGNORECASE)),
    ("Runway", re.compile(r"runwayml|runway[\s\-_]*gen[\s\-_]*\d", re.IGNORECASE)),
    ("Pika", re.compile(r"pika[-_]?labs|pika[-_]?\d", re.IGNORECASE)),
    ("Sora / OpenAI", re.compile(r"sora\s*(by\s*openai|video)?", re.IGNORECASE)),
    ("Luma Dream Machine", re.compile(r"luma\s*ai|dream\s*machine", re.IGNORECASE)),
]


def _empty(format_: MediaFormat = MediaFormat.UNKNOWN, byte_size: int = 0) -> MediaAnalysis:
    return MediaAnalysis(
        format=format_,
        kind=_KIND_BY_FORMAT.get(format_, MediaKind.UNKNOWN),
        byte_size=byte_size,
    )


def detect_format(data: bytes) -> MediaFormat:
    """Sniff format from magic bytes. Honest about user-renamed files."""
    if len(data) < 12:
        return MediaFormat.UNKNOWN
    if data.startswith(_PNG_SIGNATURE):
        return MediaFormat.PNG
    if data[0] == 0xFF and data[1] == 0xD8 and data[2] == 0xFF:
        return MediaFormat.JPEG
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return MediaFormat.WEBP
    if data[:3] == b"GIF":
        return MediaFormat.GIF
    if data[4:8] == b"ftyp":
        brand = data[8:12]
        if brand in (b"heic", b"heix", b"mif1"):
            return MediaFormat.HEIC
        if brand == b"avif":
            return MediaFormat.AVIF
        if brand == b"qt  ":
            return MediaFormat.MOV
        # Anything else that's an ISO Base Media File ftyp brand we treat as MP4.
        return MediaFormat.MP4
    return MediaFormat.UNKNOWN


def _decode_latin1(data: bytes, start: int, end: int) -> str:
    safe_end = min(end, len(data))
    if start >= safe_end:
        return ""
    return data[start:safe_end].decode("latin-1", errors="replace")


def _decode_ascii_printable(data: bytes, start: int, end: int) -> str:
    safe_end = min(end, len(data))
    out: list[str] = []
    for i in range(start, safe_end):
        b = data[i]
        if 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def _parse_png(data: bytes) -> MediaAnalysis:
    analysis = _empty(MediaFormat.PNG, len(data))
    offset = _PNG_SIGNATURE_LEN
    decoded_parts: list[str] = []
    end_seen = False
    last_chunk_end = offset

    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset : offset + 4], "big")
        if length < 0 or offset + 8 + length + 4 > len(data):
            break
        chunk_type = data[offset + 4 : offset + 8].decode("ascii", errors="replace")
        data_start = offset + 8
        data_end = data_start + length

        if chunk_type in ("tEXt", "iTXt", "zTXt"):
            kw_end = data_start
            while kw_end < data_end and data[kw_end] != 0:
                kw_end += 1
            keyword = _decode_latin1(data, data_start, kw_end)
            if keyword:
                analysis.generative_metadata_keys.append(keyword)

            if chunk_type == "tEXt":
                text = _decode_latin1(data, kw_end + 1, data_end)
                decoded_parts.append(f"{keyword}={text}")
            elif chunk_type == "iTXt":
                # iTXt layout: keyword\0 compFlag compMethod langTag\0 transKw\0 text
                p = kw_end + 3
                while p < data_end and data[p] != 0:
                    p += 1
                p += 1
                while p < data_end and data[p] != 0:
                    p += 1
                p += 1
                if p < data_end:
                    decoded_parts.append(f"{keyword}={_decode_latin1(data, p, data_end)}")
            else:
                # zTXt — keyword visible in cleartext; payload is zlib-compressed.
                decoded_parts.append(f"{keyword}=<compressed>")
        elif chunk_type == "iCCP":
            analysis.generative_metadata_keys.append("iCCP")
        elif chunk_type == "eXIf":
            analysis.generative_metadata_keys.append("eXIf")
        elif chunk_type == "IEND":
            end_seen = True
            last_chunk_end = data_end + 4
            offset = last_chunk_end
            break

        offset = data_end + 4
        last_chunk_end = offset

    if end_seen and len(data) > last_chunk_end:
        analysis.trailing_bytes = len(data) - last_chunk_end
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def _parse_jpeg(data: bytes) -> MediaAnalysis:
    analysis = _empty(MediaFormat.JPEG, len(data))
    offset = 2  # skip SOI (FF D8)
    decoded_parts: list[str] = []
    sos_seen = False

    while offset + 4 <= len(data):
        if data[offset] != 0xFF:
            break
        marker = data[offset + 1]
        if marker == 0xD9:  # EOI
            break
        if marker == 0xDA:  # SOS — entropy-coded scan begins
            sos_seen = True
            p = offset + 2
            while p + 1 < len(data):
                if data[p] == 0xFF and data[p + 1] != 0x00:
                    break
                p += 1
            offset = p
            continue

        seg_len = (data[offset + 2] << 8) | data[offset + 3]
        if seg_len < 2 or offset + 2 + seg_len > len(data):
            break
        data_start = offset + 4
        data_end = offset + 2 + seg_len

        if 0xE0 <= marker <= 0xEF:
            id_end = data_start
            while id_end < data_end and data[id_end] != 0:
                id_end += 1
            identifier = _decode_latin1(data, data_start, id_end)
            payload_start = id_end + 1
            payload = _decode_latin1(data, payload_start, data_end)

            if marker == 0xE1:
                if identifier == "Exif":
                    analysis.generative_metadata_keys.append("EXIF (APP1)")
                elif identifier.startswith("http://ns.adobe.com/xap/") or identifier.startswith(
                    "http://ns.adobe.com/xmp/"
                ):
                    analysis.has_xmp_packet = True
                    analysis.generative_metadata_keys.append("XMP packet")
                    decoded_parts.append(payload)
                    if re.search(r"c2pa|content\s*credentials|contentauth", payload, re.IGNORECASE):
                        analysis.has_c2pa_manifest = True
                    if re.search(r"synthid", payload, re.IGNORECASE):
                        analysis.has_synthid_marker = True
            elif marker == 0xEB:
                if identifier == "JP":
                    analysis.has_jumbf_box = True
                    analysis.has_c2pa_manifest = True
                    analysis.generative_metadata_keys.append("APP11 JUMBF (C2PA)")
                    decoded_parts.append(
                        _decode_latin1(data, payload_start, min(data_end, payload_start + 2048))
                    )
            elif marker == 0xED:
                if identifier == "Photoshop 3.0":
                    analysis.generative_metadata_keys.append("APP13 Photoshop IRB")
                    analysis.tool_fingerprints.append("Adobe Photoshop")
                    decoded_parts.append(
                        _decode_latin1(data, payload_start, min(data_end, payload_start + 2048))
                    )
            elif marker == 0xE2:
                analysis.generative_metadata_keys.append("APP2")
        elif marker == 0xFE:
            comment = _decode_latin1(data, data_start, data_end)
            analysis.generative_metadata_keys.append("JPEG comment")
            decoded_parts.append(comment)

        offset = data_end

    if sos_seen:
        eoi = data.rfind(b"\xff\xd9")
        if 0 <= eoi < len(data) - 2:
            analysis.trailing_bytes = len(data) - (eoi + 2)
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def _iter_isobmff_boxes(
    data: bytes, start: int, end: int, depth: int = 0
):
    """Yield (box_type, payload_start, payload_end, depth) for each box.

    Honors size==1 large boxes (8-byte 64-bit size) and stops cleanly on
    size==0 (extends to end). Depth is reported so callers can decide
    whether to recurse into nested containers.
    """
    if depth > 8:
        return  # paranoia: avoid pathological recursion on malformed files
    offset = start
    safe_end = min(end, len(data))
    while offset + 8 <= safe_end:
        box_size = int.from_bytes(data[offset : offset + 4], "big")
        box_type = data[offset + 4 : offset + 8]
        header_len = 8
        if box_size == 1:
            if offset + 16 > safe_end:
                return
            box_size = int.from_bytes(data[offset + 8 : offset + 16], "big")
            header_len = 16
        if box_size == 0:
            box_size = safe_end - offset
        if box_size < header_len or offset + box_size > safe_end:
            return
        yield box_type, offset + header_len, offset + box_size, depth
        if box_type in _ISOBMFF_CONTAINER_BOXES:
            yield from _iter_isobmff_boxes(data, offset + header_len, offset + box_size, depth + 1)
        offset += box_size


def _parse_isobmff(data: bytes, format_: MediaFormat) -> MediaAnalysis:
    analysis = _empty(format_, len(data))
    decoded_parts: list[str] = []
    last_box_end = 0

    for box_type, payload_start, payload_end, depth in _iter_isobmff_boxes(data, 0, len(data)):
        last_box_end = max(last_box_end, payload_end)

        if box_type == b"ftyp":
            brand = _decode_latin1(data, payload_start, min(payload_start + 4, payload_end))
            analysis.generative_metadata_keys.append(f"ftyp:{brand.strip()}")
        elif box_type == b"uuid":
            uuid = data[payload_start : payload_start + 16] if payload_end - payload_start >= 16 else b""
            if uuid == _C2PA_UUID:
                analysis.has_c2pa_manifest = True
                analysis.has_jumbf_box = True
                analysis.generative_metadata_keys.append("uuid box C2PA")
                decoded_parts.append(
                    _decode_latin1(data, payload_start + 16, min(payload_end, payload_start + 16 + 2048))
                )
            else:
                analysis.generative_metadata_keys.append("uuid box")
        elif box_type in (
            b"data",
            b"\xa9too",
            b"\xa9nam",
            b"\xa9cmt",
            b"\xa9ART",
            b"\xa9day",
            b"\xa9gen",
            b"\xa9swr",
        ):
            # iTunes-style metadata atoms commonly carry tool names.
            text = _decode_latin1(data, payload_start, min(payload_end, payload_start + 1024))
            decoded_parts.append(text)
        elif box_type == b"hdlr":
            decoded_parts.append(_decode_latin1(data, payload_start, min(payload_end, payload_start + 256)))
        # Only descend into containers OR harvest top-level user-data text.
        # Walking into compressed media boxes (mdat etc.) would just produce
        # noise, so we deliberately skip them.

        if depth == 0 and box_type == b"mdat":
            # mdat carries the compressed media payload; don't peek at it.
            continue

    if last_box_end and last_box_end < len(data):
        analysis.trailing_bytes = len(data) - last_box_end
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def _enrich_with_fingerprints(analysis: MediaAnalysis) -> None:
    text = analysis.decoded_text_sample
    if text:
        seen = set(analysis.tool_fingerprints)
        for name, pattern in _TOOL_PATTERNS:
            if name not in seen and pattern.search(text):
                analysis.tool_fingerprints.append(name)
                seen.add(name)

    if analysis.has_c2pa_manifest:
        analysis.findings.append(
            MediaFinding(
                marker="C2PA Content Credentials manifest present",
                confidence="high",
                detail="A JUMBF box or C2PA reference was detected in the file bytes.",
            )
        )
    if analysis.has_synthid_marker:
        analysis.findings.append(
            MediaFinding(
                marker="Google SynthID provenance marker",
                confidence="high",
                detail="SynthID metadata was detected in the XMP packet.",
            )
        )
    if analysis.has_xmp_packet and not analysis.has_c2pa_manifest:
        analysis.findings.append(
            MediaFinding(
                marker="Adobe XMP packet present",
                confidence="medium",
                detail="XMP often carries provenance, tool, and history metadata.",
            )
        )
    if analysis.trailing_bytes > 1024:
        analysis.findings.append(
            MediaFinding(
                marker=f"{analysis.trailing_bytes} bytes of trailing data after media end",
                confidence="medium",
                detail=(
                    "Large unaccounted trailers can indicate steganographic payloads "
                    "or smuggled archives appended to the file."
                ),
            )
        )
    for tool in analysis.tool_fingerprints:
        analysis.findings.append(
            MediaFinding(marker=f"Binary fingerprint: {tool}", confidence="high")
        )


def _confidence_weight(confidence: str) -> float:
    return {"high": 0.32, "medium": 0.18, "low": 0.08}.get(confidence, 0.0)


def _score_and_classify(analysis: MediaAnalysis) -> None:
    score = 0.0
    for finding in analysis.findings:
        score += _confidence_weight(finding.confidence)
    # Format-specific gentle baselines: a PNG with no metadata at all is
    # suspicious-light because real cameras almost never produce them; a
    # JPEG with no APP segments is unusual too. We keep these small so a
    # clean photo file doesn't get flagged.
    if analysis.format == MediaFormat.PNG and not analysis.generative_metadata_keys:
        score += 0.04
    if analysis.format in (MediaFormat.MP4, MediaFormat.MOV) and not analysis.tool_fingerprints:
        # Most camera-shot MP4s have at least a writer string in udta/meta.
        # If we found none, the file may have been re-encoded by a tool
        # that strips identifiers — common in AI video pipelines.
        if analysis.byte_size > 0:
            score += 0.04
    score = round(min(score, 1.0), 3)
    analysis.score = score
    if score >= 0.60:
        analysis.risk = "high"
        analysis.recommendation = (
            "Strong provenance markers detected. Treat the file as machine-generated or "
            "machine-edited unless an independent source confirms otherwise."
        )
    elif score >= 0.30:
        analysis.risk = "moderate"
        analysis.recommendation = (
            "Provenance markers detected. Review the file's origin before re-using it as evidence."
        )
    else:
        analysis.risk = "low"
        analysis.recommendation = "No strong AI / provenance markers detected."


def analyze_media(data: bytes) -> MediaAnalysis:
    """Parse `data` and return a MediaAnalysis. Never raises on malformed input."""
    if not data:
        return _empty()
    try:
        fmt = detect_format(data)
        if fmt == MediaFormat.PNG:
            analysis = _parse_png(data)
        elif fmt == MediaFormat.JPEG:
            analysis = _parse_jpeg(data)
        elif fmt in (MediaFormat.MP4, MediaFormat.MOV, MediaFormat.HEIC, MediaFormat.AVIF):
            analysis = _parse_isobmff(data, fmt)
        else:
            analysis = _empty(fmt, len(data))
        _enrich_with_fingerprints(analysis)
        _score_and_classify(analysis)
        return analysis
    except Exception:
        # Honest failure: the caller treats absence of findings as "no
        # signal". Raising would hide that we lost information.
        analysis = _empty(MediaFormat.UNKNOWN, len(data))
        _score_and_classify(analysis)
        return analysis
