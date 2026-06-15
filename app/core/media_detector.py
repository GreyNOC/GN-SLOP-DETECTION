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
import zlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

# Hard cap on the zlib-decompressed bytes we accept from a single PNG
# zTXt chunk. Without it a tiny compressed blob could expand to GiB.
_ZTXT_MAX_DECOMPRESSED: Final = 64 * 1024


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
    # One of: "provenance" | "synthetic_generation" | "editing_transcode"
    # | "tamper_smuggling" | "structural". Used by the dashboard to
    # group findings by what they actually mean — C2PA Content
    # Credentials, for example, is a *provenance* finding rather than
    # a synthetic-generation one, and the score should reflect that.
    category: str = "structural"


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
    algorithm: str = "media-picture-v3"
    # Structural ISO BMFF / container details surfaced for video heuristics.
    ftyp_brand: str = ""
    compatible_brands: list[str] = field(default_factory=list)
    video_track_count: int = 0
    audio_track_count: int = 0
    # Parse status surfaced so the analyst knows whether the result is
    # a complete picture or a best-effort one.
    parse_status: str = "ok"  # "ok" | "unsupported" | "malformed" | "parser_error"
    parse_warning: str | None = None


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
# text. Each entry carries a confidence so a soft signal (e.g. a generic
# software encoder name) doesn't get the same weight as a hard provenance
# marker (e.g. C2PA or SynthID).
#
# Patterns mirror Aegis BINARY_TOOL_PATTERNS plus video-pipeline tells.
# Video-specific notes:
#   - libavformat ("Lavf" writer string) is by far the most common
#     signature of an AI video export, because Sora, Runway, Pika, Luma,
#     and most local pipelines run their output through FFmpeg. It is
#     also legitimately used by hand-edited video, so we keep its
#     standalone confidence at "medium" — a composite finding below
#     escalates when it co-occurs with other AI-pipeline tells.
#   - x264/x265 are pure software encoders; phones and cameras use
#     hardware encoders, so their presence alone is a low-confidence
#     hint that the file went through a post-process re-encode.
_TOOL_PATTERNS: Final[list[tuple[str, re.Pattern[str], str]]] = [
    ("Stable Diffusion WebUI (A1111)", re.compile(r"Steps:\s*\d+,\s*Sampler|sd[-_]?metadata", re.IGNORECASE), "high"),
    ("ComfyUI", re.compile(r"ComfyUI|\"workflow\"\s*:", re.IGNORECASE), "high"),
    ("InvokeAI", re.compile(r"invokeai_metadata|invoke[-_]?ai", re.IGNORECASE), "high"),
    ("DALL-E / OpenAI", re.compile(r"dall[\-·]?e|\bopenai\b", re.IGNORECASE), "high"),
    ("Midjourney", re.compile(r"midjourney|--ar\s+\d", re.IGNORECASE), "high"),
    ("Adobe Firefly", re.compile(r"firefly|adobe\s*firefly", re.IGNORECASE), "high"),
    ("Google SynthID", re.compile(r"synthid|generative.?ai.?(provenance|watermark)", re.IGNORECASE), "high"),
    (
        "C2PA Content Credentials",
        re.compile(r"c2pa\.org|c2pa\.claim_generator|content\s*credentials|contentauth", re.IGNORECASE),
        "high",
    ),
    ("Adobe Photoshop", re.compile(r"photoshop|adobe\s*xmp\s*core|xmp:CreatorTool", re.IGNORECASE), "medium"),
    ("Runway", re.compile(r"runwayml|runway[\s\-_]*gen[\s\-_]*\d", re.IGNORECASE), "high"),
    ("Pika", re.compile(r"pika[\s\-_]*labs|pika[\s\-_]*\d", re.IGNORECASE), "high"),
    (
        "OpenAI Sora / ChatGPT (literal)",
        re.compile(
            r"\bsora\s*(?:by\s*openai|video)?\b"
            r"|chatgpt[^a-z]*(?:video|image|media|generation)"
            r"|gpt[\-_]?image"
            r"|gpt[\-_]?vision"
            r"|made\s+(?:with|by)\s+chatgpt"
            r"|generated\s+(?:with|by)\s+chatgpt",
            re.IGNORECASE,
        ),
        "high",
    ),
    ("Luma Dream Machine", re.compile(r"luma\s*ai|dream\s*machine", re.IGNORECASE), "high"),
    (
        "FFmpeg / libavformat pipeline",
        # No \b on Lavf/Lavc/Lavu/Lavd: these strings sit immediately after
        # binary length/locale bytes in QuickTime atoms (e.g., "\xc4Lavf"),
        # and the preceding byte often decodes as a Latin extended letter
        # which defeats the \w boundary. The literals are distinctive
        # enough that prefix-anchored is unnecessary.
        re.compile(
            r"Lavf\d|Lavc\d|Lavu\d|Lavd\d"
            r"|libavformat|libavcodec|libavutil|libavdevice"
            r"|libswscale|libswresample|ffmpeg",
            re.IGNORECASE,
        ),
        "medium",
    ),
    ("x264 software encoder", re.compile(r"(?:^|[^A-Za-z])x264|libx264", re.IGNORECASE), "low"),
    ("x265 / HEVC software encoder", re.compile(r"(?:^|[^A-Za-z])x265|libx265", re.IGNORECASE), "low"),
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
                # zTXt — keyword visible in cleartext, payload is zlib
                # deflate. Decompress under a strict size cap so an
                # adversarial PNG can't burn memory.
                # Layout after keyword\0: 1 byte compression method,
                # then deflate stream.
                comp_start = kw_end + 2
                try:
                    deco = zlib.decompressobj()
                    inflated = deco.decompress(
                        data[comp_start:data_end], _ZTXT_MAX_DECOMPRESSED
                    )
                    text = inflated.decode("latin-1", errors="replace")
                    decoded_parts.append(f"{keyword}={text}")
                except (zlib.error, ValueError):
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
    # Skip mdat payloads when harvesting text — they're the compressed
    # media stream and decoding them as latin-1 just adds noise. Other
    # leaf boxes get their payloads scraped because tool / writer strings
    # commonly hide in atoms we haven't enumerated explicitly.
    _SKIP_TEXT_HARVEST: Final = frozenset({b"mdat", b"wide", b"free", b"skip", b"junk"})

    for box_type, payload_start, payload_end, _depth in _iter_isobmff_boxes(data, 0, len(data)):
        last_box_end = max(last_box_end, payload_end)

        if box_type == b"ftyp":
            brand = _decode_latin1(data, payload_start, min(payload_start + 4, payload_end)).strip()
            analysis.ftyp_brand = brand
            analysis.generative_metadata_keys.append(f"ftyp:{brand or 'unknown'}")
            # Compatible brands run from offset 8 to end, 4 bytes each.
            cb_start = payload_start + 8
            while cb_start + 4 <= payload_end:
                cb = _decode_latin1(data, cb_start, cb_start + 4).strip()
                if cb:
                    analysis.compatible_brands.append(cb)
                cb_start += 4
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
        elif box_type == b"hdlr":
            # Handler reference. Layout: 1+3 (version+flags), 4 pre_defined,
            # 4 handler_type, 12 reserved, name. The handler_type at offset
            # 8..12 of the payload tells us if the parent track is video,
            # sound, hint, or metadata.
            if payload_end - payload_start >= 12:
                handler_type = data[payload_start + 8 : payload_start + 12]
                if handler_type == b"vide":
                    analysis.video_track_count += 1
                elif handler_type == b"soun":
                    analysis.audio_track_count += 1
            decoded_parts.append(_decode_latin1(data, payload_start, min(payload_end, payload_start + 256)))
        elif box_type not in _SKIP_TEXT_HARVEST and box_type not in _ISOBMFF_CONTAINER_BOXES:
            # Broad text harvest for any leaf box we haven't classified.
            # Caps each box at 1 KB of payload so the overall sample stays
            # bounded even on files with many small metadata atoms.
            decoded_parts.append(_decode_latin1(data, payload_start, min(payload_end, payload_start + 1024)))

    if last_box_end and last_box_end < len(data):
        analysis.trailing_bytes = len(data) - last_box_end
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def _fingerprint_category(name: str) -> str:
    if "C2PA" in name:
        return "provenance"
    if "Photoshop" in name:
        return "editing_transcode"
    if "FFmpeg" in name or "x264" in name or "x265" in name:
        return "editing_transcode"
    return "synthetic_generation"


def _enrich_with_fingerprints(analysis: MediaAnalysis) -> None:
    text = analysis.decoded_text_sample
    # Each fingerprint hit is paired with its per-pattern confidence so the
    # downstream scorer can weight a hard provenance marker differently
    # from a generic encoder string.
    fingerprint_confidence: dict[str, str] = {}
    if text:
        seen = set(analysis.tool_fingerprints)
        for name, pattern, confidence in _TOOL_PATTERNS:
            if name not in seen and pattern.search(text):
                analysis.tool_fingerprints.append(name)
                fingerprint_confidence[name] = confidence
                seen.add(name)

    if analysis.has_c2pa_manifest:
        # C2PA is provenance information, not a "this is synthetic"
        # marker. Keep medium confidence and let the dashboard show
        # the category honestly.
        analysis.findings.append(
            MediaFinding(
                marker="C2PA Content Credentials manifest present",
                confidence="medium",
                detail=(
                    "A JUMBF box or C2PA reference was detected. C2PA is a "
                    "provenance signal: the file declares an editing / capture "
                    "chain. Inspect the manifest to learn what tools touched it."
                ),
                category="provenance",
            )
        )
    if analysis.has_synthid_marker:
        analysis.findings.append(
            MediaFinding(
                marker="Google SynthID provenance marker",
                confidence="high",
                detail="SynthID metadata was detected in the XMP packet.",
                category="synthetic_generation",
            )
        )
    if analysis.has_xmp_packet and not analysis.has_c2pa_manifest:
        analysis.findings.append(
            MediaFinding(
                marker="Adobe XMP packet present",
                confidence="medium",
                detail="XMP often carries provenance, tool, and history metadata.",
                category="provenance",
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
                category="tamper_smuggling",
            )
        )
    for tool in analysis.tool_fingerprints:
        analysis.findings.append(
            MediaFinding(
                marker=f"Binary fingerprint: {tool}",
                confidence=fingerprint_confidence.get(tool, "high"),
                category=_fingerprint_category(tool),
            )
        )

    _add_video_pipeline_findings(analysis)


_APPLE_CAMERA_METADATA_RE: Final = re.compile(
    # Apple QuickTime camera/phone files always carry one or more of:
    #   - com.apple.* metadata keys (make, model, creationdate, location...)
    #   - iTunes-style ©-prefixed atoms (©cpy / ©nam / ©ART / ©day / ©alb / ©cmt / ©too)
    #     The "©" byte decodes from 0xa9 in latin-1, so we match either form.
    #   - "mdta" or "mdir" metadata-namespace markers
    r"com\.apple\.|com\.android\.|mdir|mdta|geID|\xa9cpy|\xa9nam|\xa9ART|\xa9day|\xa9alb|\xa9cmt|\xa9too|\xa9wrt|\xa9enc|\xa9gen|\xa9grp",
    re.IGNORECASE,
)


def _add_video_pipeline_findings(analysis: MediaAnalysis) -> None:
    """Compose structural ISO BMFF signals into stronger AI-video findings.

    Individual signals (FFmpeg writer, silent video, QuickTime brand on
    a non-Apple encoder) are each weak. Their *combination* is a much
    better discriminator: real camera and phone .mov / .mp4 files almost
    never carry an FFmpeg writer atom AND lack an audio track AND
    declare the QuickTime brand AND lack Apple-style capture metadata
    at the same time.
    """
    if analysis.kind != MediaKind.VIDEO:
        return

    has_ffmpeg = any("FFmpeg" in name or "libavformat" in name for name in analysis.tool_fingerprints)
    has_software_encoder = any(
        "x264" in name or "x265" in name for name in analysis.tool_fingerprints
    )
    silent_video = analysis.video_track_count >= 1 and analysis.audio_track_count == 0
    has_capture_metadata = bool(_APPLE_CAMERA_METADATA_RE.search(analysis.decoded_text_sample))

    # Strongest combined finding: silent + FFmpeg + no camera metadata.
    # This is the canonical Sora / Runway / Luma / Pika export shape: a
    # silent video re-encoded by libavformat without any of the Apple or
    # Android capture markers a real phone / camera file would carry.
    if silent_video and has_ffmpeg and not has_capture_metadata:
        analysis.findings.append(
            MediaFinding(
                marker="AI-video pipeline shape (silent + FFmpeg + no capture metadata)",
                confidence="high",
                detail=(
                    "Video has no audio track, was written by libavformat (Lavf), "
                    "and carries none of the Apple- or Android-style capture "
                    "metadata atoms a real phone or camera file would include. "
                    "This is the canonical export shape of AI video generators "
                    "such as OpenAI Sora, Runway, Luma Dream Machine, and Pika."
                ),
                category="synthetic_generation",
            )
        )
    elif silent_video and has_ffmpeg:
        # Silent + FFmpeg but capture metadata present — could be a phone
        # video that was re-edited through ffmpeg. Keep it medium.
        analysis.findings.append(
            MediaFinding(
                marker="Silent video processed by an FFmpeg pipeline",
                confidence="medium",
                detail=(
                    "Video has no audio track and was written by libavformat. "
                    "Common pattern for AI-generated video exports."
                ),
                category="editing_transcode",
            )
        )
    elif has_ffmpeg and not has_capture_metadata and analysis.kind == MediaKind.VIDEO:
        # FFmpeg-written video that's missing capture metadata, but with
        # audio. Probably re-encoded or AI-with-soundtrack — medium tell.
        analysis.findings.append(
            MediaFinding(
                marker="FFmpeg-written video with no camera/phone capture metadata",
                confidence="medium",
                detail=(
                    "Video was written by libavformat without any Apple- or "
                    "Android-style capture metadata. The file did not come "
                    "directly off a phone or dedicated camera."
                ),
                category="editing_transcode",
            )
        )

    # QuickTime brand declared from a non-Apple encoder is a soft tell.
    if analysis.ftyp_brand == "qt" and has_ffmpeg and not has_capture_metadata:
        analysis.findings.append(
            MediaFinding(
                marker="QuickTime container produced by FFmpeg",
                confidence="low",
                detail=(
                    "ftyp brand is QuickTime ('qt  ') but the writer atom is "
                    "libavformat and no Apple metadata atoms are present. "
                    "Phones and Apple software that produce 'qt  ' .mov files "
                    "always write com.apple.quicktime.* keys."
                ),
                category="editing_transcode",
            )
        )

    if silent_video and has_software_encoder and not has_ffmpeg:
        analysis.findings.append(
            MediaFinding(
                marker="Silent video encoded by software-only codec",
                confidence="low",
                detail=(
                    "Video lacks an audio track and was produced by a software "
                    "codec (x264/x265). Phones and cameras almost always use "
                    "hardware encoders and capture audio simultaneously."
                ),
                category="editing_transcode",
            )
        )

    # Honest structural finding: every silent video carries this signal,
    # regardless of writer. We grade it on the FFmpeg context — silent +
    # FFmpeg is a much stronger combined tell than silent alone.
    if silent_video:
        analysis.findings.append(
            MediaFinding(
                marker="Video container has no audio track",
                confidence="medium" if has_ffmpeg else "low",
                detail=(
                    "Most consumer cameras, phones, and screen recorders capture "
                    "audio alongside video. AI video generators (Sora, Runway, "
                    "Luma, Pika) typically produce silent video."
                ),
                category="structural",
            )
        )


def _confidence_weight(confidence: str) -> float:
    return {"high": 0.32, "medium": 0.18, "low": 0.08}.get(confidence, 0.0)


def _category_weight(category: str) -> float:
    """How much a category contributes to the overall slop score.

    Provenance markers describe what touched the file but are NOT a
    "this file is bad" signal — a properly signed C2PA chain on a real
    photo is the *good* outcome. So provenance contributes only a
    small amount to the composite. Synthetic-generation and
    tamper-smuggling carry full weight.
    """
    return {
        "synthetic_generation": 1.0,
        "tamper_smuggling": 1.0,
        "editing_transcode": 0.7,
        "structural": 0.6,
        "provenance": 0.25,
    }.get(category, 1.0)


def _score_and_classify(analysis: MediaAnalysis) -> None:
    score = 0.0
    for finding in analysis.findings:
        score += _confidence_weight(finding.confidence) * _category_weight(finding.category)
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


def _parse_webp(data: bytes) -> MediaAnalysis:
    """Parse a WebP file's RIFF chunks for EXIF and XMP metadata.

    WebP is RIFF-based: 12-byte header (RIFF + size + WEBP), then a
    series of FOURCC chunks (4-byte tag + 4-byte little-endian size +
    payload + optional padding byte).  We harvest EXIF / XMP chunks,
    leave VP8 / VP8L / VP8X / ANIM untouched.
    """
    analysis = _empty(MediaFormat.WEBP, len(data))
    if len(data) < 30:
        analysis.parse_status = "malformed"
        analysis.parse_warning = "WebP container too short for a RIFF header."
        return analysis
    offset = 12
    decoded_parts: list[str] = []
    while offset + 8 <= len(data):
        tag = data[offset : offset + 4]
        size = int.from_bytes(data[offset + 4 : offset + 8], "little")
        payload_start = offset + 8
        payload_end = payload_start + size
        if payload_end > len(data):
            analysis.parse_status = "malformed"
            analysis.parse_warning = (
                "WebP RIFF chunk size exceeds the file. Stopped at offset "
                f"{offset}."
            )
            break
        if tag == b"EXIF":
            analysis.generative_metadata_keys.append("EXIF chunk")
            decoded_parts.append(
                _decode_latin1(data, payload_start, min(payload_end, payload_start + 2048))
            )
        elif tag == b"XMP ":
            analysis.has_xmp_packet = True
            analysis.generative_metadata_keys.append("XMP chunk")
            xmp_text = _decode_latin1(
                data, payload_start, min(payload_end, payload_start + 2048)
            )
            decoded_parts.append(xmp_text)
            if re.search(r"c2pa|content\s*credentials|contentauth", xmp_text, re.IGNORECASE):
                analysis.has_c2pa_manifest = True
            if re.search(r"synthid", xmp_text, re.IGNORECASE):
                analysis.has_synthid_marker = True
        elif tag == b"ICCP":
            analysis.generative_metadata_keys.append("ICCP color profile")
        # Skip the VP8/VP8L/VP8X payloads — they're the compressed image.
        offset = payload_end + (size & 1)  # RIFF aligns chunks to even boundaries
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def _parse_gif(data: bytes) -> MediaAnalysis:
    """Parse a GIF file for comment and application extension text.

    GIF extension blocks are introduced by 0x21, followed by a label
    byte (0xFE for comment, 0xFF for application), then a series of
    sub-blocks. Each sub-block is `len` bytes (1-byte length, then
    `len` bytes of data) and the chain ends with a zero-length block.
    We collect every sub-block payload — generation tools sometimes
    stash parameters here.
    """
    analysis = _empty(MediaFormat.GIF, len(data))
    if not data.startswith(b"GIF87a") and not data.startswith(b"GIF89a"):
        analysis.parse_status = "malformed"
        analysis.parse_warning = "GIF magic header missing."
        return analysis
    offset = 13  # GIF header is 6 (sig) + 7 (LSD) bytes
    decoded_parts: list[str] = []
    # Skip the Global Color Table if present.
    if offset - 1 < len(data):
        packed = data[10]
        if packed & 0x80:
            gct_size = 3 * (1 << ((packed & 0x07) + 1))
            offset += gct_size
    while offset < len(data):
        byte = data[offset]
        if byte == 0x3B:  # trailer
            break
        if byte == 0x21:  # extension block
            if offset + 2 >= len(data):
                analysis.parse_status = "malformed"
                analysis.parse_warning = "Truncated GIF extension header."
                break
            label = data[offset + 1]
            offset += 2
            collected: list[bytes] = []
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                collected.append(data[offset : offset + length])
                offset += length
            block_text = b"".join(collected).decode("latin-1", errors="replace")
            if label == 0xFE:
                analysis.generative_metadata_keys.append("GIF comment")
                decoded_parts.append(block_text)
            elif label == 0xFF:
                analysis.generative_metadata_keys.append("GIF application extension")
                decoded_parts.append(block_text)
            # Other labels (graphic control, plain text) are skipped.
        elif byte == 0x2C:  # image descriptor — skip to next block
            # Image descriptor is 10 bytes, then optional Local Color
            # Table, then sub-block-encoded LZW data. Walk to the
            # zero-length terminator without trying to interpret it.
            offset += 10
            # Skip LCT if present.
            if offset - 1 < len(data):
                lcd_packed = data[offset - 1]
                if lcd_packed & 0x80:
                    lct_size = 3 * (1 << ((lcd_packed & 0x07) + 1))
                    offset += lct_size
            # Skip LZW minimum code size byte.
            if offset < len(data):
                offset += 1
            while offset < len(data):
                length = data[offset]
                offset += 1
                if length == 0:
                    break
                offset += length
        else:
            # Unknown block — abort to avoid infinite loop on garbage.
            analysis.parse_status = "malformed"
            analysis.parse_warning = f"Unknown GIF block byte 0x{byte:02x} at offset {offset}."
            break
    analysis.decoded_text_sample = "\n".join(decoded_parts)[:_MAX_DECODED_TEXT]
    return analysis


def reclassify(analysis: MediaAnalysis) -> None:
    """Recompute score/risk/recommendation after findings were appended.

    Used by the optional vision fusion (``app/core/media_vision.py``) to fold
    a pixel-level verdict into the metadata analysis. ``_score_and_classify``
    overwrites rather than accumulates, so this is safe to call repeatedly.
    """
    _score_and_classify(analysis)


def analyze_media(data: bytes) -> MediaAnalysis:
    """Parse `data` and return a MediaAnalysis. Never raises on malformed input."""
    if not data:
        return _empty()
    fmt = detect_format(data)
    try:
        if fmt == MediaFormat.PNG:
            analysis = _parse_png(data)
        elif fmt == MediaFormat.JPEG:
            analysis = _parse_jpeg(data)
        elif fmt in (MediaFormat.MP4, MediaFormat.MOV, MediaFormat.HEIC, MediaFormat.AVIF):
            analysis = _parse_isobmff(data, fmt)
        elif fmt == MediaFormat.WEBP:
            analysis = _parse_webp(data)
        elif fmt == MediaFormat.GIF:
            analysis = _parse_gif(data)
        else:
            analysis = _empty(fmt, len(data))
            analysis.parse_status = "unsupported"
            analysis.parse_warning = (
                "File format was not recognized by any bundled parser. "
                "Magic bytes did not match PNG, JPEG, WebP, GIF, HEIC, AVIF, MP4, or MOV."
            )
        _enrich_with_fingerprints(analysis)
        _score_and_classify(analysis)
        return analysis
    except Exception as error:
        # Honest failure: the caller treats absence of findings as "no
        # signal", but the parse_warning surfaces that we lost information.
        analysis = _empty(fmt, len(data))
        analysis.parse_status = "parser_error"
        analysis.parse_warning = f"{type(error).__name__}: {error}"[:240]
        _score_and_classify(analysis)
        return analysis
