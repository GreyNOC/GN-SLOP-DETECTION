"""Adversarial-evasion detection and normalization for the text engine.

A lexicon/statistics detector is trivially blinded by character-level tricks
that leave the text looking identical to a human reader:

  * **Zero-width / invisible characters** (U+200B..U+200D, U+FEFF, U+2060,
    soft hyphen) spliced inside words — ``revolutionary`` with a zero-width
    space in the middle no longer matches the literal token, and the tokenizer
    splits it in two.
  * **Homoglyph substitution** — Cyrillic ``о``/``е``/``а`` or Greek ``ο``/``ν``
    swapped for Latin lookalikes so a flagged word evades an exact match while
    looking unchanged. NFKC does NOT fold these (they are distinct letters in
    distinct scripts), so the existing normalization misses them.
  * **Bidi control characters** (the Trojan-Source family, U+202A..U+202E,
    U+2066..U+2069) that reorder rendered text.
  * **Exotic whitespace** (non-breaking and Unicode spaces) used to break
    tokenization or pad keyword density invisibly.

This module does two complementary things, the standard pairing for robust
detection:

  1. ``scan_evasion`` — *report* the obfuscation as a finding in its own right.
     Mixed-script words and bidi controls are near-zero-false-positive tells of
     deliberate tampering; their presence is itself signal.
  2. ``normalize_adversarial`` — *defeat* the obfuscation by stripping
     invisibles/bidi, folding the common attack homoglyphs back to ASCII, and
     regularizing whitespace, so the downstream slop signals still fire on the
     cleaned text instead of being silently evaded.

The control characters are written as explicit codepoints, never as literal
glyphs — invisible literals are unreadable in source and a normalizing editor
or linter can silently delete them. The homoglyph table is a curated set of
the high-frequency attack characters, not the full Unicode confusables
database — enough to defeat the common evasions while staying small and
auditable.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Invisible / zero-width formatting characters with no place in ordinary prose.
_INVISIBLE_CHARS: frozenset[str] = frozenset(
    chr(cp)
    for cp in (
        0x200B,  # zero width space
        0x200C,  # zero width non-joiner
        0x200D,  # zero width joiner
        0x2060,  # word joiner
        0xFEFF,  # zero width no-break space / BOM
        0x00AD,  # soft hyphen
        0x180E,  # Mongolian vowel separator (historically zero-width)
        0x200E,  # left-to-right mark
        0x200F,  # right-to-left mark
        0x061C,  # arabic letter mark
    )
)

# Bidirectional override/embedding/isolate controls (Trojan Source family).
_BIDI_CONTROLS: frozenset[str] = frozenset(
    chr(cp)
    for cp in (
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # embeddings + overrides
        0x2066, 0x2067, 0x2068, 0x2069,          # isolates
    )
)

# Non-standard whitespace that renders like a space but is not U+0020. Folded
# to a plain space during normalization; counted (above a tolerance) as a tell.
_EXOTIC_SPACES: frozenset[str] = frozenset(
    chr(cp)
    for cp in (
        0x00A0,  # no-break space
        0x1680,  # ogham space mark
        *range(0x2000, 0x200B),  # en quad .. hair space
        0x202F,  # narrow no-break space
        0x205F,  # medium mathematical space
        0x3000,  # ideographic space
    )
)

# Curated homoglyph -> ASCII map. Covers the Cyrillic and Greek letters whose
# glyphs are visually identical (or nearly so) to common Latin letters — the
# characters actually used in homoglyph evasion. NFKC leaves these untouched.
# Keys are built from codepoints for the same auditability reason as above.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lowercase -> Latin
    chr(0x0430): "a", chr(0x0435): "e", chr(0x043E): "o", chr(0x0440): "p",
    chr(0x0441): "c", chr(0x0445): "x", chr(0x0443): "y", chr(0x0456): "i",
    chr(0x0458): "j", chr(0x0455): "s", chr(0x043A): "k", chr(0x04BB): "h",
    chr(0x0501): "d", chr(0x051B): "q", chr(0x0461): "w",
    # Cyrillic uppercase -> Latin
    chr(0x0410): "A", chr(0x0412): "B", chr(0x0415): "E", chr(0x041A): "K",
    chr(0x041C): "M", chr(0x041D): "H", chr(0x041E): "O", chr(0x0420): "P",
    chr(0x0421): "C", chr(0x0422): "T", chr(0x0425): "X", chr(0x0405): "S",
    chr(0x0406): "I", chr(0x0408): "J",
    # Greek lowercase -> Latin
    chr(0x03BF): "o", chr(0x03B1): "a", chr(0x03BD): "v", chr(0x03C1): "p",
    chr(0x03C4): "t", chr(0x03B5): "e", chr(0x03B9): "i", chr(0x03BA): "k",
    chr(0x03C5): "u",
    # Greek uppercase -> Latin
    chr(0x039F): "O", chr(0x0391): "A", chr(0x0392): "B", chr(0x0395): "E",
    chr(0x0397): "H", chr(0x0399): "I", chr(0x039A): "K", chr(0x039C): "M",
    chr(0x039D): "N", chr(0x03A1): "P", chr(0x03A4): "T", chr(0x03A7): "X",
    chr(0x0396): "Z",
}

_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


@dataclass(frozen=True)
class EvasionReport:
    """What character-level obfuscation, if any, was found in the text."""

    invisible_chars: int = 0
    bidi_controls: int = 0
    exotic_spaces: int = 0
    confusable_chars: int = 0
    mixed_script_words: int = 0
    examples: tuple[str, ...] = field(default_factory=tuple)

    @property
    def total(self) -> int:
        return (
            self.invisible_chars
            + self.bidi_controls
            + self.exotic_spaces
            + self.confusable_chars
            + self.mixed_script_words
        )

    @property
    def is_evasive(self) -> bool:
        """High-confidence deliberate obfuscation.

        Any invisible-in-text character, any bidi control, or any mixed-script
        word is a near-zero-false-positive tell. Exotic spaces and lone
        confusable characters can occur innocently (a pasted nbsp, a single
        accented loanword), so they do not trip this on their own.
        """
        return self.invisible_chars > 0 or self.bidi_controls > 0 or self.mixed_script_words > 0


def _script_of(char: str) -> str:
    """Coarse script classification for an alphabetic character."""
    code = ord(char)
    if 0x0400 <= code <= 0x04FF or 0x0500 <= code <= 0x052F:
        return "cyrillic"
    if 0x0370 <= code <= 0x03FF or 0x1F00 <= code <= 0x1FFF:
        return "greek"
    if (
        0x41 <= code <= 0x5A
        or 0x61 <= code <= 0x7A
        or 0x00C0 <= code <= 0x024F  # Latin-1 supplement + extended (accents)
    ):
        return "latin"
    return "other"


def scan_evasion(text: str) -> EvasionReport:
    """Detect character-level evasion without modifying the text."""
    if not text:
        return EvasionReport()
    invisible = sum(1 for ch in text if ch in _INVISIBLE_CHARS)
    bidi = sum(1 for ch in text if ch in _BIDI_CONTROLS)
    exotic = sum(1 for ch in text if ch in _EXOTIC_SPACES)
    confusable = sum(1 for ch in text if ch in _HOMOGLYPHS)

    mixed = 0
    examples: list[str] = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        scripts = {_script_of(ch) for ch in token if ch.isalpha()}
        scripts.discard("other")
        if len(scripts) > 1:
            mixed += 1
            if len(examples) < 5:
                examples.append(token)
    return EvasionReport(
        invisible_chars=invisible,
        bidi_controls=bidi,
        exotic_spaces=exotic,
        confusable_chars=confusable,
        mixed_script_words=mixed,
        examples=tuple(examples),
    )


def normalize_adversarial(text: str) -> str:
    """Strip invisibles/bidi, fold attack homoglyphs to ASCII, regularize spaces.

    Returns text that is semantically what a human reader sees, so the
    downstream rule matching cannot be evaded by character-level tricks. Does
    not collapse runs of whitespace — that is left to the engine's existing
    normalization so behavior on clean text is unchanged.
    """
    if not text:
        return text
    out: list[str] = []
    for ch in text:
        if ch in _INVISIBLE_CHARS or ch in _BIDI_CONTROLS:
            continue
        if ch in _EXOTIC_SPACES:
            out.append(" ")
            continue
        out.append(_HOMOGLYPHS.get(ch, ch))
    return "".join(out)


def deobfuscate(text: str) -> tuple[str, EvasionReport]:
    """Convenience: scan the raw text and return (cleaned_text, report)."""
    report = scan_evasion(text)
    return normalize_adversarial(text), report


def canonicalize(text: str) -> str:
    """NFKC on top of adversarial normalization, for callers wanting one entry."""
    return unicodedata.normalize("NFKC", normalize_adversarial(text))
