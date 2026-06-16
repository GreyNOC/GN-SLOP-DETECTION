"""Tests for adversarial-evasion detection, normalization, and engine robustness.

Two properties matter, and the second is the one that actually defends the
detector:

  1. Obfuscation is *detected* (surfaced as its own signal).
  2. Obfuscation does not *blind* the engine — after normalization the same
     slop signals that fire on the clean text still fire on the obfuscated one.

Control characters are spelled with chr(0x....) so the test source stays
readable and a normalizing editor can't silently eat them.
"""

from __future__ import annotations

from app.core.adversarial import (
    EvasionReport,
    normalize_adversarial,
    scan_evasion,
)
from app.core.detector import SlopDetector

ZWSP = chr(0x200B)  # zero width space
ZWNJ = chr(0x200C)  # zero width non-joiner
BIDI_OVERRIDE = chr(0x202E)  # right-to-left override (Trojan Source)
NBSP = chr(0x00A0)  # no-break space
CYR_O = chr(0x043E)  # Cyrillic small o (homoglyph of Latin o)
CYR_A = chr(0x0430)  # Cyrillic small a
CYR_E = chr(0x0435)  # Cyrillic small e
CYR_Y = chr(0x0443)  # Cyrillic small u (homoglyph of Latin y)


def _signal_names(text: str, profile: str = "general") -> set[str]:
    return {s.name for s in SlopDetector().analyze(text, profile=profile).signals}


# --- detection -------------------------------------------------------------


def test_scan_detects_zero_width() -> None:
    report = scan_evasion(f"rev{ZWSP}olution{ZWSP}ary")
    assert report.invisible_chars == 2
    assert report.is_evasive


def test_scan_detects_bidi_control() -> None:
    report = scan_evasion(f"normal text {BIDI_OVERRIDE} reordered")
    assert report.bidi_controls == 1
    assert report.is_evasive


def test_scan_detects_mixed_script_word() -> None:
    # "revolutionary" with Cyrillic o's embedded -> Latin+Cyrillic in one token.
    word = f"rev{CYR_O}luti{CYR_O}nary"
    report = scan_evasion(word)
    assert report.mixed_script_words == 1
    assert report.confusable_chars == 2
    assert report.is_evasive
    assert report.examples and word in report.examples[0]


def test_clean_text_is_not_evasive() -> None:
    report = scan_evasion("This is a perfectly ordinary sentence about cafe latte.")
    assert not report.is_evasive
    assert report.mixed_script_words == 0


def test_lone_nbsp_is_not_evasive() -> None:
    # A single non-breaking space (common from CMS paste) must not trip the
    # high-confidence evasion flag on its own.
    report = scan_evasion(f"hello{NBSP}world from the editor")
    assert report.exotic_spaces == 1
    assert not report.is_evasive


# --- normalization ---------------------------------------------------------


def test_normalize_strips_invisibles() -> None:
    assert normalize_adversarial(f"rev{ZWSP}olu{ZWNJ}tionary") == "revolutionary"


def test_normalize_folds_homoglyphs() -> None:
    assert normalize_adversarial(f"rev{CYR_O}luti{CYR_O}nary") == "revolutionary"
    assert normalize_adversarial(f"{CYR_A}wesome s{CYR_E}rvice") == "awesome service"


def test_normalize_regularizes_exotic_space() -> None:
    assert normalize_adversarial(f"hello{NBSP}world") == "hello world"


def test_normalize_strips_bidi() -> None:
    assert normalize_adversarial(f"abc{BIDI_OVERRIDE}def") == "abcdef"


def test_normalize_leaves_clean_ascii_untouched() -> None:
    clean = "A normal sentence with plain words in it."
    assert normalize_adversarial(clean) == clean


# --- engine robustness (the load-bearing property) -------------------------

_SLOPPY = (
    "This revolutionary, cutting-edge, game-changing solution leverages "
    "next-generation synergy to deliver unprecedented, world-class outcomes "
    "for every single team that depends on it, guaranteed."
)


def test_engine_flags_obfuscated_sloppy_text() -> None:
    assert "vague_language" in _signal_names(_SLOPPY)  # baseline trips the lexicon

    # Hide the lexicon hits with zero-width splices + homoglyphs.
    obfuscated = (
        f"This rev{ZWSP}olutionary, cutting-edge, game-changing solution "
        f"leverages next-generation s{CYR_Y}nergy to deliver unprecedented, "
        f"w{CYR_O}rld-class outcomes for every single team that depends on it, "
        f"guaranteed."
    )
    obf_names = _signal_names(obfuscated)
    # The slop signal survives de-obfuscation...
    assert "vague_language" in obf_names
    # ...AND the obfuscation itself is now flagged.
    assert "evasion_obfuscation" in obf_names


def test_obfuscation_does_not_lower_score() -> None:
    detector = SlopDetector()
    clean = detector.analyze(_SLOPPY).score
    obfuscated_text = _SLOPPY.replace("revolutionary", f"rev{ZWSP}{CYR_O}luti{CYR_O}nary")
    obfuscated = detector.analyze(obfuscated_text).score
    # Evasion adds a signal and the slop signals still fire, so the obfuscated
    # version can only score at least as high as the clean one.
    assert obfuscated >= clean


def test_clean_text_has_no_evasion_signal() -> None:
    assert "evasion_obfuscation" not in _signal_names(_SLOPPY)


def test_empty_report_total_is_zero() -> None:
    assert EvasionReport().total == 0
