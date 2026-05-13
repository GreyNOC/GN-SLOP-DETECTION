from app.core.detector import SlopDetector


def test_detector_returns_low_score_for_specific_content():
    text = "The firewall blocked 42 inbound SSH attempts from 203.0.113.10 between 14:05 and 14:10 UTC."
    result = SlopDetector().analyze(text)
    assert result.risk == "low"
    assert result.score < 0.30


def test_detector_flags_sloppy_content():
    text = "In today's fast-paced world, this revolutionary seamless synergy is guaranteed and best-in-class. " * 4
    result = SlopDetector().analyze(text)
    assert result.risk in {"moderate", "high"}
    assert result.signals
