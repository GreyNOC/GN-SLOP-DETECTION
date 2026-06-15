"""Tests for the 2025-26 frontier heuristic refresh (Track D).

Positive: each new signal fires on its targeted AI-styled sample.
Negative (load-bearing): a concrete SOC incident note fires NONE of them.
Net: a clearly-sloppy modern sample outscores a concrete note.
"""

from __future__ import annotations

from app.core.detector import SlopDetector


def _names(text: str, profile: str = "general") -> set[str]:
    return {s.name for s in SlopDetector().analyze(text, profile=profile).signals}


def test_contrastive_negation_fires_on_ai_framing() -> None:
    text = (
        "It's not just a tool, it's a movement. This is not only faster, but "
        "smarter. Our customers depend on this platform every single day across "
        "many different teams and time zones, and they tell us it changed how "
        "they work together."
    )
    assert "contrastive_negation" in _names(text)


def test_rule_of_three_fires_on_comma_triads() -> None:
    text = (
        "The platform is faster, cheaper, and safer than anything that came "
        "before it. It informs, it shapes, and it transforms how modern teams "
        "plan, build, and operate together. We move quickly, decisively, and "
        "confidently into the next quarter, and every stakeholder across the "
        "whole organization has clearly noticed the improvement in speed, "
        "quality, and overall morale this year. Honestly, the entire leadership "
        "team agrees on this particular point quite completely and openly."
    )
    assert "rule_of_three" in _names(text)


def test_over_structuring_fires_on_emoji_bulleted_markdown() -> None:
    text = (
        "# The Ultimate Guide to Everything\n\n"
        "## Why It Matters\n\n"
        "In a world where everything moves quickly, you need a partner you can "
        "trust to deliver real outcomes for your team and your customers every "
        "single day without fail.\n\n"
        "✅ **Fast** delivery on every order, every time\n"
        "✅ **Reliable** uptime that your whole company can count on\n"
        "✨ **Seamless** onboarding for everyone on the team\n\n"
        "## The Takeaway\n\n"
        "### Next Steps\n\n"
        "This **comprehensive**, **powerful**, and genuinely **transformative** "
        "platform will reshape how your entire organization plans, builds, and "
        "ships software for years to come."
    )
    assert "over_structuring" in _names(text)


def test_frontier_rhetoric_phrases_fire() -> None:
    text = (
        "Here's the thing: let's break it down. At its core, in a world where "
        "everything changes, the result? A better experience. The takeaway? "
        "More than just hype."
    )
    assert "frontier_rhetoric" in _names(text)


def test_new_signals_do_not_fire_on_concrete_incident_note() -> None:
    text = (
        "At 14:05 UTC the WAF blocked 42 inbound requests from 203.0.113.10 to "
        "/api/login. Rule SQLI-204 matched the payload. We rate-limited the "
        "source /24 at the edge and opened INC-4821. CVE-2024-31497 was "
        "confirmed patched on host db-03 (v2.4.1) at 14:12. No data "
        "exfiltration was observed in the 24h window after containment. The "
        "responders involved were TCP, UDP, and ICMP traffic analysts."
    )
    names = _names(text, profile="soc")
    assert "contrastive_negation" not in names
    assert "rule_of_three" not in names
    assert "over_structuring" not in names
    assert "frontier_rhetoric" not in names


def test_modern_sloppy_sample_scores_higher_than_concrete() -> None:
    sloppy = (
        "# Here's the Thing\n\n"
        "Let's break it down. This isn't just a product, it's a revolution. "
        "It's not only faster, but smarter. At its core, in a world where "
        "everything changes, the result? A seamless, holistic, and "
        "game-changing experience that customers love.\n\n"
        "✅ **Powerful**\n✅ **Scalable**\n✨ **Innovative**\n\n"
        "The takeaway? More than just hype, it is genuinely the future, "
        "delivered today for every single team that depends on it."
    )
    concrete = (
        "At 14:05 UTC the firewall blocked 42 SSH attempts from 203.0.113.10. "
        "INC-4821 opened; host patched to v2.4.1 at 14:12."
    )
    detector = SlopDetector()
    assert detector.analyze(sloppy).score > detector.analyze(concrete).score


def test_soc_profile_softens_new_signals() -> None:
    sloppy = (
        "# The Ultimate Guide to Everything\n\n"
        "## Why It Matters\n\n"
        "This isn't just a tool, it's a movement. It's not only faster, but "
        "smarter and bolder for every modern team out there today.\n\n"
        "✅ **Fast** delivery on every order, every single time without fail\n"
        "✅ **Reliable** uptime that your whole company can absolutely count on\n"
        "✨ **Seamless** onboarding for everyone who joins the growing team\n\n"
        "## The Takeaway\n\n### Next Steps\n\n"
        "We move quickly, decisively, and confidently into a future that is "
        "faster, cleaner, and bolder than anything before it for everyone."
    )
    detector = SlopDetector()
    assert detector.analyze(sloppy, profile="soc").score <= detector.analyze(sloppy).score
