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


def test_detector_returns_complete_slop_picture():
    text = (
        "Experts agree this unmatched platform will improve every workflow. "
        "It is important to note that the solution is revolutionary and dynamic."
    )
    result = SlopDetector().analyze(text)
    assert result.profile.algorithm == "rule-picture-v3"
    assert result.dimensions
    assert {dimension.name for dimension in result.dimensions} >= {"Clarity", "Evidence", "Specificity"}
    assert all(0.0 <= dimension.score <= 1.0 for dimension in result.dimensions)


def test_detector_matches_curly_quoted_phrases():
    # Pasted content frequently uses curly apostrophes; the engine must still
    # match phrases that depend on the apostrophe such as "it's worth noting".
    text = (
        "It’s worth noting that this revolutionary solution is guaranteed. "
        "It’s worth noting that experts agree, without a doubt."
    )
    result = SlopDetector().analyze(text)
    signal_names = {signal.name for signal in result.signals}
    assert "filler_phrases" in signal_names
    assert "unsupported_claim_phrases" in signal_names


def test_detector_flags_em_dash_overuse():
    # Em-dash drift relative to sentence length is a frequent AI tell. Push past
    # the 60-word floor by repeating a dash-heavy sentence and adding filler.
    base = (
        "The proposal — broadly speaking — outlines a path — with caveats — forward."
    )
    tail = (
        " Adoption depends on cost, governance, training, tooling, and the appetite "
        "for change inside the organisation across teams, departments, and regions."
    )
    text = (base + " ") * 5 + tail
    result = SlopDetector().analyze(text)
    signal_names = {signal.name for signal in result.signals}
    assert "em_dash_overuse" in signal_names


def test_detector_flags_transition_word_stuffing():
    text = (
        "Moreover, the system performs well under steady production load conditions. "
        "Furthermore, observed latency remains acceptable across the measured regions. "
        "Additionally, the team noted high throughput during the burst windows. "
        "However, the overall cost profile has trended higher than projections. "
        "Consequently, the program team must decide on the next migration step. "
        "Therefore, a follow-up architecture review is scheduled for next month. "
        "Notably, the regressions identified during testing were minor and isolated. "
        "Indeed, the data captured during rollout supports a wider deployment. "
        "Importantly, the rollout still proceeds in staged batches over coming sprints. "
        "Essentially, the broader program continues into the next planning cycle as planned."
    )
    result = SlopDetector().analyze(text)
    signal_names = {signal.name for signal in result.signals}
    assert "transition_word_stuffing" in signal_names


def test_detector_flags_repeated_trigrams():
    chunk = "The detection pipeline ingests structured telemetry for review."
    text = (
        (chunk + " ") * 4
        + "Operators rely on dashboards for situational awareness during the shift. "
        + "Engineers monitor latency carefully and document changes for downstream consumers. "
        + "Procedures are documented in runbooks updated quarterly by the platform team. "
        + (chunk + " ") * 2
        + "Stakeholders meet weekly to triage the highest priority findings together."
    )
    result = SlopDetector().analyze(text)
    signal_names = {signal.name for signal in result.signals}
    assert "repeated_phrases" in signal_names


def test_detector_specificity_ratio_counts_acronyms_and_numbers_only():
    # Long but generic words must NOT inflate the specificity ratio. Previously
    # words like "revolutionary" counted as concrete simply because they were
    # long. Pad past the 40-word floor with more generic vocabulary.
    text = (
        "This revolutionary unprecedented transformative innovative solution leverages synergy across everything. "
        "Holistic synergistic comprehensive scalable platforms empower agile streamlined workflows everywhere. "
        "Bespoke seamless powerful future proof tooling delivers value for stakeholders today. "
        "Robust transformative dynamic powerful holistic capabilities enable smoother delivery across teams."
    )
    result = SlopDetector().analyze(text)
    assert result.profile.specificity_ratio == 0.0
    assert any(signal.name == "low_specificity" for signal in result.signals)


def test_detector_recognises_doi_citation():
    text = (
        "The malware family was profiled in detail at doi:10.1000/abcd over three independent runs. "
        "Across all telemetry, analysts confirmed the staged exfil pattern."
    )
    result = SlopDetector().analyze(text)
    assert result.profile.citation_count >= 1


def test_detector_handles_empty_input():
    result = SlopDetector().analyze("")
    assert result.word_count == 0
    assert result.score == 0.0
    assert result.risk == "low"
    assert result.signals == []
