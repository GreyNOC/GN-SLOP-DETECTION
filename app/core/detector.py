from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from statistics import mean, pstdev
from typing import TYPE_CHECKING

from app.core.adversarial import normalize_adversarial, scan_evasion
from app.core.learned_weights import LearnedWeights, scaled_activation

if TYPE_CHECKING:
    from app.core.model_detector import ModelDetector, ModelDetectorResult


@dataclass(frozen=True)
class SignalMatch:
    term: str
    excerpt: str
    line: int | None = None


@dataclass(frozen=True)
class DetectionSignal:
    name: str
    category: str
    weight: float
    count: int
    description: str
    matches: tuple[SignalMatch, ...] = ()


@dataclass(frozen=True)
class AnalysisDimension:
    name: str
    score: float
    status: str
    description: str


@dataclass(frozen=True)
class ContentProfile:
    algorithm: str
    sentence_count: int
    average_sentence_length: float
    specificity_ratio: float
    evidence_density: float
    repetition_density: float
    link_count: int
    numeric_detail_count: int
    citation_count: int


@dataclass(frozen=True)
class DetectionResult:
    score: float
    risk: str
    word_count: int
    signals: list[DetectionSignal]
    dimensions: list[AnalysisDimension]
    profile: ContentProfile
    recommendation: str
    content_profile: str = "general"
    sample_quality: str = "medium"
    confidence: float = 1.0
    # Optional model-based AI-likelihood estimate (see model_detector.py).
    # None unless a ModelDetector was supplied to analyze(). Surfaced as
    # explainable metadata only — never folded into the composite score.
    model_detection: ModelDetectorResult | None = None


EM_DASH = "—"
EN_DASH = "–"

CURLY_PUNCTUATION = {
    "‘": "'",
    "’": "'",
    "“": '"',
    "”": '"',
    "′": "'",
    "″": '"',
    "´": "'",
    "«": '"',
    "»": '"',
}

WORD_RE = re.compile(r"\b[\w'\-]+\b")
SENTENCE_SPLIT_RE = re.compile(r"[.!?]+")
LINK_RE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
NUMBER_RE = re.compile(
    r"(?<!\w)\d+(?:[.,:/\-]\d+)*(?:%|x|ms|s|m|h|kb|mb|gb|tb)?(?:\b|(?=%))",
    re.IGNORECASE,
)
CITATION_RE = re.compile(
    r"\[\d+(?:[\s,\-]\d+)*\]"
    r"|\([A-Z][A-Za-z .\-]+,\s*\d{4}\)"
    r"|\bdoi:\s*\S+"
    r"|\b10\.\d{4,9}/[^\s]+",
    re.IGNORECASE,
)
EM_DASH_RE = re.compile(rf"[{EM_DASH}{EN_DASH}]")

# Frontier rhetorical patterns (2025-26). The static lexicons catch dead
# 2023-era tells; these catch what modern models actually do. Modern models
# deliberately vary sentence length (blunting the burstiness/MATTR signals),
# but they lean hard on a few rhetorical and layout moves.
#
# Contrastive negation: "it's not just X, it's Y" / "isn't about X, it's Y"
# (em/en dashes are already normalized to " - " before matching).
CONTRASTIVE_NEGATION_RE = re.compile(
    # "about" is dropped from the qualifier set: "not about X, but Y" is
    # ordinary contrastive prose, not the AI tic. The pivot accepts the
    # un-contracted "it is" / "that is" too, not just the contraction.
    r"\b(?:it'?s|that'?s|this is|we'?re|they'?re|you'?re)?\s*not\s+"
    r"(?:just|only|merely|simply)\b[^.!?]{1,80}?"
    r"(?:,\s*(?:it'?s|it\s+is|that'?s|that\s+is|but rather|but)\b"
    r"|\s-\s|;\s*(?:it'?s|it\s+is)\b)",
    re.IGNORECASE,
)
# Bare "not X - it's Y" / "not X, but Y" without a leading pronoun.
CONTRASTIVE_NEGATION_DASH_RE = re.compile(
    r"\bnot\s+[^.!?,]{2,40}\s-\s(?:it'?s|but|rather)\b",
    re.IGNORECASE,
)
# Rule-of-three escalation: three comma-separated items with a trailing
# and/or, e.g. "faster, cheaper, and safer". Three capture groups so the
# detector can filter technical enumerations (acronyms / numbers).
RULE_OF_THREE_RE = re.compile(
    r"\b(\w+(?:\s\w+){0,2}),\s+(\w+(?:\s\w+){0,2}),\s+(?:and|or)\s+(\w+(?:\s\w+){0,2})\b",
    re.IGNORECASE,
)
# Over-structuring (run on RAW text — markdown survives only before
# normalization collapses newlines): headers, heavy bold runs, emoji bullets.
MD_HEADER_RE = re.compile(r"(?m)^\s{0,3}#{1,6}\s+\S")
MD_BOLD_RE = re.compile(r"\*\*[^*\n]{1,60}\*\*")
EMOJI_BULLET_RE = re.compile(
    r"(?m)^\s*(?:[-*]\s+)?"
    r"(?:✅|❌|✨|•|\U0001F449|\U0001F539|\U0001F4A1|\U0001F680|➡|⭐)"
)

# Function words that should be excluded from repetition / TTR / stuffing analyses
# so signal calculations are dominated by content tokens.
STOPWORDS = frozenset({
    "a", "an", "the", "is", "it", "of", "to", "in", "on", "at", "and", "or", "but", "for",
    "with", "as", "be", "been", "are", "was", "were", "this", "that", "these", "those", "by",
    "from", "into", "you", "your", "we", "our", "they", "their", "i", "me", "my", "he", "she",
    "his", "her", "them", "us", "if", "so", "no", "not", "do", "does", "did", "have", "has",
    "had", "can", "could", "would", "should", "will", "just", "than", "then", "there", "here",
    "what", "which", "who", "whom", "when", "where", "why", "how", "any", "all", "every",
    "some", "one", "two", "more", "most", "such", "both", "either", "neither", "also", "yet",
    "very", "much", "many", "via", "out", "over", "about", "between", "while",
})


_VALID_PROFILES = ("general", "soc", "marketing", "academic", "support")

# Profile-specific multipliers applied to specific signal categories.
# A multiplier of 1.0 keeps the default weight; <1.0 softens; >1.0
# sharpens. Multipliers are deliberately conservative so a profile
# never silences a signal entirely.
_PROFILE_MULTIPLIERS: dict[str, dict[str, float]] = {
    "general": {},
    "soc": {
        # SOC notes use compressed technical phrasing; vague-language
        # hits there are usually false positives.
        "vague_language": 0.55,
        "filler_phrases": 0.65,
        "long_sentences": 0.5,
        # Runbooks/playbooks legitimately use headers, bold, and triads.
        "over_structuring": 0.6,
        "rule_of_three": 0.7,
    },
    "marketing": {
        # Marketing copy will always use some promotional language;
        # don't punish it twice, but keep the unsupported-claims
        # penalty intact.
        "vague_language": 0.5,
        "seo_or_clickbait_phrases": 0.5,
        # Still flag the bigger lies hard.
        "unsupported_claims": 1.0,
        "unsupported_claim_phrases": 1.0,
    },
    "academic": {
        # Academic writing rewards citations; soften the AI-template
        # signal because formal prose is allowed to be formulaic.
        "template_or_ai_scars": 0.7,
        # Formal argumentation uses "not X but Y" framing legitimately.
        "contrastive_negation": 0.7,
    },
    "support": {
        # Support tickets are conversational; long sentences and
        # transitions are normal.
        "long_sentences": 0.6,
        "transition_word_stuffing": 0.7,
        # Numbered step lists are normal in support replies.
        "over_structuring": 0.7,
    },
}

# Concrete-detail patterns used by the upgraded specificity calculator.
# Each hit advances the "this text contains specifics" counter and is
# also surfaced as a signal match excerpt.
_SPECIFICITY_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ip", re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")),
    ("ipv6", re.compile(r"\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)),
    ("port", re.compile(r"\b(?:port|tcp|udp)\s*[:#]?\s*\d{1,5}\b", re.IGNORECASE)),
    ("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)),
    ("hash", re.compile(r"\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b", re.IGNORECASE)),
    ("date", re.compile(r"\b(?:19|20)\d{2}-\d{2}-\d{2}\b|\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}")),
    (
        "domain",
        re.compile(
            r"\b[a-z0-9][a-z0-9\-]+\.(?:com|org|net|io|ai|dev|gov|edu|uk|de|fr|jp|cn|au|ca)\b",
            re.IGNORECASE,
        ),
    ),
    ("url", re.compile(r"https?://\S+")),
    ("file_path", re.compile(r"(?:^|\s)/(?:[\w\-./]+)|\b[A-Za-z]:\\[\w\-\\.]+")),
    ("version", re.compile(r"\bv?\d+\.\d+(?:\.\d+){0,2}\b")),
    ("ticket", re.compile(r"\b(?:[A-Z]{2,8}-\d{3,6}|#\d{3,6})\b")),
    (
        "measurement",
        re.compile(
            r"\b\d+(?:\.\d+)?\s*(?:ms|s|min|h|hour|hours|day|days|MB|GB|TB|KB|kbps|mbps|gbps|%)\b",
            re.IGNORECASE,
        ),
    ),
]


class SlopDetector:
    """Explainable rule-based slop detector.

    This detector is intentionally conservative. It does not prove authorship;
    it scores signs of weak, repetitive, generic, or unsupported content.
    """

    ALGORITHM_VERSION = "rule-picture-v5"

    VAGUE_TERMS = frozenset({
        "revolutionary", "cutting-edge", "game-changing", "next-generation",
        "seamless", "synergy", "robust", "innovative", "unprecedented",
        "leverage", "optimize", "transformative", "world-class", "holistic",
        "dynamic", "powerful", "comprehensive", "scalable", "future-proof",
        "paradigm", "ecosystem", "tapestry", "landscape", "empower",
        "streamline", "vibrant", "elevate", "groundbreaking", "state-of-the-art",
        "bespoke", "transform", "synergistic", "agile", "frictionless",
    })

    UNSUPPORTED_CLAIMS = frozenset({
        "guaranteed", "proven", "always", "never", "best-in-class",
        "industry-leading", "unmatched", "definitive", "superior",
        "world-renowned", "award-winning", "undeniable", "indisputable",
        "flawless", "ultimate", "unparalleled", "unrivaled",
    })

    UNSUPPORTED_PHRASES = frozenset({
        "everyone knows", "studies show", "experts agree", "without a doubt",
        "research proves", "scientists agree", "it is clear that",
        "it is widely known", "common knowledge", "needless to say",
        "it goes without saying", "as we all know",
    })

    FILLER_PHRASES = frozenset({
        "in today's fast-paced world", "it is important to note",
        "it's important to note", "it is worth noting", "it's worth noting",
        "it is worth mentioning", "it's worth mentioning",
        "at the end of the day", "this article will explore",
        "delve into", "unlock the power", "take it to the next level",
        "when it comes to", "in the realm of", "in this day and age",
        "in the world of", "navigating the complexities", "in the ever-evolving",
        "play a crucial role", "play a pivotal role", "the bottom line",
        "first and foremost", "in essence",
        # 2025-26 frontier filler.
        "a testament to", "speaks volumes", "in the grand scheme of things",
        "at the heart of", "a deep dive into", "the ever-changing landscape",
        "stand the test of time", "a double-edged sword", "the lifeblood of",
        "when it comes down to it", "shed light on", "pave the way",
        "the secret sauce", "the name of the game",
    })

    AI_OR_TEMPLATE_PHRASES = frozenset({
        "as an ai language model", "i cannot browse the internet",
        "in conclusion,", "overall,", "whether you're", "look no further",
        "here are some key", "let's dive in", "let's explore",
        "i hope this helps", "feel free to ask", "let me know if you have",
        "of course!", "certainly!", "absolutely!", "great question",
        "i'm sorry, but", "as an ai", "i am an ai", "as a language model",
        "you might be wondering", "let's take a closer look",
        # 2025-26 chat-assistant residue.
        "here's a breakdown", "here's the breakdown", "let's dive deeper",
        "to put it simply", "to sum it up", "in summary,", "key takeaways",
        "tl;dr", "in short,", "hope this helps!", "happy to help",
        "i'd be happy to", "great point", "you're absolutely right",
        "let's get started", "without further ado",
    })

    SEO_PHRASES = frozenset({
        "ultimate guide", "everything you need to know", "top tips",
        "must-read", "click here", "boost your", "rank higher",
        "game changer", "deep dive", "supercharge", "next-level",
        "level up your",
        # 2025-26 listicle / blog scaffolding.
        "in this article", "read on", "keep reading", "the complete guide",
        "step-by-step guide", "pro tip", "here's why",
    })

    AI_TRANSITION_WORDS = frozenset({
        "moreover", "furthermore", "additionally", "however",
        "consequently", "therefore", "nonetheless", "nevertheless",
        "ultimately", "notably", "importantly", "indeed", "essentially",
        "crucially", "fundamentally", "interestingly", "remarkably",
        "significantly", "arguably", "likewise",
    })

    # Current frontier rhetorical openers/connectors — exact-phrase, low
    # false-positive, surfaced as template residue. Punctuation-anchored
    # entries ("the result?", "the takeaway?") are near-zero FP; bare
    # high-FP phrases ("that said", "the truth is") are deliberately
    # excluded to keep precision high.
    FRONTIER_RHETORIC_PHRASES = frozenset({
        "here's the thing", "here is the thing", "let's break it down",
        "let's break this down", "the result?", "the takeaway?",
        "the bottom line?", "at its core", "in a world where",
        "more than just", "but here's the kicker", "the kicker?",
        "think of it like", "think of it as", "the beauty of",
        "this is where", "the magic happens", "let that sink in",
        "what does this mean for you", "so what does this mean",
        "buckle up", "plot twist", "long story short",
    })

    CLAIM_VERBS = frozenset({
        "improve", "increase", "reduce", "prevent", "protect", "detect",
        "ensure", "eliminate", "solve", "deliver", "enable", "boost",
        "accelerate", "maximize",
    })

    # Surfaced for callers to tune.
    MIN_WORDS_FOR_BURSTINESS = 80
    BURSTINESS_FLAG_THRESHOLD = 0.30
    MIN_WORDS_FOR_TTR = 80
    TTR_FLAG_THRESHOLD = 0.45

    def __init__(self, learned_weights: LearnedWeights | None = None) -> None:
        """Optionally score with learned, glass-box weights instead of the
        hand-tuned defaults.

        ``learned_weights`` may be passed explicitly; if omitted, the engine
        looks for a ``SLOP_LEARNED_WEIGHTS`` file via the env. Either way the
        default (nothing configured) keeps the byte-identical hand-tuned
        behavior, and the signal list/dimensions are unchanged — only the
        composite score's combination rule swaps to the fitted logistic.
        """
        self._learned = learned_weights if learned_weights is not None else LearnedWeights.from_env()

    def analyze(
        self,
        text: str,
        profile: str = "general",
        model_detector: ModelDetector | None = None,
    ) -> DetectionResult:
        if profile not in _VALID_PROFILES:
            profile = "general"
        raw = text or ""
        # The em-dash signal is calculated against the original text because
        # _normalize_for_matching rewrites dashes to spaces for phrase matching.
        em_dash_count = len(EM_DASH_RE.findall(raw))
        evidence = self._evidence_counts(raw)

        normalized = self._normalize_for_matching(raw)
        normalized_lower = normalized.lower()
        cased_tokens = WORD_RE.findall(normalized)
        words = [token.lower() for token in cased_tokens]
        word_count = len(words)
        sentences = self._sentences(normalized)
        sentence_lengths = [len(WORD_RE.findall(sentence)) for sentence in sentences]

        signals: list[DetectionSignal] = []
        signals.extend(
            self._term_signal(
                words, self.VAGUE_TERMS,
                "vague_language", "clarity", 0.18,
                "Generic marketing or low-specificity language",
            )
        )
        signals.extend(
            self._term_signal(
                words, self.UNSUPPORTED_CLAIMS,
                "unsupported_claims", "evidence", 0.22,
                "Strong claims that may need evidence",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized_lower, self.UNSUPPORTED_PHRASES,
                "unsupported_claim_phrases", "evidence", 0.22,
                "Claim phrases that reference authority without showing sources",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized_lower, self.FILLER_PHRASES,
                "filler_phrases", "clarity", 0.20,
                "Common filler phrases that add little meaning",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized_lower, self.AI_OR_TEMPLATE_PHRASES,
                "template_or_ai_scars", "authenticity", 0.18,
                "Template-like phrasing common in low-effort generated text",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized_lower, self.SEO_PHRASES,
                "seo_or_clickbait_phrases", "manipulation", 0.14,
                "Search-optimized or promotional phrasing may be crowding out substance",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized_lower, self.FRONTIER_RHETORIC_PHRASES,
                "frontier_rhetoric", "authenticity", 0.14,
                "Rhetorical openers/connectors common in modern generated prose",
            )
        )

        transitions = sum(1 for word in words if word in self.AI_TRANSITION_WORDS)
        if (
            word_count >= 100
            and transitions >= 4
            and transitions / max(word_count, 1) >= 0.015
        ):
            signals.append(
                DetectionSignal(
                    "transition_word_stuffing", "structure", 0.14, transitions,
                    "Frequent formulaic transition words suggest templated structure",
                )
            )

        if (
            em_dash_count >= 4
            and word_count >= 60
            and em_dash_count / max(word_count / 100, 1) >= 1.0
        ):
            signals.append(
                DetectionSignal(
                    "em_dash_overuse", "authenticity", 0.16, em_dash_count,
                    "Heavy em/en-dash usage relative to length is a frequent AI pattern",
                )
            )

        # Character-level evasion (homoglyphs / zero-width / bidi). Scored on
        # RAW text, before normalize_for_matching scrubs it. This is a
        # deliberate-manipulation tell, not a quality one: a high-confidence,
        # near-zero-false-positive signal that someone tried to hide the text
        # from an exact-match detector.
        evasion = scan_evasion(raw)
        if evasion.is_evasive:
            tells: list[str] = []
            if evasion.invisible_chars:
                tells.append(f"{evasion.invisible_chars} zero-width/invisible char(s)")
            if evasion.bidi_controls:
                tells.append(f"{evasion.bidi_controls} bidi control(s)")
            if evasion.mixed_script_words:
                sample = ", ".join(evasion.examples[:3])
                tells.append(f"{evasion.mixed_script_words} mixed-script word(s): {sample}")
            matches = tuple(SignalMatch(term="evasion", excerpt=tell) for tell in tells)
            signals.append(
                DetectionSignal(
                    "evasion_obfuscation", "manipulation", 0.22,
                    max(evasion.invisible_chars + evasion.bidi_controls + evasion.mixed_script_words, 1),
                    "Text uses homoglyphs, zero-width, or bidi characters to evade "
                    "exact-match detection — a deliberate-obfuscation tell",
                    matches,
                )
            )

        # Contrastive negation ("not just X, it's Y") — authenticity scar.
        contrastive = self._contrastive_negation(normalized)
        if word_count >= 40 and contrastive >= 2:
            signals.append(
                DetectionSignal(
                    "contrastive_negation", "authenticity", 0.16, contrastive,
                    "Repeated 'not just X, it's Y' framing is a frequent AI rhetorical tic",
                )
            )

        # Rule-of-three escalation — structural tic, weak per-hit so require 3.
        triads = self._rule_of_three(normalized)
        if word_count >= 60 and triads >= 3:
            signals.append(
                DetectionSignal(
                    "rule_of_three", "structure", 0.12, triads,
                    "Frequent three-part comma escalations suggest templated rhetoric",
                )
            )

        # Over-structuring (heavy headers / bold / emoji bullets) on RAW text.
        headers, bold_runs, emoji_bullets = self._over_structuring(raw)
        structure_load = (
            (1 if headers >= 4 else 0)
            + (1 if bold_runs >= 6 else 0)
            + (1 if emoji_bullets >= 3 else 0)
        )
        if word_count >= 80 and structure_load >= 2:
            signals.append(
                DetectionSignal(
                    "over_structuring", "structure", 0.12,
                    headers + bold_runs + emoji_bullets,
                    "Heavy headers, bold runs, or emoji bullets relative to length "
                    "is a generated-layout pattern",
                )
            )

        repetition_count = self._repetition_count(words)
        if repetition_count:
            signals.append(
                DetectionSignal(
                    "repetitive_terms", "originality", 0.16, repetition_count,
                    "Repeated content words may indicate padding or generated text",
                )
            )

        trigram_repeats = self._ngram_repetition(words, 3)
        if word_count >= 80 and trigram_repeats:
            signals.append(
                DetectionSignal(
                    "repeated_phrases", "originality", 0.16, trigram_repeats,
                    "Multi-word phrases repeat unusually often",
                )
            )

        if sentence_lengths and mean(sentence_lengths) > 28:
            signals.append(
                DetectionSignal(
                    "long_sentences", "clarity", 0.10, 1,
                    "Average sentence length is high, reducing clarity",
                )
            )

        burstiness = self._burstiness(sentence_lengths)
        if (
            word_count >= self.MIN_WORDS_FOR_BURSTINESS
            and 0 < burstiness < self.BURSTINESS_FLAG_THRESHOLD
        ):
            signals.append(
                DetectionSignal(
                    "low_burstiness", "structure", 0.12, 1,
                    "Sentence lengths vary very little, a pattern common in generated text",
                )
            )

        specificity_ratio, _specificity_matches = self._specificity_ratio_v2(
            cased_tokens, words, raw
        )
        if word_count >= 40 and specificity_ratio < 0.10:
            signals.append(
                DetectionSignal(
                    "low_specificity", "specificity", 0.14, 1,
                    "Text has few concrete nouns, numbers, or named details",
                )
            )

        claim_density = self._claim_density(words)
        evidence_density = self._evidence_density(evidence, word_count)
        if word_count >= 60 and claim_density >= 0.030 and evidence_density < 0.020:
            signals.append(
                DetectionSignal(
                    "evidence_gap", "evidence", 0.18, 1,
                    "Claims are present but dates, links, citations, or measurements are sparse",
                )
            )

        # Claim-to-evidence proximity. A sentence that asserts something
        # strong should sit next to a link / number / citation / named
        # entity. If a majority of claim sentences are bare, treat that
        # as a separate, weaker signal than the bulk evidence_density
        # hit above.
        unsupported_claim_sentences = self._unsupported_claim_sentences(sentences)
        if word_count >= 50 and unsupported_claim_sentences >= max(2, len(sentences) // 4):
            signals.append(
                DetectionSignal(
                    "unsupported_claim_sentences",
                    "evidence",
                    0.14,
                    unsupported_claim_sentences,
                    "Several claim sentences lack any nearby evidence anchor",
                )
            )

        keyword_stuffing = self._keyword_stuffing_count(words)
        if keyword_stuffing:
            signals.append(
                DetectionSignal(
                    "keyword_stuffing", "manipulation", 0.14, keyword_stuffing,
                    "Repeated prominent terms suggest search padding or manufactured emphasis",
                )
            )

        repeated_starters = self._repeated_sentence_starters(sentences)
        if repeated_starters:
            signals.append(
                DetectionSignal(
                    "repeated_sentence_starts", "structure", 0.10, repeated_starters,
                    "Multiple sentences begin with the same pattern",
                )
            )

        ttr = self._mattr(words)
        if word_count >= self.MIN_WORDS_FOR_TTR and 0 < ttr < self.TTR_FLAG_THRESHOLD:
            signals.append(
                DetectionSignal(
                    "low_vocabulary_diversity", "originality", 0.14, 1,
                    "Vocabulary diversity (moving TTR) is low for the length",
                )
            )

        # Apply profile-specific weight multipliers. Hits are rewritten,
        # not dropped, so the dashboard still surfaces them — they just
        # contribute less / more to the composite score.
        multipliers = _PROFILE_MULTIPLIERS.get(profile, {})
        if multipliers:
            adjusted: list[DetectionSignal] = []
            for signal in signals:
                multiplier = multipliers.get(signal.name, 1.0)
                if multiplier == 1.0:
                    adjusted.append(signal)
                    continue
                adjusted.append(
                    DetectionSignal(
                        signal.name,
                        signal.category,
                        round(signal.weight * multiplier, 4),
                        signal.count,
                        signal.description,
                        signal.matches,
                    )
                )
            signals = adjusted

        repetition_density = self._repetition_density(words)
        algorithm = self.ALGORITHM_VERSION + ("+learned" if self._learned is not None else "")
        profile_content = ContentProfile(
            algorithm=algorithm,
            sentence_count=len(sentences),
            average_sentence_length=round(mean(sentence_lengths), 2) if sentence_lengths else 0.0,
            specificity_ratio=round(specificity_ratio, 3),
            evidence_density=round(evidence_density, 3),
            repetition_density=round(repetition_density, 3),
            link_count=evidence["links"],
            numeric_detail_count=evidence["numbers"],
            citation_count=evidence["citations"],
        )
        score = self._score(signals, word_count)
        risk = self._risk(score)
        dimensions = self._dimensions(signals, profile_content)
        recommendation = self._recommendation(risk, dimensions)
        sample_quality, confidence = self._sample_quality(word_count)
        # Optional model-based second opinion. A buggy or unavailable
        # detector must never break rule-based analysis, so swallow errors.
        model_detection = None
        if model_detector is not None:
            try:
                model_detection = model_detector.analyze(raw)
            except Exception:
                model_detection = None
        return DetectionResult(
            score=score,
            risk=risk,
            word_count=word_count,
            signals=signals,
            dimensions=dimensions,
            profile=profile_content,
            recommendation=recommendation,
            content_profile=profile,
            sample_quality=sample_quality,
            confidence=confidence,
            model_detection=model_detection,
        )

    def _normalize_for_matching(self, text: str) -> str:
        # First defeat character-level evasion (zero-width splices, homoglyph
        # substitution, bidi controls, exotic spaces) so an attacker cannot
        # hide a flagged word from the lexicons. NFKC does NOT fold cross-script
        # homoglyphs, so this step is additive, not redundant.
        text = normalize_adversarial(text)
        # NFKC folds presentational variants (full-width digits, ligatures) into
        # base forms so curly-quoted or fancy text still matches the rule sets.
        text = unicodedata.normalize("NFKC", text)
        for source, target in CURLY_PUNCTUATION.items():
            text = text.replace(source, target)
        text = text.replace(EM_DASH, " - ").replace(EN_DASH, " - ")
        return re.sub(r"\s+", " ", text).strip()

    def _term_signal(
        self,
        words: list[str],
        terms: frozenset[str],
        name: str,
        category: str,
        weight: float,
        description: str,
    ) -> list[DetectionSignal]:
        hits: list[str] = []
        for word in words:
            if word in terms:
                hits.append(word)
        if not hits:
            return []
        matches = tuple(
            SignalMatch(term=term, excerpt=term) for term in list(dict.fromkeys(hits))[:8]
        )
        return [DetectionSignal(name, category, weight, len(hits), description, matches)]

    def _phrase_signal(
        self,
        text: str,
        phrases: frozenset[str],
        name: str,
        category: str,
        weight: float,
        description: str,
    ) -> list[DetectionSignal]:
        total = 0
        match_list: list[SignalMatch] = []
        for phrase in phrases:
            occurrences = text.count(phrase)
            if not occurrences:
                continue
            total += occurrences
            if len(match_list) < 8:
                index = text.find(phrase)
                start = max(0, index - 24)
                end = min(len(text), index + len(phrase) + 24)
                excerpt = re.sub(r"\s+", " ", text[start:end]).strip()
                match_list.append(SignalMatch(term=phrase, excerpt=excerpt[:160]))
        if not total:
            return []
        return [DetectionSignal(name, category, weight, total, description, tuple(match_list))]

    def _repetition_count(self, words: list[str]) -> int:
        meaningful = [word for word in words if len(word) > 4 and word not in STOPWORDS]
        counts = Counter(meaningful)
        return sum(1 for count in counts.values() if count >= 4)

    def _ngram_repetition(self, words: list[str], n: int) -> int:
        tokens = [word for word in words if word not in STOPWORDS]
        if len(tokens) < n * 3:
            return 0
        ngrams = list(zip(*(tokens[i:] for i in range(n)), strict=False))
        counts = Counter(ngrams)
        return sum(1 for count in counts.values() if count >= 3)

    def _sentences(self, text: str) -> list[str]:
        return [segment.strip() for segment in SENTENCE_SPLIT_RE.split(text) if segment.strip()]

    def _specificity_ratio_v2(
        self,
        cased_tokens: list[str],
        words: list[str],
        raw: str,
    ) -> tuple[float, tuple[SignalMatch, ...]]:
        """New specificity scorer.

        Builds a denominator from word tokens. The numerator counts:
          - tokens that contain a digit
          - tokens that are CamelCase / acronyms
          - matches of the concrete-detail patterns (IPs, CVEs, ports,
            URLs, file paths, versions, ticket ids, measurements, etc.)
        Each concrete pattern match is also captured as a SignalMatch
        excerpt for the dashboard.
        """
        if not words:
            return 0.0, ()
        concrete = 0
        for token_cased, token_lower in zip(cased_tokens, words, strict=True):
            if any(ch.isdigit() for ch in token_lower):
                concrete += 1
                continue
            if (
                len(token_cased) >= 2
                and token_cased[0].isupper()
                and any(ch.isupper() for ch in token_cased[1:])
            ):
                concrete += 1
        matches: list[SignalMatch] = []
        for kind, pattern in _SPECIFICITY_PATTERNS:
            for match in pattern.finditer(raw):
                concrete += 1
                if len(matches) < 12:
                    start = max(0, match.start() - 24)
                    end = min(len(raw), match.end() + 24)
                    excerpt = re.sub(r"\s+", " ", raw[start:end]).strip()
                    matches.append(SignalMatch(term=kind, excerpt=excerpt[:120]))
                if len(matches) >= 64:
                    break
        return concrete / len(words), tuple(matches)

    def _unsupported_claim_sentences(self, sentences: list[str]) -> int:
        """Count sentences that look like claims but lack nearby evidence.

        "Claim" here is a heuristic: the sentence contains a claim verb
        or unsupported claim adjective. "Evidence" means the same
        sentence or its immediate neighbours include a number, URL,
        citation marker, date, named org (capitalized 2+ word phrase),
        CVE, or measurement.
        """
        if not sentences:
            return 0
        claim_re = re.compile(
            r"\b(?:" + "|".join(re.escape(w) for w in (self.CLAIM_VERBS | self.UNSUPPORTED_CLAIMS)) + r")\b",
            re.IGNORECASE,
        )
        evidence_re = re.compile(
            r"\b\d|https?://|CVE-\d{4}-\d|doi:|\[\d+\]|\([A-Z][a-z]+,\s*\d{4}\)|"
            r"\b[A-Z][a-zA-Z]+\s[A-Z][a-zA-Z]+\b",
        )
        bare = 0
        for index, sentence in enumerate(sentences):
            if not claim_re.search(sentence):
                continue
            # Look at this sentence + neighbour for any evidence anchor.
            window = sentence
            if index + 1 < len(sentences):
                window += " " + sentences[index + 1]
            if index - 1 >= 0:
                window = sentences[index - 1] + " " + window
            if not evidence_re.search(window):
                bare += 1
        return bare

    def _sample_quality(self, word_count: int) -> tuple[str, float]:
        if word_count < 30:
            return "low", 0.45
        if word_count < 150:
            return "medium", 0.75
        return "high", 1.0

    def _specificity_ratio(self, cased_tokens: list[str], words: list[str]) -> float:
        if not words:
            return 0.0
        concrete = 0
        for token_cased, token_lower in zip(cased_tokens, words, strict=True):
            if any(ch.isdigit() for ch in token_lower):
                concrete += 1
                continue
            # Proper noun / acronym heuristic: capitalized with at least one
            # other uppercase letter (e.g., "SSH", "GreyNOC", "DDoS").
            if (
                len(token_cased) >= 2
                and token_cased[0].isupper()
                and any(ch.isupper() for ch in token_cased[1:])
            ):
                concrete += 1
        return concrete / len(words)

    def _claim_density(self, words: list[str]) -> float:
        if not words:
            return 0.0
        claims = sum(1 for word in words if word in self.CLAIM_VERBS or word in self.UNSUPPORTED_CLAIMS)
        return claims / len(words)

    def _evidence_counts(self, text: str) -> dict[str, int]:
        links = len(LINK_RE.findall(text))
        numbers = len(NUMBER_RE.findall(text))
        citations = len(CITATION_RE.findall(text))
        return {"links": links, "numbers": numbers, "citations": citations}

    def _evidence_density(self, evidence: dict[str, int], word_count: int) -> float:
        if word_count == 0:
            return 0.0
        anchors = evidence["links"] + evidence["numbers"] + evidence["citations"]
        return anchors / word_count

    def _repetition_density(self, words: list[str]) -> float:
        meaningful = [word for word in words if len(word) > 4 and word not in STOPWORDS]
        if not meaningful:
            return 0.0
        repeated_instances = sum(count - 1 for count in Counter(meaningful).values() if count > 1)
        return repeated_instances / len(meaningful)

    def _keyword_stuffing_count(self, words: list[str]) -> int:
        meaningful = [word for word in words if len(word) > 5 and word not in STOPWORDS]
        if len(meaningful) < 40:
            return 0
        counts = Counter(meaningful)
        total = len(meaningful)
        return sum(1 for count in counts.values() if count / total >= 0.05 and count >= 5)

    def _repeated_sentence_starters(self, sentences: list[str]) -> int:
        if len(sentences) < 4:
            return 0
        starters = []
        for sentence in sentences:
            tokens = WORD_RE.findall(sentence.lower())
            if len(tokens) >= 2:
                starters.append(" ".join(tokens[:2]))
        counts = Counter(starters)
        return sum(1 for count in counts.values() if count >= 3)

    def _contrastive_negation(self, normalized: str) -> int:
        # "not just X, it's Y" framing. Two patterns; sum their hits.
        return (
            len(CONTRASTIVE_NEGATION_RE.findall(normalized))
            + len(CONTRASTIVE_NEGATION_DASH_RE.findall(normalized))
        )

    def _rule_of_three(self, normalized: str) -> int:
        # Comma triads with a trailing and/or. Filter technical enumerations
        # so "TCP, UDP, and ICMP", "REST, SOAP, and GraphQL", or "v1, v2, and
        # v3" are not mistaken for rhetorical escalation. Run on cased text so
        # acronyms are visible.
        count = 0
        for match in RULE_OF_THREE_RE.finditer(normalized):
            items = [match.group(1).strip(), match.group(2).strip(), match.group(3).strip()]
            if any(any(ch.isdigit() for ch in item) for item in items):
                continue
            # Skip when any item is a short all-caps token (an acronym like
            # TCP/REST). A single acronym is enough to mark the triad as a
            # technical enumeration rather than rhetoric.
            if any(item.isalpha() and item.isupper() and len(item) <= 6 for item in items):
                continue
            count += 1
        return count

    def _over_structuring(self, raw: str) -> tuple[int, int, int]:
        # RAW text: markdown markers survive only before normalization
        # collapses newlines and rewrites punctuation.
        headers = len(MD_HEADER_RE.findall(raw))
        bold = len(MD_BOLD_RE.findall(raw))
        emoji_bullets = len(EMOJI_BULLET_RE.findall(raw))
        return headers, bold, emoji_bullets

    def _burstiness(self, sentence_lengths: list[int]) -> float:
        # Coefficient of variation. Human prose mixes short/long sentences; AI
        # output tends toward a tight distribution. Returns -1.0 when there is
        # not enough data so callers can disable the signal.
        if len(sentence_lengths) < 5:
            return -1.0
        average = mean(sentence_lengths)
        if average <= 0:
            return -1.0
        return pstdev(sentence_lengths) / average

    def _mattr(self, words: list[str], window: int = 50) -> float:
        # Moving-average type-token ratio: a length-stable estimate of
        # vocabulary diversity.
        meaningful = [word for word in words if word not in STOPWORDS]
        if len(meaningful) < window:
            return -1.0
        ratios = [
            len(set(meaningful[i : i + window])) / window
            for i in range(len(meaningful) - window + 1)
        ]
        return mean(ratios) if ratios else -1.0

    def _score(self, signals: list[DetectionSignal], word_count: int) -> float:
        if word_count == 0:
            return 0.0
        # Learned, glass-box scoring (opt-in): a fitted logistic over the same
        # per-signal activations. Default stays the hand-tuned additive rule.
        if self._learned is not None:
            return self._learned.score(signals)
        # Soft saturation: each additional hit contributes half as much as the
        # previous one and the per-signal contribution is capped, so a single
        # noisy detector cannot dominate the composite score.
        weighted = 0.0
        for signal in signals:
            weighted += signal.weight * scaled_activation(signal.count)
        length_adjustment = min(word_count / 800, 0.08)
        return round(min(weighted + length_adjustment, 1.0), 3)

    def _dimensions(
        self, signals: list[DetectionSignal], profile: ContentProfile
    ) -> list[AnalysisDimension]:
        category_scores: dict[str, float] = {
            "clarity": 0.0,
            "evidence": max(0.0, 0.20 - min(profile.evidence_density, 0.20)),
            "specificity": max(0.0, 0.20 - min(profile.specificity_ratio, 0.20)),
            "originality": min(profile.repetition_density * 1.2, 0.35),
            "manipulation": 0.0,
            "structure": 0.0,
            "authenticity": 0.0,
        }
        for signal in signals:
            category_scores[signal.category] = (
                category_scores.get(signal.category, 0.0)
                + signal.weight * scaled_activation(signal.count)
            )

        dimension_specs = [
            ("Clarity", "clarity", "How much filler, vagueness, or hard-to-read sentence shape appears."),
            (
                "Evidence",
                "evidence",
                "Whether claims are supported by links, citations, dates, measurements, or named specifics.",
            ),
            ("Specificity", "specificity", "How much concrete detail appears compared with generic phrasing."),
            ("Originality", "originality", "How much repeated language or padding appears in the content."),
            (
                "Manipulation",
                "manipulation",
                "Whether SEO, clickbait, or exaggerated promotional language is shaping the piece.",
            ),
            ("Structure", "structure", "Whether sentence patterns look repetitive or templated."),
            ("Authenticity", "authenticity", "Whether template residue or obvious generated-text scars are present."),
        ]
        return [
            AnalysisDimension(
                name,
                round(min(category_scores.get(key, 0.0), 1.0), 3),
                self._dimension_status(category_scores.get(key, 0.0)),
                description,
            )
            for name, key, description in dimension_specs
        ]

    def _dimension_status(self, score: float) -> str:
        if score >= 0.45:
            return "elevated"
        if score >= 0.18:
            return "review"
        return "clean"

    def _risk(self, score: float) -> str:
        if score >= 0.60:
            return "high"
        if score >= 0.30:
            return "moderate"
        return "low"

    def _recommendation(self, risk: str, dimensions: list[AnalysisDimension]) -> str:
        elevated = [dimension.name.lower() for dimension in dimensions if dimension.status == "elevated"]
        focus = f" Focus review on {', '.join(elevated[:3])}." if elevated else ""
        if risk == "high":
            return (
                "Escalate for human review and request supporting evidence, source links, or clearer specifics."
                + focus
            )
        if risk == "moderate":
            return (
                "Review before publishing or acting. Ask for concrete details and remove filler language."
                + focus
            )
        return "No major slop indicators found. Keep normal review standards."
