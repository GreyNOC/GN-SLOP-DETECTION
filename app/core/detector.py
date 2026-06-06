from __future__ import annotations

import re
import unicodedata
from collections import Counter
from dataclasses import dataclass
from statistics import mean, pstdev


@dataclass(frozen=True)
class DetectionSignal:
    name: str
    category: str
    weight: float
    count: int
    description: str


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


class SlopDetector:
    """Explainable rule-based slop detector.

    This detector is intentionally conservative. It does not prove authorship;
    it scores signs of weak, repetitive, generic, or unsupported content.
    """

    ALGORITHM_VERSION = "rule-picture-v3"

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
    })

    AI_OR_TEMPLATE_PHRASES = frozenset({
        "as an ai language model", "i cannot browse the internet",
        "in conclusion,", "overall,", "whether you're", "look no further",
        "here are some key", "let's dive in", "let's explore",
        "i hope this helps", "feel free to ask", "let me know if you have",
        "of course!", "certainly!", "absolutely!", "great question",
        "i'm sorry, but", "as an ai", "i am an ai", "as a language model",
        "you might be wondering", "let's take a closer look",
    })

    SEO_PHRASES = frozenset({
        "ultimate guide", "everything you need to know", "top tips",
        "must-read", "click here", "boost your", "rank higher",
        "game changer", "deep dive", "supercharge", "next-level",
        "level up your",
    })

    AI_TRANSITION_WORDS = frozenset({
        "moreover", "furthermore", "additionally", "however",
        "consequently", "therefore", "nonetheless", "nevertheless",
        "ultimately", "notably", "importantly", "indeed", "essentially",
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

    def analyze(self, text: str) -> DetectionResult:
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

        specificity_ratio = self._specificity_ratio(cased_tokens, words)
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

        repetition_density = self._repetition_density(words)
        profile = ContentProfile(
            algorithm=self.ALGORITHM_VERSION,
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
        dimensions = self._dimensions(signals, profile)
        recommendation = self._recommendation(risk, dimensions)
        return DetectionResult(
            score=score,
            risk=risk,
            word_count=word_count,
            signals=signals,
            dimensions=dimensions,
            profile=profile,
            recommendation=recommendation,
        )

    def _normalize_for_matching(self, text: str) -> str:
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
        counts = sum(1 for word in words if word in terms)
        if counts == 0:
            return []
        return [DetectionSignal(name, category, weight, counts, description)]

    def _phrase_signal(
        self,
        text: str,
        phrases: frozenset[str],
        name: str,
        category: str,
        weight: float,
        description: str,
    ) -> list[DetectionSignal]:
        counts = sum(text.count(phrase) for phrase in phrases)
        if counts == 0:
            return []
        return [DetectionSignal(name, category, weight, counts, description)]

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
        # Soft saturation: each additional hit contributes half as much as the
        # previous one and the per-signal contribution is capped, so a single
        # noisy detector cannot dominate the composite score.
        weighted = 0.0
        for signal in signals:
            if signal.count <= 1:
                scaled = 1.0
            else:
                scaled = min(1.0 + 0.5 * (signal.count - 1), 4.0)
            weighted += signal.weight * scaled
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
            if signal.count <= 1:
                scaled = 1.0
            else:
                scaled = min(1.0 + 0.5 * (signal.count - 1), 4.0)
            category_scores[signal.category] = (
                category_scores.get(signal.category, 0.0) + signal.weight * scaled
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
