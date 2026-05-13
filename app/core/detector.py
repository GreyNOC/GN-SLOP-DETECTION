from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from statistics import mean


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


class SlopDetector:
    """Explainable rule-based slop detector.

    This detector is intentionally conservative. It does not prove authorship;
    it scores signs of weak, repetitive, generic, or unsupported content.
    """

    ALGORITHM_VERSION = "rule-picture-v2"

    VAGUE_TERMS = {
        "revolutionary",
        "cutting-edge",
        "game-changing",
        "next-generation",
        "seamless",
        "synergy",
        "robust",
        "innovative",
        "unprecedented",
        "leverage",
        "optimize",
        "transformative",
        "world-class",
        "holistic",
        "dynamic",
        "powerful",
        "comprehensive",
        "scalable",
        "future-proof",
    }

    UNSUPPORTED_CLAIMS = {
        "guaranteed",
        "proven",
        "always",
        "never",
        "best-in-class",
        "industry-leading",
        "unmatched",
        "definitive",
        "superior",
    }

    UNSUPPORTED_PHRASES = {
        "everyone knows",
        "studies show",
        "experts agree",
        "without a doubt",
        "research proves",
        "scientists agree",
        "it is clear that",
    }

    FILLER_PHRASES = {
        "in today's fast-paced world",
        "it is important to note",
        "at the end of the day",
        "this article will explore",
        "delve into",
        "unlock the power",
        "take it to the next level",
    }

    AI_OR_TEMPLATE_PHRASES = {
        "as an ai language model",
        "i cannot browse the internet",
        "in conclusion",
        "overall,",
        "whether you're",
        "look no further",
        "here are some key",
        "let's dive in",
    }

    SEO_PHRASES = {
        "ultimate guide",
        "everything you need to know",
        "top tips",
        "must-read",
        "click here",
        "boost your",
        "rank higher",
    }

    CLAIM_VERBS = {
        "improve",
        "increase",
        "reduce",
        "prevent",
        "protect",
        "detect",
        "ensure",
        "eliminate",
        "solve",
        "deliver",
        "enable",
    }

    def analyze(self, text: str) -> DetectionResult:
        normalized = self._normalize(text)
        words = re.findall(r"\b[\w'-]+\b", normalized)
        word_count = len(words)
        sentences = self._sentences(text)
        sentence_lengths = [len(re.findall(r"\b[\w'-]+\b", sentence)) for sentence in sentences]
        evidence = self._evidence_counts(text)

        signals: list[DetectionSignal] = []
        signals.extend(
            self._term_signal(
                words,
                self.VAGUE_TERMS,
                "vague_language",
                "clarity",
                0.18,
                "Generic marketing or low-specificity language",
            )
        )
        signals.extend(
            self._term_signal(
                words,
                self.UNSUPPORTED_CLAIMS,
                "unsupported_claims",
                "evidence",
                0.22,
                "Strong claims that may need evidence",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized,
                self.UNSUPPORTED_PHRASES,
                "unsupported_claim_phrases",
                "evidence",
                0.22,
                "Claim phrases that reference authority without showing sources",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized,
                self.FILLER_PHRASES,
                "filler_phrases",
                "clarity",
                0.20,
                "Common filler phrases that add little meaning",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized,
                self.AI_OR_TEMPLATE_PHRASES,
                "template_or_ai_scars",
                "authenticity",
                0.16,
                "Template-like phrasing that often appears in low-effort generated text",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized,
                self.SEO_PHRASES,
                "seo_or_clickbait_phrases",
                "manipulation",
                0.14,
                "Search-optimized or promotional phrasing may be crowding out substance",
            )
        )

        repetition_count = self._repetition_count(words)
        if repetition_count:
            signals.append(
                DetectionSignal(
                    "repetitive_terms",
                    "originality",
                    0.16,
                    repetition_count,
                    "Repeated words may indicate padding or generated text",
                )
            )

        if sentence_lengths and mean(sentence_lengths) > 28:
            signals.append(
                DetectionSignal(
                    "long_sentences",
                    "clarity",
                    0.10,
                    1,
                    "Average sentence length is high, reducing clarity",
                )
            )

        specificity_ratio = self._specificity_ratio(words)
        if word_count > 0 and specificity_ratio < 0.18 and word_count >= 40:
            signals.append(
                DetectionSignal(
                    "low_specificity",
                    "specificity",
                    0.14,
                    1,
                    "Text has few concrete nouns, numbers, or named details",
                )
            )

        claim_density = self._claim_density(words)
        evidence_density = self._evidence_density(evidence, word_count)
        if word_count >= 60 and claim_density >= 0.035 and evidence_density < 0.020:
            signals.append(
                DetectionSignal(
                    "evidence_gap",
                    "evidence",
                    0.18,
                    1,
                    "Claims are present but dates, links, citations, or measurements are sparse",
                )
            )

        keyword_stuffing = self._keyword_stuffing_count(words)
        if keyword_stuffing:
            signals.append(
                DetectionSignal(
                    "keyword_stuffing",
                    "manipulation",
                    0.14,
                    keyword_stuffing,
                    "Repeated prominent terms suggest search padding or manufactured emphasis",
                )
            )

        repeated_starters = self._repeated_sentence_starters(sentences)
        if repeated_starters:
            signals.append(
                DetectionSignal(
                    "repeated_sentence_starts",
                    "structure",
                    0.10,
                    repeated_starters,
                    "Multiple sentences begin with the same pattern",
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

    def _normalize(self, text: str) -> str:
        return re.sub(r"\s+", " ", text.lower()).strip()

    def _term_signal(
        self,
        words: list[str],
        terms: set[str],
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
        phrases: set[str],
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
        meaningful = [word for word in words if len(word) > 4]
        counts = Counter(meaningful)
        return sum(1 for count in counts.values() if count >= 4)

    def _sentences(self, text: str) -> list[str]:
        return [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]

    def _specificity_ratio(self, words: list[str]) -> float:
        if not words:
            return 0.0
        concrete = [word for word in words if any(ch.isdigit() for ch in word) or len(word) >= 8]
        return len(concrete) / len(words)

    def _claim_density(self, words: list[str]) -> float:
        if not words:
            return 0.0
        claims = sum(1 for word in words if word in self.CLAIM_VERBS or word in self.UNSUPPORTED_CLAIMS)
        return claims / len(words)

    def _evidence_counts(self, text: str) -> dict[str, int]:
        links = len(re.findall(r"https?://\S+|www\.\S+", text, flags=re.IGNORECASE))
        numbers = len(
            re.findall(
                r"\b\d+(?:[.,:/-]\d+)*(?:%|x|ms|s|m|h|kb|mb|gb|tb)?\b",
                text,
                flags=re.IGNORECASE,
            )
        )
        citations = len(re.findall(r"\[[0-9a-zA-Z]+\]|\([A-Za-z][A-Za-z .-]+,\s*\d{4}\)", text))
        return {"links": links, "numbers": numbers, "citations": citations}

    def _evidence_density(self, evidence: dict[str, int], word_count: int) -> float:
        if word_count == 0:
            return 0.0
        anchors = evidence["links"] + evidence["numbers"] + evidence["citations"]
        return anchors / word_count

    def _repetition_density(self, words: list[str]) -> float:
        meaningful = [word for word in words if len(word) > 4]
        if not meaningful:
            return 0.0
        repeated_instances = sum(count - 1 for count in Counter(meaningful).values() if count > 1)
        return repeated_instances / len(meaningful)

    def _keyword_stuffing_count(self, words: list[str]) -> int:
        meaningful = [word for word in words if len(word) > 5]
        if len(meaningful) < 40:
            return 0
        counts = Counter(meaningful)
        total = len(meaningful)
        return sum(1 for count in counts.values() if count / total >= 0.08 and count >= 5)

    def _repeated_sentence_starters(self, sentences: list[str]) -> int:
        if len(sentences) < 4:
            return 0
        starters = []
        for sentence in sentences:
            words = re.findall(r"\b[\w'-]+\b", sentence.lower())
            if len(words) >= 2:
                starters.append(" ".join(words[:2]))
        counts = Counter(starters)
        return sum(1 for count in counts.values() if count >= 3)

    def _score(self, signals: list[DetectionSignal], word_count: int) -> float:
        if word_count == 0:
            return 0.0
        weighted = sum(signal.weight * min(signal.count, 4) for signal in signals)
        length_adjustment = min(word_count / 500, 0.12)
        return round(min(weighted + length_adjustment, 1.0), 3)

    def _dimensions(self, signals: list[DetectionSignal], profile: ContentProfile) -> list[AnalysisDimension]:
        category_scores = {
            "clarity": 0.0,
            "evidence": max(0.0, 0.20 - min(profile.evidence_density, 0.20)),
            "specificity": max(0.0, 0.24 - min(profile.specificity_ratio, 0.24)),
            "originality": min(profile.repetition_density * 1.2, 0.35),
            "manipulation": 0.0,
            "structure": 0.0,
            "authenticity": 0.0,
        }
        for signal in signals:
            category_scores[signal.category] = (
                category_scores.get(signal.category, 0.0) + signal.weight * min(signal.count, 4)
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
            return "Review before publishing or acting. Ask for concrete details and remove filler language." + focus
        return "No major slop indicators found. Keep normal review standards."
