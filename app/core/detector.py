from __future__ import annotations

import re
from dataclasses import dataclass
from statistics import mean


@dataclass(frozen=True)
class DetectionSignal:
    name: str
    weight: float
    count: int
    description: str


@dataclass(frozen=True)
class DetectionResult:
    score: float
    risk: str
    word_count: int
    signals: list[DetectionSignal]
    recommendation: str


class SlopDetector:
    """Explainable rule-based slop detector.

    This detector is intentionally conservative. It does not prove authorship;
    it scores signs of weak, repetitive, generic, or unsupported content.
    """

    VAGUE_TERMS = {
        "revolutionary", "cutting-edge", "game-changing", "next-generation",
        "seamless", "synergy", "robust", "innovative", "unprecedented",
        "leverage", "optimize", "transformative", "world-class", "holistic",
    }

    UNSUPPORTED_CLAIMS = {
        "guaranteed", "proven", "always", "never", "everyone knows",
        "studies show", "experts agree", "without a doubt", "best-in-class",
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

    def analyze(self, text: str) -> DetectionResult:
        normalized = self._normalize(text)
        words = re.findall(r"\b[\w'-]+\b", normalized)
        word_count = len(words)

        signals: list[DetectionSignal] = []
        signals.extend(
            self._term_signal(
                words,
                self.VAGUE_TERMS,
                "vague_language",
                0.18,
                "Generic marketing or low-specificity language",
            )
        )
        signals.extend(
            self._term_signal(
                words,
                self.UNSUPPORTED_CLAIMS,
                "unsupported_claims",
                0.22,
                "Strong claims that may need evidence",
            )
        )
        signals.extend(
            self._phrase_signal(
                normalized,
                self.FILLER_PHRASES,
                "filler_phrases",
                0.20,
                "Common filler phrases that add little meaning",
            )
        )

        repetition_count = self._repetition_count(words)
        if repetition_count:
            signals.append(
                DetectionSignal(
                    "repetitive_terms",
                    0.16,
                    repetition_count,
                    "Repeated words may indicate padding or generated text",
                )
            )

        sentence_lengths = self._sentence_lengths(text)
        if sentence_lengths and mean(sentence_lengths) > 28:
            signals.append(
                DetectionSignal("long_sentences", 0.10, 1, "Average sentence length is high, reducing clarity")
            )

        if word_count > 0 and self._specificity_ratio(words) < 0.18 and word_count >= 40:
            signals.append(
                DetectionSignal("low_specificity", 0.14, 1, "Text has few concrete nouns, numbers, or named details")
            )

        score = self._score(signals, word_count)
        risk = self._risk(score)
        recommendation = self._recommendation(risk)
        return DetectionResult(
            score=score,
            risk=risk,
            word_count=word_count,
            signals=signals,
            recommendation=recommendation,
        )

    def _normalize(self, text: str) -> str:
        return re.sub(r"\s+", " ", text.lower()).strip()

    def _term_signal(
        self,
        words: list[str],
        terms: set[str],
        name: str,
        weight: float,
        description: str,
    ) -> list[DetectionSignal]:
        counts = sum(1 for word in words if word in terms)
        if counts == 0:
            return []
        return [DetectionSignal(name, weight, counts, description)]

    def _phrase_signal(
        self,
        text: str,
        phrases: set[str],
        name: str,
        weight: float,
        description: str,
    ) -> list[DetectionSignal]:
        counts = sum(text.count(phrase) for phrase in phrases)
        if counts == 0:
            return []
        return [DetectionSignal(name, weight, counts, description)]

    def _repetition_count(self, words: list[str]) -> int:
        meaningful = [word for word in words if len(word) > 4]
        counts = {word: meaningful.count(word) for word in set(meaningful)}
        return sum(1 for count in counts.values() if count >= 4)

    def _sentence_lengths(self, text: str) -> list[int]:
        sentences = [s.strip() for s in re.split(r"[.!?]+", text) if s.strip()]
        return [len(re.findall(r"\b[\w'-]+\b", sentence)) for sentence in sentences]

    def _specificity_ratio(self, words: list[str]) -> float:
        if not words:
            return 0.0
        concrete = [word for word in words if any(ch.isdigit() for ch in word) or len(word) >= 8]
        return len(concrete) / len(words)

    def _score(self, signals: list[DetectionSignal], word_count: int) -> float:
        if word_count == 0:
            return 0.0
        weighted = sum(signal.weight * min(signal.count, 4) for signal in signals)
        length_adjustment = min(word_count / 500, 0.12)
        return round(min(weighted + length_adjustment, 1.0), 3)

    def _risk(self, score: float) -> str:
        if score >= 0.60:
            return "high"
        if score >= 0.30:
            return "moderate"
        return "low"

    def _recommendation(self, risk: str) -> str:
        if risk == "high":
            return "Escalate for human review and request supporting evidence, source links, or clearer specifics."
        if risk == "moderate":
            return "Review before publishing or acting. Ask for concrete details and remove filler language."
        return "No major slop indicators found. Keep normal review standards."
