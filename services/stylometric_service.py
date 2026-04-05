import math
import re
from collections import Counter

from models import StylometricAnalysis, TrustStatus


class StylometricService:
    """
    Lightweight stylometric consistency check.
    The goal is not authorship attribution, but detecting a meaningful
    departure from a source's historical writing profile.
    """

    FUNCTION_WORDS = {
        "the", "a", "an", "and", "or", "but", "if", "then", "than", "that",
        "this", "these", "those", "is", "are", "was", "were", "be", "been",
        "to", "of", "for", "with", "in", "on", "at", "by", "from", "as",
        "it", "its", "their", "his", "her", "our", "we", "you", "they",
        "he", "she", "not", "no", "do", "does", "did", "have", "has", "had"
    }

    WORD_RE = re.compile(r"\b[\w'-]+\b")
    SENTENCE_RE = re.compile(r"[.!?]+")

    @staticmethod
    async def analyze(current_text: str, historical_texts: list[str]) -> StylometricAnalysis:
        analysis = StylometricAnalysis()

        usable_history = [text.strip() for text in historical_texts if text and text.strip()]
        current_text = (current_text or "").strip()

        analysis.sample_count = len(usable_history)
        analysis.current_word_count = StylometricService._word_count(current_text)
        analysis.baseline_word_count = sum(StylometricService._word_count(text) for text in usable_history)

        if not current_text:
            analysis.flags.append("No current text provided for stylometric analysis")
            return analysis

        if len(usable_history) < 2:
            analysis.flags.append("At least two historical texts are required for stylometric analysis")
            return analysis

        if analysis.current_word_count < 40:
            analysis.flags.append("Current text is too short for reliable stylometric analysis")
            return analysis

        if analysis.baseline_word_count < 50:
            analysis.flags.append("Historical baseline is too small for reliable stylometric analysis")
            return analysis

        current_profile = StylometricService._extract_profile(current_text)
        history_profiles = [StylometricService._extract_profile(text) for text in usable_history]
        baseline_profile = StylometricService._average_profiles(history_profiles)

        style_distance = StylometricService._profile_distance(current_profile, baseline_profile)
        analysis.style_distance = round(style_distance, 3)

        if style_distance >= 0.35:
            analysis.stylistic_shift_detected = True
            analysis.risk_score = 8
            analysis.status = TrustStatus.SUSPICIOUS
            analysis.flags.append("Writing style differs significantly from historical samples")
        elif style_distance >= 0.22:
            analysis.risk_score = 4
            analysis.status = TrustStatus.SUSPICIOUS
            analysis.flags.append("Writing style shows a moderate shift from historical samples")
        else:
            analysis.risk_score = 0
            analysis.status = TrustStatus.VERIFIED
            analysis.flags.append("Writing style is broadly consistent with historical samples")

        coverage = min(1.0, analysis.baseline_word_count / 800)
        analysis.confidence = round(max(0.35, min(0.92, 0.45 + coverage * 0.35 + len(usable_history) * 0.03)), 2)
        analysis.details = {
            "current_profile": current_profile,
            "baseline_profile": baseline_profile,
        }

        return analysis

    @staticmethod
    def _word_count(text: str) -> int:
        return len(StylometricService.WORD_RE.findall(text.lower()))

    @staticmethod
    def _extract_profile(text: str) -> dict:
        lowered = text.lower()
        words = StylometricService.WORD_RE.findall(lowered)
        word_count = max(1, len(words))
        sentences = [segment.strip() for segment in StylometricService.SENTENCE_RE.split(text) if segment.strip()]
        sentence_count = max(1, len(sentences))
        punctuation_count = sum(1 for char in text if char in ".,;:!?-'\"()")
        unique_words = len(set(words))
        function_count = sum(1 for word in words if word in StylometricService.FUNCTION_WORDS)

        avg_sentence_length = word_count / sentence_count
        avg_word_length = sum(len(word) for word in words) / word_count
        type_token_ratio = unique_words / word_count
        punctuation_density = punctuation_count / max(1, len(text))
        function_word_ratio = function_count / word_count

        return {
            "avg_sentence_length": round(avg_sentence_length, 4),
            "avg_word_length": round(avg_word_length, 4),
            "type_token_ratio": round(type_token_ratio, 4),
            "punctuation_density": round(punctuation_density, 4),
            "function_word_ratio": round(function_word_ratio, 4),
        }

    @staticmethod
    def _average_profiles(profiles: list[dict]) -> dict:
        keys = profiles[0].keys()
        return {
            key: round(sum(profile[key] for profile in profiles) / len(profiles), 4)
            for key in keys
        }

    @staticmethod
    def _profile_distance(current: dict, baseline: dict) -> float:
        weighted_keys = {
            "avg_sentence_length": 1.0,
            "avg_word_length": 0.8,
            "type_token_ratio": 1.0,
            "punctuation_density": 0.7,
            "function_word_ratio": 1.1,
        }
        weighted_sum = 0.0
        weight_total = 0.0

        for key, weight in weighted_keys.items():
            baseline_value = max(0.0001, baseline[key])
            delta = abs(current[key] - baseline[key]) / baseline_value
            bounded_delta = min(1.5, delta)
            weighted_sum += bounded_delta * weight
            weight_total += weight

        return weighted_sum / max(1.0, weight_total)
