import json
import re
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from pathlib import Path


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_SCORES = {
    Severity.LOW: 0.25,
    Severity.MEDIUM: 0.5,
    Severity.HIGH: 0.75,
    Severity.CRITICAL: 1.0,
}


@dataclass
class DetectionResult:
    is_injection: bool
    confidence: float
    matched_patterns: list[str] = field(default_factory=list)
    matched_categories: list[str] = field(default_factory=list)
    severity: Severity = Severity.LOW

    def to_dict(self) -> dict:
        return {
            "is_injection": self.is_injection,
            "confidence": self.confidence,
            "matched_patterns": self.matched_patterns,
            "matched_categories": self.matched_categories,
            "severity": self.severity.value,
        }


@lru_cache(maxsize=1)
def _load_patterns(patterns_path: Path) -> dict:
    if not patterns_path.exists():
        return {}
    try:
        return json.loads(patterns_path.read_text())
    except (json.JSONDecodeError, IOError):
        return {}


class InjectionDetector:
    def __init__(self, patterns_path: Path | None = None):
        if patterns_path is None:
            patterns_path = Path(__file__).parent / "injection_patterns.json"
        self.patterns_path = patterns_path
        self._compiled_patterns: dict[str, list[tuple[re.Pattern, str]]] = {}
        self._severities: dict[str, Severity] = {}
        self._load_and_compile()

    def _load_and_compile(self) -> None:
        raw_patterns = _load_patterns(self.patterns_path)

        for category, data in raw_patterns.items():
            severity_str = data.get("severity", "medium")
            self._severities[category] = Severity(severity_str)

            compiled = []
            for pattern in data.get("patterns", []):
                try:
                    compiled.append((re.compile(pattern, re.IGNORECASE), pattern))
                except re.error:
                    continue
            self._compiled_patterns[category] = compiled

    def detect(self, text: str) -> DetectionResult:
        if not text or not self._compiled_patterns:
            return DetectionResult(is_injection=False, confidence=0.0)

        text_lower = text.lower()
        matched_patterns: list[str] = []
        matched_categories: list[str] = []
        max_severity = Severity.LOW
        category_hits: dict[str, int] = {}

        for category, patterns in self._compiled_patterns.items():
            for compiled_pattern, raw_pattern in patterns:
                if compiled_pattern.search(text_lower):
                    matched_patterns.append(raw_pattern)
                    if category not in matched_categories:
                        matched_categories.append(category)
                    category_hits[category] = category_hits.get(category, 0) + 1

                    cat_severity = self._severities.get(category, Severity.MEDIUM)
                    if SEVERITY_SCORES[cat_severity] > SEVERITY_SCORES[max_severity]:
                        max_severity = cat_severity

        if not matched_patterns:
            return DetectionResult(is_injection=False, confidence=0.0)

        confidence = self._calculate_confidence(
            matched_patterns, matched_categories, category_hits, max_severity
        )

        return DetectionResult(
            is_injection=True,
            confidence=confidence,
            matched_patterns=matched_patterns,
            matched_categories=matched_categories,
            severity=max_severity,
        )

    def _calculate_confidence(
        self,
        matched_patterns: list[str],
        matched_categories: list[str],
        category_hits: dict[str, int],
        max_severity: Severity,
    ) -> float:
        base_score = SEVERITY_SCORES[max_severity]
        pattern_bonus = min(0.2, len(matched_patterns) * 0.05)
        category_bonus = min(0.15, (len(matched_categories) - 1) * 0.05)

        confidence = base_score + pattern_bonus + category_bonus
        return min(1.0, round(confidence, 2))

    def check_payload(self, payload: dict) -> DetectionResult:
        texts_to_check: list[str] = []

        for msg in payload.get("messages", []):
            content = msg.get("content", "")
            if isinstance(content, str):
                texts_to_check.append(content)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text":
                        texts_to_check.append(part.get("text", ""))

        combined_text = " ".join(texts_to_check)
        return self.detect(combined_text)
