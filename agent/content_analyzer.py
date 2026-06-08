"""
GuardianLens — Content Analyzer
Analyzes text for cybercrime patterns, harmful content,
grooming language, hate speech, and harassment.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ThreatLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    NONE = "none"
    PHISHING = "phishing"
    GROOMING = "grooming"
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    SCAM = "scam"
    ILLEGAL_CONTENT = "illegal_content"
    ADULT_CONTENT = "adult_content"


@dataclass
class AnalysisResult:
    threat_level: ThreatLevel
    threat_type: ThreatType
    confidence: float          # 0.0 to 1.0
    explanation: str
    flagged_phrases: list[str]
    recommended_action: str
    is_safe_for_minors: bool


# ── Keyword pattern banks ────────────────────────────────────────────────────

PHISHING_PATTERNS = [
    r"\bclick here to verify\b",
    r"\baccount (suspended|locked|compromised)\b",
    r"\burgent.{0,20}(action|response|reply) required\b",
    r"\bconfirm your (password|credentials|details)\b",
    r"\bwon (a prize|lottery|reward)\b",
    r"\bsend (your|the) (otp|pin|password)\b",
    r"\bbank (details|account|transfer)\b",
]

GROOMING_PATTERNS = [
    r"\bdon't tell (your|anyone|parents|mom|dad)\b",
    r"\bkeep (this|it|our) (secret|between us)\b",
    r"\byou('re| are) (so )?(mature|special|different from other kids)\b",
    r"\bsend me (a |your )?(photo|pic|picture|video)\b",
    r"\bmeet (me|up|in person|offline)\b",
    r"\byou can trust me\b",
    r"\bi('ll| will) (buy|give|send) you\b",
]

HATE_SPEECH_PATTERNS = [
    r"\b(kill|eliminate|destroy|wipe out).{0,20}(all|every).{0,10}(people|group|race|religion)\b",
    r"\b(inferior|subhuman|vermin).{0,20}(people|race|group)\b",
]

HARASSMENT_PATTERNS = [
    r"\b(i('ll| will)|gonna|going to).{0,15}(find|hunt|get|hurt|destroy) you\b",
    r"\bkill yourself\b",
    r"\byou (should|deserve to) (die|suffer|rot)\b",
    r"\bwatch your back\b",
]

SCAM_PATTERNS = [
    r"\b(make|earn).{0,10}\$[\d,]+ (per day|a day|weekly|daily)\b",
    r"\binvest.{0,20}(bitcoin|crypto|guaranteed returns)\b",
    r"\bsend (money|cash|bitcoin).{0,20}(to receive|to get)\b",
    r"\bwork from home.{0,20}(no experience|easy money)\b",
]

ADULT_CONTENT_PATTERNS = [
    r"\b(explicit|nsfw|adult|xxx|18\+) content\b",
    r"\bonly ?fans\b",
    r"\bsexual(ly)? explicit\b",
]


def _scan_patterns(text: str, patterns: list[str]) -> list[str]:
    """Return matched phrases from a list of regex patterns."""
    found = []
    text_lower = text.lower()
    for pattern in patterns:
        matches = re.findall(pattern, text_lower)
        if not matches:
            continue
        if isinstance(matches[0], str):
            found.extend(matches)
        else:
            found.extend(m[0] for m in matches)
    return list(set(found))


def _score(matches: list[str], weight: float = 1.0) -> float:
    """Convert match count to a 0–1 confidence score."""
    if not matches:
        return 0.0
    return min(1.0, len(matches) * weight * 0.3)


# ── Main analysis function ───────────────────────────────────────────────────

def analyze_content(
    text: str,
    user_age: Optional[int] = None,
    context: Optional[str] = None,
) -> AnalysisResult:
    """
    Analyze text content for safety threats.

    Args:
        text: The message or content to analyze.
        user_age: Age of the recipient (if known). Enables minor protection.
        context: Optional context tag e.g. 'social_media', 'dm', 'comment'.

    Returns:
        AnalysisResult with threat level, type, confidence, and recommended action.
    """
    if not text or not text.strip():
        return AnalysisResult(
            threat_level=ThreatLevel.SAFE,
            threat_type=ThreatType.NONE,
            confidence=0.0,
            explanation="Empty content — nothing to analyze.",
            flagged_phrases=[],
            recommended_action="allow",
            is_safe_for_minors=True,
        )

    # Run all pattern scans
    phishing_hits   = _scan_patterns(text, PHISHING_PATTERNS)
    grooming_hits   = _scan_patterns(text, GROOMING_PATTERNS)
    hate_hits       = _scan_patterns(text, HATE_SPEECH_PATTERNS)
    harassment_hits = _scan_patterns(text, HARASSMENT_PATTERNS)
    scam_hits       = _scan_patterns(text, SCAM_PATTERNS)
    adult_hits      = _scan_patterns(text, ADULT_CONTENT_PATTERNS)

    # Score each category
    scores = {
        ThreatType.PHISHING:       (_score(phishing_hits, 1.2),   phishing_hits),
        ThreatType.GROOMING:       (_score(grooming_hits, 1.5),   grooming_hits),
        ThreatType.HATE_SPEECH:    (_score(hate_hits, 1.4),       hate_hits),
        ThreatType.HARASSMENT:     (_score(harassment_hits, 1.3), harassment_hits),
        ThreatType.SCAM:           (_score(scam_hits, 1.1),       scam_hits),
        ThreatType.ADULT_CONTENT:  (_score(adult_hits, 1.0),      adult_hits),
    }

    # Find dominant threat
    dominant_type = max(scores, key=lambda k: scores[k][0])
    confidence, flagged = scores[dominant_type]

    # Determine threat level
    if confidence == 0.0:
        level = ThreatLevel.SAFE
        dominant_type = ThreatType.NONE
    elif confidence < 0.3:
        level = ThreatLevel.LOW
    elif confidence < 0.5:
        level = ThreatLevel.MEDIUM
    elif confidence < 0.75:
        level = ThreatLevel.HIGH
    else:
        level = ThreatLevel.CRITICAL

    # Minor protection boost — escalate adult content for minors
    is_minor = user_age is not None and user_age < 18
    if is_minor and dominant_type == ThreatType.ADULT_CONTENT and confidence > 0.1:
        level = ThreatLevel.CRITICAL
        confidence = max(confidence, 0.9)

    is_safe_for_minors = (
        level in (ThreatLevel.SAFE, ThreatLevel.LOW)
        and dominant_type not in (ThreatType.ADULT_CONTENT, ThreatType.GROOMING, ThreatType.ILLEGAL_CONTENT)
    )

    # Build explanation
    explanations = {
        ThreatType.NONE:           "No threats detected. Content appears safe.",
        ThreatType.PHISHING:       "Content contains patterns consistent with phishing attempts.",
        ThreatType.GROOMING:       "Content contains grooming language targeting minors.",
        ThreatType.HATE_SPEECH:    "Content contains hate speech or incitement patterns.",
        ThreatType.HARASSMENT:     "Content contains harassment or threatening language.",
        ThreatType.SCAM:           "Content contains patterns consistent with financial scams.",
        ThreatType.ADULT_CONTENT:  "Content contains adult/explicit material.",
    }

    # Recommend action
    if level == ThreatLevel.SAFE:
        action = "allow"
    elif level == ThreatLevel.LOW:
        action = "flag_for_review"
    elif level == ThreatLevel.MEDIUM:
        action = "warn_user"
    elif level == ThreatLevel.HIGH:
        action = "block_and_notify_guardian"
    else:
        action = "block_immediately_and_alert"

    return AnalysisResult(
        threat_level=level,
        threat_type=dominant_type,
        confidence=round(confidence, 3),
        explanation=explanations[dominant_type],
        flagged_phrases=flagged,
        recommended_action=action,
        is_safe_for_minors=is_safe_for_minors,
    )