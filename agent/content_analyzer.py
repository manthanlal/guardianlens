"""
GuardianLens — Content Analyzer
Enhanced NLP safety scoring with:
- Expanded pattern banks covering more real-world threats
- Multi-threat detection (catches overlapping threat types)
- Context-aware scoring (DM context raises grooming score)
- Language normalization (handles l33tspeak, spacing tricks)
- Severity breakdown per threat type
"""

import re
from dataclasses import dataclass, field
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
    CYBERBULLYING = "cyberbullying"
    EXTREMISM = "extremism"


@dataclass
class ThreatDetail:
    threat_type: ThreatType
    confidence: float
    flagged_phrases: list[str]


@dataclass
class AnalysisResult:
    threat_level: ThreatLevel
    threat_type: ThreatType           # dominant threat
    confidence: float                  # 0.0 to 1.0
    explanation: str
    flagged_phrases: list[str]
    recommended_action: str
    is_safe_for_minors: bool
    all_threats: list[ThreatDetail] = field(default_factory=list)  # all detected threats
    context_flags: list[str] = field(default_factory=list)         # extra context warnings


# ── Keyword pattern banks ────────────────────────────────────────────────────

PHISHING_PATTERNS = [
    r"\bclick here to verify\b",
    r"\baccount (suspended|locked|compromised|disabled|restricted)\b",
    r"\burgent.{0,20}(action|response|reply|attention) required\b",
    r"\bconfirm your (password|credentials|details|identity|information)\b",
    r"\bwon (a prize|lottery|reward|giveaway|contest)\b",
    r"\bsend (your|the) (otp|otp code|pin|password|verification code)\b",
    r"\bbank (details|account|transfer|login|credentials)\b",
    r"\bverify (your|the) (account|identity|email|information)\b",
    r"\bupdate (your|billing|payment|credit card) (information|details|method)\b",
    r"\byour (account|subscription|access) (will be|is) (terminated|deleted|suspended)\b",
    r"\bsecurity (alert|warning|breach|issue) detected\b",
    r"\bunusual (activity|login|sign.?in) (detected|noticed|found)\b",
    r"\benter (your|the) (code|otp|pin|password) (below|here|now)\b",
    r"\blimited time (offer|access|opportunity)\b",
    r"\bact (now|immediately|fast|quickly) (or|to avoid)\b",
]

GROOMING_PATTERNS = [
    r"\bdon'?t tell (your|anyone|parents?|mom|dad|family|friends?|teachers?)\b",
    r"\bkeep (this|it|our|a) (secret|between us|just between)\b",
    r"\byou'?re? (so )?(mature|special|different|unlike other kids|advanced for your age)\b",
    r"\bsend me (a |your )?(photo|pic|picture|image|video|selfie|snap)\b",
    r"\bmeet (me|up|in person|offline|irl|somewhere)\b",
    r"\byou can trust me\b",
    r"\bi'?(?:ll| will) (buy|give|send|get) you\b",
    r"\bare you (home |alone|by yourself)\b",
    r"\bwhere (are|do) you (live|stay|go to school)\b",
    r"\bdo your parents? (know|check|monitor|watch)\b",
    r"\byou look (so )?(beautiful|cute|hot|sexy|attractive|pretty) (for your age)?\b",
    r"\bhow old (are you|r u)\b",
    r"\bdo you have (snapchat|snap|telegram|signal|whatsapp|kik|discord)\b",
    r"\blet'?s (talk|chat|video call|meet) (privately|in private|somewhere else|on another app)\b",
    r"\bi won'?t (hurt|tell|judge) you\b",
    r"\bno one (has to|needs to|will) know\b",
    r"\byou'?re? (not like|different from) (other|most) (kids|girls|boys|teenagers?)\b",
]

HATE_SPEECH_PATTERNS = [
    r"\b(kill|eliminate|destroy|wipe out|exterminate).{0,20}(all|every).{0,10}(people|group|race|religion|jews?|muslims?|christians?)\b",
    r"\b(inferior|subhuman|vermin|animals?|parasites?).{0,20}(people|race|group|community)\b",
    r"\b(go back to|get out of) (your country|where you came from|africa|mexico)\b",
    r"\b(white|black|brown|yellow).{0,10}(supremacy|power|pride)\b",
    r"\b(all|these|those) (muslims?|jews?|christians?|blacks?|whites?|immigrants?|foreigners?) (should|must|deserve to)\b",
    r"\b(ethnic|racial|religious) (cleansing|genocide|purge)\b",
]

HARASSMENT_PATTERNS = [
    r"\b(i'?(?:ll| will)|gonna|going to).{0,15}(find|hunt|track|locate|get|hurt|destroy|ruin|expose) you\b",
    r"\bkill (yourself|urself|ur self)\b",
    r"\byou (should|deserve to|ought to) (die|suffer|rot|disappear|end it)\b",
    r"\bwatch your (back|step)\b",
    r"\bi know (where you|your address|where you live|your school)\b",
    r"\byou'?re? (worthless|pathetic|disgusting|trash|garbage|useless|a waste)\b",
    r"\b(everyone|nobody) (hates?|despises?) you\b",
    r"\bno one (cares?|likes?|loves?) you\b",
    r"\byou'?re? (better off|should be) dead\b",
    r"\bgo (die|kill yourself|end yourself|delete yourself)\b",
]

CYBERBULLYING_PATTERNS = [
    r"\b(spread|share|post|send).{0,20}(rumor|lie|secret|photo|video).{0,20}(about|of) (you|them|her|him)\b",
    r"\beveryone (knows?|is saying|thinks?|is laughing).{0,20}(about|at) you\b",
    r"\byou'?re? (so |such a )?(loser|freak|weirdo|ugly|fat|stupid|dumb|idiot|moron)\b",
    r"\b(block|report|ignore).{0,10}(everyone|all your friends?)\b",
    r"\bno one (wants?|likes?) (you|to be your friend)\b",
]

SCAM_PATTERNS = [
    r"\b(make|earn).{0,10}\$[\d,]+\+? (per day|a day|weekly|daily|per hour|an hour)\b",
    r"\binvest.{0,20}(bitcoin|crypto|cryptocurrency|nft|guaranteed returns?|risk.?free)\b",
    r"\bsend (money|cash|bitcoin|crypto|gift cards?|itunes?).{0,20}(to receive|to get|and get back)\b",
    r"\bwork from home.{0,20}(no experience|easy money|guaranteed income|passive income)\b",
    r"\b(guaranteed|100%) (returns?|profit|income|money back)\b",
    r"\b(nigerian?|foreign) (prince|official|diplomat|minister).{0,30}(money|funds?|transfer|inheritance)\b",
    r"\byou'?ve? (been selected|won|are eligible).{0,20}(prize|reward|cash|grant)\b",
    r"\bpay (a small|the) (fee|processing fee|tax|charge) (to|and) (receive|claim|unlock)\b",
    r"\b(gift card|itunes? card|google play card).{0,20}(payment|pay|send)\b",
    r"\bdouble (your|the) (money|investment|bitcoin|crypto)\b",
]

ADULT_CONTENT_PATTERNS = [
    r"\b(explicit|nsfw|adult|xxx|18\+|x.rated) (content|material|video|photo|image)\b",
    r"\bonly ?fans?\b",
    r"\bsexual(ly)? explicit\b",
    r"\b(nude|naked|nudes).{0,10}(photo|pic|video|image|selfie)\b",
    r"\b(porn|pornography|pornographic)\b",
    r"\bsexting\b",
    r"\b(erotic|sexual) (content|material|roleplay|rp)\b",
]

EXTREMISM_PATTERNS = [
    r"\b(jihad|holy war).{0,20}(against|kill|attack|destroy)\b",
    r"\b(attack|bomb|shoot|kill).{0,20}(school|church|mosque|synagogue|government|police)\b",
    r"\b(join|support|follow).{0,20}(isis|isil|al.?qaeda|taliban|terrorist)\b",
    r"\b(radicalize|recruit).{0,20}(youth|young|kids?|children)\b",
    r"\b(mass (shooting|attack|casualty)|domestic terrorism)\b",
]

# ── Normalizer ───────────────────────────────────────────────────────────────

def _normalize(text: str) -> str:
    """
    Normalize text to catch obfuscation tricks:
    - l33tspeak: @ → a, 3 → e, 0 → o, 1 → i
    - Extra spaces between letters
    - Repeated punctuation
    """
    text = text.lower()
    # l33tspeak substitutions
    replacements = {
        '@': 'a', '3': 'e', '0': 'o', '1': 'i', '$': 's',
        '!': 'i', '5': 's', '7': 't', '+': 't',
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    # Remove extra spaces between individual letters (e.g. "k i l l")
    text = re.sub(r'(?<=[a-z]) (?=[a-z])', '', text)
    # Collapse repeated punctuation
    text = re.sub(r'[!?.,]{2,}', '.', text)
    return text


def _scan_patterns(text: str, patterns: list[str]) -> list[str]:
    """Return matched phrases from a list of regex patterns."""
    found = []
    text_lower = text.lower()
    text_normalized = _normalize(text)

    for pattern in patterns:
        for t in (text_lower, text_normalized):
            matches = re.findall(pattern, t)
            if not matches:
                continue
            if isinstance(matches[0], str):
                found.extend(matches)
            else:
                found.extend(m[0] for m in matches if m)

    return list(set(f.strip() for f in found if f.strip()))


def _score(matches: list[str], weight: float = 1.0) -> float:
    """Convert match count to a 0–1 confidence score."""
    if not matches:
        return 0.0
    # Diminishing returns: 1 hit → 0.3, 2 → 0.5, 3 → 0.65, 4+ → 0.75+
    base = min(1.0, 0.25 + (len(matches) - 1) * 0.15)
    return min(1.0, round(base * weight, 3))


# ── Context multipliers ───────────────────────────────────────────────────────

CONTEXT_WEIGHTS = {
    "dm":           {"grooming": 1.4, "harassment": 1.2},
    "direct_message": {"grooming": 1.4, "harassment": 1.2},
    "comment":      {"cyberbullying": 1.3, "hate_speech": 1.2},
    "social_media": {"scam": 1.2, "phishing": 1.1},
    "email":        {"phishing": 1.4, "scam": 1.3},
    "chat":         {"grooming": 1.2, "harassment": 1.1},
}


def _apply_context(
    scores: dict,
    context: Optional[str],
) -> dict:
    """Boost threat scores based on message context."""
    if not context:
        return scores
    ctx = context.lower()
    weights = CONTEXT_WEIGHTS.get(ctx, {})
    for threat_key, multiplier in weights.items():
        for threat_type in scores:
            if threat_type.value == threat_key:
                old_score, hits = scores[threat_type]
                scores[threat_type] = (min(1.0, old_score * multiplier), hits)
    return scores


# ── Main analysis function ────────────────────────────────────────────────────

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
        context: Optional context tag e.g. 'dm', 'email', 'social_media', 'comment'.

    Returns:
        AnalysisResult with threat level, type, confidence, and full threat breakdown.
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
    hits = {
        ThreatType.PHISHING:      _scan_patterns(text, PHISHING_PATTERNS),
        ThreatType.GROOMING:      _scan_patterns(text, GROOMING_PATTERNS),
        ThreatType.HATE_SPEECH:   _scan_patterns(text, HATE_SPEECH_PATTERNS),
        ThreatType.HARASSMENT:    _scan_patterns(text, HARASSMENT_PATTERNS),
        ThreatType.CYBERBULLYING: _scan_patterns(text, CYBERBULLYING_PATTERNS),
        ThreatType.SCAM:          _scan_patterns(text, SCAM_PATTERNS),
        ThreatType.ADULT_CONTENT: _scan_patterns(text, ADULT_CONTENT_PATTERNS),
        ThreatType.EXTREMISM:     _scan_patterns(text, EXTREMISM_PATTERNS),
    }

    # Score weights per threat type (higher = more dangerous)
    weights = {
        ThreatType.PHISHING:      1.2,
        ThreatType.GROOMING:      1.6,   # highest — targeting minors
        ThreatType.HATE_SPEECH:   1.4,
        ThreatType.HARASSMENT:    1.3,
        ThreatType.CYBERBULLYING: 1.2,
        ThreatType.SCAM:          1.1,
        ThreatType.ADULT_CONTENT: 1.0,
        ThreatType.EXTREMISM:     1.5,
    }

    scores = {
        t: (_score(hits[t], weights[t]), hits[t])
        for t in hits
    }

    # Apply context multipliers
    scores = _apply_context(scores, context)

    # Build full threat list (all non-zero threats)
    all_threats = [
        ThreatDetail(
            threat_type=t,
            confidence=round(scores[t][0], 3),
            flagged_phrases=scores[t][1],
        )
        for t in scores if scores[t][0] > 0
    ]
    all_threats.sort(key=lambda x: x.confidence, reverse=True)

    # Dominant threat
    dominant_type = max(scores, key=lambda k: scores[k][0])
    confidence, flagged = scores[dominant_type]

    # Determine threat level
    if confidence == 0.0:
        level = ThreatLevel.SAFE
        dominant_type = ThreatType.NONE
    elif confidence < 0.25:
        level = ThreatLevel.LOW
    elif confidence < 0.45:
        level = ThreatLevel.MEDIUM
    elif confidence < 0.70:
        level = ThreatLevel.HIGH
    else:
        level = ThreatLevel.CRITICAL

    # Minor protection — escalate for dangerous content types
    is_minor = user_age is not None and user_age < 18
    minor_escalate_types = {
        ThreatType.ADULT_CONTENT,
        ThreatType.GROOMING,
        ThreatType.EXTREMISM,
        ThreatType.ILLEGAL_CONTENT,
    }
    if is_minor and dominant_type in minor_escalate_types and confidence > 0.1:
        level = ThreatLevel.CRITICAL
        confidence = max(confidence, 0.88)

    # Context flags (extra warnings for the UI)
    context_flags = []
    if len(all_threats) > 1:
        context_flags.append(
            f"Multiple threat types detected: {', '.join(t.threat_type.value for t in all_threats)}"
        )
    if is_minor and any(t.threat_type == ThreatType.GROOMING for t in all_threats):
        context_flags.append("⚠️ Grooming indicators detected — guardian alert recommended immediately.")
    if dominant_type == ThreatType.EXTREMISM:
        context_flags.append("⚠️ Extremist content — consider reporting to authorities.")

    is_safe_for_minors = (
        level in (ThreatLevel.SAFE, ThreatLevel.LOW)
        and dominant_type not in (
            ThreatType.ADULT_CONTENT, ThreatType.GROOMING,
            ThreatType.ILLEGAL_CONTENT, ThreatType.EXTREMISM,
        )
    )

    explanations = {
        ThreatType.NONE:          "No threats detected. Content appears safe.",
        ThreatType.PHISHING:      "Content contains patterns consistent with phishing attempts targeting credentials or personal data.",
        ThreatType.GROOMING:      "Content contains grooming language — patterns used to build inappropriate trust with minors.",
        ThreatType.HATE_SPEECH:   "Content contains hate speech or incitement targeting a group based on identity.",
        ThreatType.HARASSMENT:    "Content contains harassment, threats, or language designed to intimidate.",
        ThreatType.CYBERBULLYING: "Content contains cyberbullying patterns designed to humiliate or isolate.",
        ThreatType.SCAM:          "Content contains patterns consistent with financial scams or fraud.",
        ThreatType.ADULT_CONTENT: "Content contains adult or explicit material.",
        ThreatType.ILLEGAL_CONTENT: "Content references or promotes illegal activity.",
        ThreatType.EXTREMISM:     "Content contains extremist or radicalisation patterns.",
    }

    actions = {
        ThreatLevel.SAFE:     "allow",
        ThreatLevel.LOW:      "flag_for_review",
        ThreatLevel.MEDIUM:   "warn_user",
        ThreatLevel.HIGH:     "block_and_notify_guardian",
        ThreatLevel.CRITICAL: "block_immediately_and_alert",
    }

    return AnalysisResult(
        threat_level=level,
        threat_type=dominant_type,
        confidence=round(confidence, 3),
        explanation=explanations.get(dominant_type, "Unknown threat type."),
        flagged_phrases=flagged,
        recommended_action=actions[level],
        is_safe_for_minors=is_safe_for_minors,
        all_threats=all_threats,
        context_flags=context_flags,
    )
