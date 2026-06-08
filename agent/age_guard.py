"""
GuardianLens — Age Guard
Enforces age-appropriate content filtering and intercepts
harmful redirects targeting minors.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agent.content_analyzer import AnalysisResult, ThreatLevel, ThreatType
from agent.url_scanner import URLRisk, URLScanResult


class AgeGroup(str, Enum):
    CHILD = "child"          # under 13
    TEEN = "teen"            # 13–17
    ADULT = "adult"          # 18+
    UNKNOWN = "unknown"      # age not provided


@dataclass
class GuardDecision:
    allowed: bool
    age_group: AgeGroup
    reason: str
    alert_guardian: bool
    alert_message: str
    content_blocked: bool
    url_blocked: bool


def _classify_age(age: Optional[int]) -> AgeGroup:
    if age is None:
        return AgeGroup.UNKNOWN
    if age < 13:
        return AgeGroup.CHILD
    if age < 18:
        return AgeGroup.TEEN
    return AgeGroup.ADULT


# ── Content guard ─────────────────────────────────────────────────────────────

def guard_content(
    analysis: AnalysisResult,
    age: Optional[int] = None,
) -> GuardDecision:
    """
    Apply age-appropriate filtering to a content analysis result.

    Args:
        analysis: Result from content_analyzer.analyze_content()
        age: User's age (None = unknown)

    Returns:
        GuardDecision with allow/block decision and guardian alert details.
    """
    age_group = _classify_age(age)
    is_minor = age_group in (AgeGroup.CHILD, AgeGroup.TEEN, AgeGroup.UNKNOWN)

    # Adults: only block CRITICAL threats
    if age_group == AgeGroup.ADULT:
        if analysis.threat_level == ThreatLevel.CRITICAL:
            return GuardDecision(
                allowed=False,
                age_group=age_group,
                reason=f"Critical threat detected: {analysis.threat_type.value}",
                alert_guardian=False,
                alert_message="",
                content_blocked=True,
                url_blocked=False,
            )
        return GuardDecision(
            allowed=True,
            age_group=age_group,
            reason="Content permitted for adults.",
            alert_guardian=False,
            alert_message="",
            content_blocked=False,
            url_blocked=False,
        )

    # Minors: strict mode
    blocked_threat_types = {
        ThreatType.GROOMING,
        ThreatType.ADULT_CONTENT,
        ThreatType.ILLEGAL_CONTENT,
        ThreatType.PHISHING,
        ThreatType.HARASSMENT,
    }

    should_block = (
        analysis.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)
        or analysis.threat_type in blocked_threat_types
        or not analysis.is_safe_for_minors
    )

    alert_guardian = should_block or analysis.threat_level == ThreatLevel.MEDIUM

    alert_message = ""
    if alert_guardian:
        threat_label = analysis.threat_type.value.replace("_", " ").title()
        age_label = f"age {age}" if age else "a minor (age unknown)"
        alert_message = (
            f"⚠️ GuardianLens Alert: {threat_label} content was "
            f"{'blocked' if should_block else 'flagged'} for {age_label}. "
            f"Confidence: {analysis.confidence:.0%}. "
            f"Action taken: {analysis.recommended_action.replace('_', ' ')}."
        )

    return GuardDecision(
        allowed=not should_block,
        age_group=age_group,
        reason=(
            f"Blocked: {analysis.explanation}"
            if should_block
            else "Content permitted."
        ),
        alert_guardian=alert_guardian,
        alert_message=alert_message,
        content_blocked=should_block,
        url_blocked=False,
    )


# ── URL guard ─────────────────────────────────────────────────────────────────

def guard_url(
    scan: URLScanResult,
    age: Optional[int] = None,
) -> GuardDecision:
    """
    Apply age-appropriate filtering to a URL scan result.

    Args:
        scan: Result from url_scanner.scan_url()
        age: User's age (None = unknown)

    Returns:
        GuardDecision with allow/block decision and guardian alert details.
    """
    age_group = _classify_age(age)
    is_minor = age_group in (AgeGroup.CHILD, AgeGroup.TEEN, AgeGroup.UNKNOWN)

    should_block = (
        scan.risk == URLRisk.BLOCKED
        or (is_minor and scan.risk in (URLRisk.DANGEROUS, URLRisk.BLOCKED))
        or (is_minor and not scan.is_safe_for_minors)
    )

    alert_guardian = should_block or scan.risk == URLRisk.SUSPICIOUS

    alert_message = ""
    if alert_guardian and is_minor:
        age_label = f"age {age}" if age else "a minor (age unknown)"
        alert_message = (
            f"⚠️ GuardianLens URL Alert: A link was "
            f"{'blocked' if should_block else 'flagged as suspicious'} "
            f"for {age_label}.\n"
            f"URL: {scan.url}\n"
            f"Risk level: {scan.risk.value.upper()}\n"
            f"Reasons: {'; '.join(scan.reasons)}"
        )

    return GuardDecision(
        allowed=not should_block,
        age_group=age_group,
        reason=(
            f"URL blocked: {'; '.join(scan.reasons)}"
            if should_block
            else "URL appears safe."
        ),
        alert_guardian=alert_guardian,
        alert_message=alert_message,
        content_blocked=False,
        url_blocked=should_block,
    )


# ── Combined guard ────────────────────────────────────────────────────────────

def full_guard(
    text: Optional[str] = None,
    url: Optional[str] = None,
    age: Optional[int] = None,
) -> dict:
    """
    Run both content and URL guards in one call.
    Returns a combined decision dict for the API.
    """
    from agent.content_analyzer import analyze_content
    from agent.url_scanner import scan_url

    results = {}

    if text:
        analysis = analyze_content(text, user_age=age)
        content_decision = guard_content(analysis, age)
        results["content"] = {
            "analysis": analysis,
            "decision": content_decision,
        }

    if url:
        scan = scan_url(url, user_age=age)
        url_decision = guard_url(scan, age)
        results["url"] = {
            "scan": scan,
            "decision": url_decision,
        }

    return results
