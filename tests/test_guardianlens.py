"""
GuardianLens — Tests
Run with: pytest tests/ -v
"""

import pytest
from agent.content_analyzer import analyze_content, ThreatLevel, ThreatType
from agent.url_scanner import scan_url, URLRisk
from agent.age_guard import guard_content, guard_url, AgeGroup


# ── Content Analyzer Tests ────────────────────────────────────────────────────

class TestContentAnalyzer:

    def test_safe_content(self):
        result = analyze_content("Hello, how are you today?")
        assert result.threat_level == ThreatLevel.SAFE
        assert result.threat_type == ThreatType.NONE
        assert result.is_safe_for_minors is True

    def test_phishing_detected(self):
        result = analyze_content(
            "Your account has been suspended. Click here to verify your credentials immediately."
        )
        assert result.threat_type == ThreatType.PHISHING
        assert result.threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def test_grooming_detected(self):
        result = analyze_content(
            "Don't tell your parents about this, keep it between us. You're so mature for your age."
        )
        assert result.threat_type == ThreatType.GROOMING
        assert result.is_safe_for_minors is False

    def test_scam_detected(self):
        result = analyze_content(
            "Earn $5000 per day working from home! No experience needed. Send money to receive your starter kit."
        )
        assert result.threat_type == ThreatType.SCAM

    def test_adult_content_for_minor(self):
        result = analyze_content("Explicit adult content 18+", user_age=14)
        assert result.threat_type == ThreatType.ADULT_CONTENT
        assert result.threat_level == ThreatLevel.CRITICAL
        assert result.is_safe_for_minors is False

    def test_empty_content(self):
        result = analyze_content("")
        assert result.threat_level == ThreatLevel.SAFE

    def test_recommended_action_for_critical(self):
        result = analyze_content(
            "Don't tell your mom. Keep this between us. Send me your photo.",
            user_age=12
        )
        assert result.recommended_action in (
            "block_and_notify_guardian", "block_immediately_and_alert"
        )


# ── URL Scanner Tests ─────────────────────────────────────────────────────────

class TestURLScanner:

    def test_valid_safe_url(self):
        result = scan_url("https://www.google.com")
        assert result.risk in (URLRisk.SAFE, URLRisk.SUSPICIOUS)

    def test_invalid_url(self):
        result = scan_url("not-a-url-at-all")
        assert result.risk != URLRisk.SAFE

    def test_ip_based_url(self):
        result = scan_url("http://192.168.1.1/login")
        assert result.risk in (URLRisk.SUSPICIOUS, URLRisk.DANGEROUS, URLRisk.BLOCKED)
        assert any("IP" in r for r in result.reasons)

    def test_suspicious_tld(self):
        result = scan_url("https://freeprize.tk/claim")
        assert result.risk in (URLRisk.SUSPICIOUS, URLRisk.DANGEROUS, URLRisk.BLOCKED)

    def test_phishing_keyword_in_url(self):
        result = scan_url("https://paypal-alert.com/account-suspended/verify")
        assert result.risk in (URLRisk.SUSPICIOUS, URLRisk.DANGEROUS, URLRisk.BLOCKED)

    def test_adult_domain_blocked_for_minor(self):
        result = scan_url("https://pornhub.com", user_age=15)
        assert result.risk == URLRisk.BLOCKED
        assert result.is_safe_for_minors is False

    def test_empty_url(self):
        result = scan_url("")
        assert result.risk == URLRisk.SAFE


# ── Age Guard Tests ───────────────────────────────────────────────────────────

class TestAgeGuard:

    def test_adult_allowed_medium_threat(self):
        analysis = analyze_content("Click here to verify your account.", user_age=25)
        decision = guard_content(analysis, age=25)
        assert decision.age_group == AgeGroup.ADULT

    def test_child_blocked_grooming(self):
        analysis = analyze_content(
            "Don't tell your parents. Keep it between us. You're so mature.",
            user_age=11
        )
        decision = guard_content(analysis, age=11)
        assert decision.allowed is False
        assert decision.alert_guardian is True
        assert decision.age_group == AgeGroup.CHILD

    def test_teen_blocked_adult_content(self):
        analysis = analyze_content("Explicit adult content 18+", user_age=16)
        decision = guard_content(analysis, age=16)
        assert decision.allowed is False
        assert decision.age_group == AgeGroup.TEEN

    def test_guardian_alert_message_populated(self):
        analysis = analyze_content(
            "Don't tell your parents. Send me your photo.",
            user_age=13
        )
        decision = guard_content(analysis, age=13)
        if decision.alert_guardian:
            assert len(decision.alert_message) > 0

    def test_safe_content_allowed_for_child(self):
        analysis = analyze_content("Let's learn about dinosaurs!", user_age=8)
        decision = guard_content(analysis, age=8)
        assert decision.allowed is True
