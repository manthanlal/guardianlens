"""
GuardianLens — URL Scanner
Checks links for phishing, malware, illegal redirects,
and unsafe destinations before the user clicks.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import httpx
import tldextract
import validators


class URLRisk(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


@dataclass
class URLScanResult:
    url: str
    risk: URLRisk
    confidence: float
    reasons: list[str]
    final_destination: str | None   # after redirect resolution
    is_safe_for_minors: bool
    recommended_action: str


# ── Known bad TLDs & suspicious patterns ────────────────────────────────────

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # free, abused heavily
    ".xyz", ".top", ".click", ".download",
    ".porn", ".adult", ".sex",            # adult TLDs
}

ADULT_DOMAINS = {
    "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com",
    "youporn.com", "tube8.com", "spankbang.com",
}

KNOWN_PHISHING_KEYWORDS = [
    "login-verify", "account-suspended", "secure-update",
    "paypal-alert", "bank-confirm", "click-to-verify",
    "prize-claim", "free-gift", "password-reset-alert",
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "rb.gy", "shorturl.at",
}

IP_URL_PATTERN = re.compile(
    r"https?://(\d{1,3}\.){3}\d{1,3}"
)


# ── Helpers ──────────────────────────────────────────────────────────────────

def _is_valid_url(url: str) -> bool:
    return validators.url(url) is True


def _extract_domain(url: str) -> str:
    extracted = tldextract.extract(url)
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _get_tld(url: str) -> str:
    extracted = tldextract.extract(url)
    return f".{extracted.suffix}".lower()


def _resolve_redirects(url: str, timeout: int = 5) -> str:
    """Follow redirects and return the final URL."""
    try:
        with httpx.Client(follow_redirects=True, timeout=timeout) as client:
            response = client.head(url)
            return str(response.url)
    except Exception:
        return url   # return original if we can't resolve


def _check_google_safe_browsing(url: str) -> bool:
    """
    Check URL against Google Safe Browsing API.
    Returns True if the URL is flagged as unsafe.
    """
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "guardianlens", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        with httpx.Client(timeout=5) as client:
            response = client.post(endpoint, json=payload)
            data = response.json()
            return bool(data.get("matches"))
    except Exception:
        return False


# ── Main scan function ───────────────────────────────────────────────────────

def scan_url(url: str, user_age: int | None = None) -> URLScanResult:
    """
    Scan a URL for safety threats.

    Args:
        url: The URL to scan.
        user_age: Age of the user clicking the link (enables minor protection).

    Returns:
        URLScanResult with risk level and recommended action.
    """
    reasons: list[str] = []
    risk_score: float = 0.0
    is_minor = user_age is not None and user_age < 18

    # Basic validation
    if not url or not url.strip():
        return URLScanResult(
            url=url, risk=URLRisk.SAFE, confidence=0.0,
            reasons=["No URL provided."], final_destination=None,
            is_safe_for_minors=True, recommended_action="allow",
        )

    if not _is_valid_url(url):
        reasons.append("URL format is invalid or malformed.")
        risk_score += 0.4

    domain = _extract_domain(url)
    tld = _get_tld(url)

    # IP-based URL (very suspicious)
    if IP_URL_PATTERN.match(url):
        reasons.append("URL uses a raw IP address instead of a domain name.")
        risk_score += 0.5

    # Suspicious TLD
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"Domain uses a high-risk TLD: {tld}")
        risk_score += 0.3

    # Adult domain — block for minors
    if domain in ADULT_DOMAINS:
        reasons.append(f"Domain is a known adult content site: {domain}")
        risk_score += 0.6 if not is_minor else 1.0

    # Phishing keywords in URL
    url_lower = url.lower()
    for keyword in KNOWN_PHISHING_KEYWORDS:
        if keyword in url_lower:
            reasons.append(f"URL contains phishing keyword: '{keyword}'")
            risk_score += 0.35

    # URL shortener — resolve and re-check
    final_destination = url
    if domain in SHORTENER_DOMAINS:
        reasons.append(f"URL uses a link shortener ({domain}). Resolving redirect...")
        final_destination = _resolve_redirects(url)
        if final_destination != url:
            reasons.append(f"Redirects to: {final_destination}")
            # Re-scan destination domain
            dest_domain = _extract_domain(final_destination)
            if dest_domain in ADULT_DOMAINS:
                reasons.append("Redirect destination is an adult content site.")
                risk_score += 0.7

    # Excessively long URL (common in phishing)
    if len(url) > 200:
        reasons.append("URL is unusually long — common in phishing attacks.")
        risk_score += 0.2

    # Multiple subdomains (e.g. paypal.secure.login.evil.com)
    subdomain_count = len(tldextract.extract(url).subdomain.split("."))
    if subdomain_count > 3:
        reasons.append(f"URL has {subdomain_count} subdomains — suspicious structure.")
        risk_score += 0.25

    # Google Safe Browsing API check
    if _check_google_safe_browsing(url):
        reasons.append("Flagged by Google Safe Browsing as dangerous.")
        risk_score += 0.8

    # Normalize risk score to 0–1
    confidence = min(1.0, risk_score)

    # Determine risk level
    if confidence < 0.2:
        risk = URLRisk.SAFE
    elif confidence < 0.45:
        risk = URLRisk.SUSPICIOUS
    elif confidence < 0.7:
        risk = URLRisk.DANGEROUS
    else:
        risk = URLRisk.BLOCKED

    # Minor override — any dangerous+ is blocked
    if is_minor and risk == URLRisk.DANGEROUS:
        risk = URLRisk.BLOCKED
        reasons.append("Escalated to BLOCKED: minor protection is active.")

    # Recommended action
    actions = {
        URLRisk.SAFE:       "allow",
        URLRisk.SUSPICIOUS: "warn_user_before_redirect",
        URLRisk.DANGEROUS:  "block_and_notify",
        URLRisk.BLOCKED:    "block_immediately_and_alert_guardian",
    }

    is_safe_for_minors = risk in (URLRisk.SAFE,) and domain not in ADULT_DOMAINS

    return URLScanResult(
        url=url,
        risk=risk,
        confidence=round(confidence, 3),
        reasons=reasons if reasons else ["No threats detected."],
        final_destination=final_destination if final_destination != url else None,
        is_safe_for_minors=is_safe_for_minors,
        recommended_action=actions[risk],
    )
