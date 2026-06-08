"""
GuardianLens — Report Generator
Generates weekly safety summary reports for parents and guardians.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional


@dataclass
class SafetyEvent:
    timestamp: datetime
    event_type: str          # "content_blocked", "url_blocked", "flagged"
    threat_type: str
    threat_level: str
    description: str
    action_taken: str


@dataclass
class SafetyReport:
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    child_name: str
    total_events: int
    blocked_count: int
    flagged_count: int
    top_threats: list[str]
    events: list[SafetyEvent]
    overall_risk: str        # "low", "moderate", "high"
    recommendations: list[str]
    summary_text: str


# ── In-memory event log (replace with DB in production) ──────────────────────

_event_log: list[SafetyEvent] = []


def log_event(
    event_type: str,
    threat_type: str,
    threat_level: str,
    description: str,
    action_taken: str,
) -> SafetyEvent:
    """Log a safety event for later reporting."""
    event = SafetyEvent(
        timestamp=datetime.utcnow(),
        event_type=event_type,
        threat_type=threat_type,
        threat_level=threat_level,
        description=description,
        action_taken=action_taken,
    )
    _event_log.append(event)
    return event


def get_events(days: int = 7) -> list[SafetyEvent]:
    """Return events from the last N days."""
    cutoff = datetime.utcnow() - timedelta(days=days)
    return [e for e in _event_log if e.timestamp >= cutoff]


def _overall_risk(blocked: int, flagged: int, total: int) -> str:
    if total == 0:
        return "low"
    ratio = blocked / max(total, 1)
    if ratio > 0.3 or blocked > 10:
        return "high"
    if ratio > 0.1 or blocked > 3:
        return "moderate"
    return "low"


def _build_recommendations(report: "SafetyReport") -> list[str]:
    recs = []
    if "grooming" in report.top_threats:
        recs.append("Consider reviewing your child's direct messages with unknown contacts.")
    if "phishing" in report.top_threats:
        recs.append("Talk to your child about not clicking links from unknown senders.")
    if "adult_content" in report.top_threats:
        recs.append("Enable stricter content filters on your child's device.")
    if report.overall_risk == "high":
        recs.append("High activity detected — consider a family conversation about online safety.")
    if not recs:
        recs.append("All looks good! Keep encouraging safe browsing habits.")
    return recs


# ── Main report function ──────────────────────────────────────────────────────

def generate_report(
    child_name: str = "Your child",
    days: int = 7,
) -> SafetyReport:
    """
    Generate a safety report for the past N days.

    Args:
        child_name: Name of the child/user being monitored.
        days: Number of days to include in the report (default: 7).

    Returns:
        SafetyReport with summary stats, events, and recommendations.
    """
    now = datetime.utcnow()
    period_start = now - timedelta(days=days)
    events = get_events(days=days)

    blocked = [e for e in events if "blocked" in e.event_type]
    flagged = [e for e in events if "flagged" in e.event_type]

    threat_counts: dict[str, int] = {}
    for e in events:
        threat_counts[e.threat_type] = threat_counts.get(e.threat_type, 0) + 1
    top_threats = sorted(threat_counts, key=threat_counts.get, reverse=True)[:3]  # type: ignore

    risk = _overall_risk(len(blocked), len(flagged), len(events))

    risk_emoji = {"low": "🟢", "moderate": "🟡", "high": "🔴"}.get(risk, "⚪")

    summary = (
        f"{risk_emoji} GuardianLens Weekly Report for {child_name}\n"
        f"Period: {period_start.strftime('%b %d')} – {now.strftime('%b %d, %Y')}\n\n"
        f"Total safety events: {len(events)}\n"
        f"Content/URLs blocked: {len(blocked)}\n"
        f"Items flagged for review: {len(flagged)}\n"
        f"Overall risk level: {risk.upper()}\n"
    )

    report = SafetyReport(
        generated_at=now,
        period_start=period_start,
        period_end=now,
        child_name=child_name,
        total_events=len(events),
        blocked_count=len(blocked),
        flagged_count=len(flagged),
        top_threats=top_threats,
        events=events,
        overall_risk=risk,
        recommendations=[],
        summary_text=summary,
    )
    report.recommendations = _build_recommendations(report)

    return report


def report_to_dict(report: SafetyReport) -> dict:
    """Serialize a SafetyReport to a JSON-friendly dict."""
    return {
        "generated_at": report.generated_at.isoformat(),
        "period_start": report.period_start.isoformat(),
        "period_end": report.period_end.isoformat(),
        "child_name": report.child_name,
        "total_events": report.total_events,
        "blocked_count": report.blocked_count,
        "flagged_count": report.flagged_count,
        "top_threats": report.top_threats,
        "overall_risk": report.overall_risk,
        "recommendations": report.recommendations,
        "summary_text": report.summary_text,
        "events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "threat_type": e.threat_type,
                "threat_level": e.threat_level,
                "description": e.description,
                "action_taken": e.action_taken,
            }
            for e in report.events
        ],
    }
