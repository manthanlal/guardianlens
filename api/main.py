"""
GuardianLens — FastAPI Backend
Main API entry point. Serves the dashboard and exposes
safety scanning endpoints.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

load_dotenv()

from agent.content_analyzer import analyze_content
from agent.url_scanner import scan_url
from agent.age_guard import full_guard, guard_content, guard_url
from agent.report_generator import generate_report, log_event, report_to_dict

app = FastAPI(
    title="GuardianLens API",
    description="AI-powered social media safety agent for cybercrime prevention and minor protection.",
    version="1.0.0",
)

# ── Request / Response models ─────────────────────────────────────────────────

class ContentScanRequest(BaseModel):
    text: str
    user_age: Optional[int] = None
    context: Optional[str] = None


class URLScanRequest(BaseModel):
    url: str
    user_age: Optional[int] = None


class FullScanRequest(BaseModel):
    text: Optional[str] = None
    url: Optional[str] = None
    user_age: Optional[int] = None


class ReportRequest(BaseModel):
    child_name: str = "Your child"
    days: int = 7


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the guardian dashboard."""
    dashboard_path = Path(__file__).parent.parent / "ui" / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>GuardianLens</h1><p>Dashboard not found. Check ui/dashboard.html</p>")


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "GuardianLens", "version": "1.0.0"}


@app.post("/scan/content")
async def scan_content(request: ContentScanRequest):
    """
    Analyze text content for safety threats.
    Returns threat level, type, confidence, and recommended action.
    """
    if not request.text:
        raise HTTPException(status_code=400, detail="Text is required.")

    analysis = analyze_content(
        text=request.text,
        user_age=request.user_age,
        context=request.context,
    )
    decision = guard_content(analysis, age=request.user_age)

    # Log the event if a threat was detected
    if analysis.threat_level.value not in ("safe", "low"):
        log_event(
            event_type="content_blocked" if decision.content_blocked else "content_flagged",
            threat_type=analysis.threat_type.value,
            threat_level=analysis.threat_level.value,
            description=analysis.explanation,
            action_taken=analysis.recommended_action,
        )

    return {
        "threat_level": analysis.threat_level.value,
        "threat_type": analysis.threat_type.value,
        "confidence": analysis.confidence,
        "explanation": analysis.explanation,
        "flagged_phrases": analysis.flagged_phrases,
        "recommended_action": analysis.recommended_action,
        "is_safe_for_minors": analysis.is_safe_for_minors,
        "guard_decision": {
            "allowed": decision.allowed,
            "age_group": decision.age_group.value,
            "reason": decision.reason,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        },
    }


@app.post("/scan/url")
async def scan_url_endpoint(request: URLScanRequest):
    """
    Scan a URL for phishing, malware, adult content, and unsafe redirects.
    """
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required.")

    scan = scan_url(url=request.url, user_age=request.user_age)
    decision = guard_url(scan, age=request.user_age)

    if scan.risk.value not in ("safe",):
        log_event(
            event_type="url_blocked" if decision.url_blocked else "url_flagged",
            threat_type=scan.risk.value,
            threat_level=scan.risk.value,
            description="; ".join(scan.reasons),
            action_taken=scan.recommended_action,
        )

    return {
        "url": scan.url,
        "risk": scan.risk.value,
        "confidence": scan.confidence,
        "reasons": scan.reasons,
        "final_destination": scan.final_destination,
        "is_safe_for_minors": scan.is_safe_for_minors,
        "recommended_action": scan.recommended_action,
        "guard_decision": {
            "allowed": decision.allowed,
            "age_group": decision.age_group.value,
            "reason": decision.reason,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        },
    }


@app.post("/scan/full")
async def full_scan(request: FullScanRequest):
    """
    Run both content and URL analysis in one call.
    Use this for scanning social media posts that may contain both text and links.
    """
    if not request.text and not request.url:
        raise HTTPException(status_code=400, detail="Provide at least text or url.")

    results = full_guard(
        text=request.text,
        url=request.url,
        age=request.user_age,
    )

    response = {}

    if "content" in results:
        analysis = results["content"]["analysis"]
        decision = results["content"]["decision"]
        response["content"] = {
            "threat_level": analysis.threat_level.value,
            "threat_type": analysis.threat_type.value,
            "confidence": analysis.confidence,
            "explanation": analysis.explanation,
            "allowed": decision.allowed,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        }

    if "url" in results:
        scan = results["url"]["scan"]
        decision = results["url"]["decision"]
        response["url"] = {
            "risk": scan.risk.value,
            "confidence": scan.confidence,
            "reasons": scan.reasons,
            "allowed": decision.allowed,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        }

    return response


@app.post("/report")
async def get_report(request: ReportRequest):
    """Generate a safety report for the past N days."""
    report = generate_report(
        child_name=request.child_name,
        days=request.days,
    )
    return report_to_dict(report)


@app.get("/report/summary")
async def quick_summary():
    """Quick 7-day summary for the dashboard."""
    report = generate_report(child_name="User", days=7)
    return {
        "total_events": report.total_events,
        "blocked_count": report.blocked_count,
        "flagged_count": report.flagged_count,
        "overall_risk": report.overall_risk,
        "top_threats": report.top_threats,
        "recommendations": report.recommendations,
    }
