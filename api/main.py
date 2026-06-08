"""
GuardianLens — FastAPI Backend
New in v3:
  - /mcp endpoint — MCP protocol handler for Foundry IQ agents
  - /foundry/status — Foundry IQ connection status
  - /foundry/enrich — manually enrich any scan with Foundry IQ
  - All scans now auto-enrich with Foundry IQ when configured
"""

import os
import json
from pathlib import Path
from datetime import datetime
from collections import defaultdict

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

load_dotenv()

from agent.content_analyzer import analyze_content, ThreatLevel
from agent.url_scanner import scan_url, URLRisk
from agent.age_guard import full_guard, guard_content, guard_url
from agent.report_generator import generate_report, log_event, report_to_dict
from foundry_iq.knowledge_connector import (
    enrich_safety_decision,
    query_threat_intelligence,
    get_foundry_status,
)
from foundry_iq.mcp_server import handle_mcp_request, execute_tool

app = FastAPI(
    title="GuardianLens API",
    description=(
        "AI-powered social media safety agent with MCP + Microsoft Foundry IQ integration. "
        "Built for Microsoft Agents League Hackathon 2026."
    ),
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Session stats ─────────────────────────────────────────────────────────────

_session_stats = {
    "total_scans": 0,
    "threats_blocked": 0,
    "threats_flagged": 0,
    "foundry_iq_calls": 0,
    "threat_breakdown": defaultdict(int),
    "started_at": datetime.utcnow().isoformat(),
}


def _update_stats(threat_level: str, threat_type: str, blocked: bool, foundry_used: bool = False):
    _session_stats["total_scans"] += 1
    if blocked:
        _session_stats["threats_blocked"] += 1
    elif threat_level not in ("safe",):
        _session_stats["threats_flagged"] += 1
    if threat_type and threat_type != "none":
        _session_stats["threat_breakdown"][threat_type] += 1
    if foundry_used:
        _session_stats["foundry_iq_calls"] += 1


# ── Request models ────────────────────────────────────────────────────────────

class ContentScanRequest(BaseModel):
    text: str
    user_age: Optional[int] = None
    context: Optional[str] = None
    enrich: bool = True          # set False to skip Foundry IQ enrichment


class URLScanRequest(BaseModel):
    url: str
    user_age: Optional[int] = None


class FullScanRequest(BaseModel):
    text: Optional[str] = None
    url: Optional[str] = None
    user_age: Optional[int] = None
    context: Optional[str] = None
    enrich: bool = True


class SocialScanRequest(BaseModel):
    content: str
    user_age: Optional[int] = None
    platform: Optional[str] = None
    enrich: bool = True


class BatchScanRequest(BaseModel):
    items: list[str]
    user_age: Optional[int] = None
    context: Optional[str] = None


class EnrichRequest(BaseModel):
    content: str
    threat_type: str
    confidence: float


class ReportRequest(BaseModel):
    child_name: str = "Your child"
    days: int = 7


# ── Helper ────────────────────────────────────────────────────────────────────

def _format_content_response(analysis, decision, enriched=None):
    return {
        "threat_level": analysis.threat_level.value,
        "threat_type": analysis.threat_type.value,
        "confidence": enriched.blended_confidence if enriched else analysis.confidence,
        "explanation": enriched.foundry_explanation if enriched else analysis.explanation,
        "citations": enriched.foundry_citations if enriched else [],
        "intelligence_source": enriched.source if enriched else "local",
        "grounded": enriched.grounded if enriched else False,
        "flagged_phrases": analysis.flagged_phrases,
        "recommended_action": analysis.recommended_action,
        "is_safe_for_minors": analysis.is_safe_for_minors,
        "context_flags": analysis.context_flags,
        "all_threats": [
            {
                "threat_type": t.threat_type.value,
                "confidence": t.confidence,
                "flagged_phrases": t.flagged_phrases,
            }
            for t in analysis.all_threats
        ],
        "guard_decision": {
            "allowed": decision.allowed,
            "age_group": decision.age_group.value,
            "reason": decision.reason,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        },
    }


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    dashboard_path = Path(__file__).parent.parent / "ui" / "dashboard.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>GuardianLens</h1>")


@app.get("/health")
async def health():
    foundry = get_foundry_status()
    return {
        "status": "ok",
        "service": "GuardianLens",
        "version": "3.0.0",
        "uptime_since": _session_stats["started_at"],
        "foundry_iq": foundry["status"],
        "total_scans": _session_stats["total_scans"],
    }


@app.get("/stats")
async def stats():
    foundry = get_foundry_status()
    return {
        **_session_stats,
        "threat_breakdown": dict(_session_stats["threat_breakdown"]),
        "foundry_iq": foundry,
    }


# ── MCP endpoint ──────────────────────────────────────────────────────────────

@app.post("/mcp")
async def mcp_handler(request: Request):
    """
    MCP Protocol endpoint.
    Foundry IQ agents and other MCP clients connect here to use
    GuardianLens tools: scan_content, scan_url, full_guard,
    get_threat_intelligence, generate_safety_report.
    """
    try:
        body = await request.json()
        response = handle_mcp_request(body)
        return response
    except Exception as e:
        return {
            "jsonrpc": "2.0",
            "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
        }


# ── Foundry IQ endpoints ──────────────────────────────────────────────────────

@app.get("/foundry/status")
async def foundry_status():
    """Check Foundry IQ connection status."""
    return get_foundry_status()


@app.post("/foundry/enrich")
async def foundry_enrich(request: EnrichRequest):
    """Manually enrich a threat detection with Foundry IQ intelligence."""
    enriched = enrich_safety_decision(
        content=request.content,
        local_threat_type=request.threat_type,
        local_confidence=request.confidence,
    )
    return {
        "threat_type": enriched.original_threat_type,
        "original_confidence": enriched.original_confidence,
        "blended_confidence": enriched.blended_confidence,
        "explanation": enriched.foundry_explanation,
        "citations": enriched.foundry_citations,
        "grounded": enriched.grounded,
        "source": enriched.source,
        "recommended_action": enriched.recommended_action,
    }


@app.get("/foundry/intel/{threat_type}")
async def foundry_intel(threat_type: str):
    """Get threat intelligence for a specific threat type."""
    valid = [
        "phishing", "grooming", "scam", "hate_speech",
        "harassment", "cyberbullying", "extremism", "adult_content"
    ]
    if threat_type not in valid:
        raise HTTPException(status_code=400, detail=f"Unknown threat type. Valid: {valid}")

    result = execute_tool("get_threat_intelligence", {"threat_type": threat_type})
    return result


# ── Scan endpoints ────────────────────────────────────────────────────────────

@app.post("/scan/content")
async def scan_content(request: ContentScanRequest):
    if not request.text:
        raise HTTPException(status_code=400, detail="Text is required.")

    analysis = analyze_content(
        text=request.text,
        user_age=request.user_age,
        context=request.context,
    )
    decision = guard_content(analysis, age=request.user_age)

    # Enrich with Foundry IQ
    enriched = None
    if request.enrich and analysis.threat_type.value != "none":
        enriched = enrich_safety_decision(
            content=request.text,
            local_threat_type=analysis.threat_type.value,
            local_confidence=analysis.confidence,
        )

    if analysis.threat_level.value not in ("safe", "low"):
        log_event(
            event_type="content_blocked" if decision.content_blocked else "content_flagged",
            threat_type=analysis.threat_type.value,
            threat_level=analysis.threat_level.value,
            description=analysis.explanation,
            action_taken=analysis.recommended_action,
        )

    _update_stats(
        analysis.threat_level.value,
        analysis.threat_type.value,
        decision.content_blocked,
        foundry_used=enriched is not None,
    )

    return _format_content_response(analysis, decision, enriched)


@app.post("/scan/url")
async def scan_url_endpoint(request: URLScanRequest):
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

    _update_stats(scan.risk.value, scan.risk.value, decision.url_blocked)

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
    if not request.text and not request.url:
        raise HTTPException(status_code=400, detail="Provide at least text or url.")

    results = full_guard(text=request.text, url=request.url, age=request.user_age)
    response = {}

    if "content" in results:
        analysis = results["content"]["analysis"]
        decision = results["content"]["decision"]
        enriched = None
        if request.enrich and analysis.threat_type.value != "none":
            enriched = enrich_safety_decision(
                content=request.text or "",
                local_threat_type=analysis.threat_type.value,
                local_confidence=analysis.confidence,
            )
        _update_stats(analysis.threat_level.value, analysis.threat_type.value, decision.content_blocked, enriched is not None)
        response["content"] = _format_content_response(analysis, decision, enriched)

    if "url" in results:
        scan = results["url"]["scan"]
        decision = results["url"]["decision"]
        _update_stats(scan.risk.value, scan.risk.value, decision.url_blocked)
        response["url"] = {
            "risk": scan.risk.value,
            "confidence": scan.confidence,
            "reasons": scan.reasons,
            "allowed": decision.allowed,
            "alert_guardian": decision.alert_guardian,
            "alert_message": decision.alert_message,
        }

    return response


@app.post("/scan/social")
async def scan_social(request: SocialScanRequest):
    import re
    text = request.content
    platform = request.platform or "unknown"

    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    urls_found = re.findall(url_pattern, text)

    platform_context_map = {
        "instagram": "social_media", "tiktok": "social_media",
        "twitter": "social_media", "x": "social_media",
        "facebook": "social_media", "snapchat": "dm",
        "discord": "dm", "telegram": "dm", "whatsapp": "dm",
    }
    context = platform_context_map.get(platform.lower(), "social_media")

    analysis = analyze_content(text, user_age=request.user_age, context=context)
    decision = guard_content(analysis, age=request.user_age)

    enriched = None
    if request.enrich and analysis.threat_type.value != "none":
        enriched = enrich_safety_decision(
            content=text,
            local_threat_type=analysis.threat_type.value,
            local_confidence=analysis.confidence,
        )

    _update_stats(analysis.threat_level.value, analysis.threat_type.value, decision.content_blocked, enriched is not None)

    url_results = []
    for url in urls_found[:5]:
        scan = scan_url(url, user_age=request.user_age)
        url_decision = guard_url(scan, age=request.user_age)
        _update_stats(scan.risk.value, scan.risk.value, url_decision.url_blocked)
        url_results.append({
            "url": url,
            "risk": scan.risk.value,
            "allowed": url_decision.allowed,
            "reasons": scan.reasons[:2],
        })

    content_blocked = not decision.allowed
    any_url_blocked = any(not r["allowed"] for r in url_results)
    overall_safe = not content_blocked and not any_url_blocked

    return {
        "platform": platform,
        "overall_safe": overall_safe,
        "intelligence_source": enriched.source if enriched else "local",
        "content_analysis": _format_content_response(analysis, decision, enriched),
        "urls_found": len(urls_found),
        "url_results": url_results,
        "summary": (
            "✅ Post appears safe."
            if overall_safe
            else f"⚠️ Threats detected: {analysis.threat_type.value}"
            + (f" + {sum(1 for r in url_results if not r['allowed'])} unsafe URL(s)" if any_url_blocked else "")
        ),
    }


@app.post("/scan/batch")
async def batch_scan(request: BatchScanRequest):
    if not request.items:
        raise HTTPException(status_code=400, detail="Items list is required.")
    if len(request.items) > 20:
        raise HTTPException(status_code=400, detail="Max 20 items per batch.")

    results = []
    for i, text in enumerate(request.items):
        analysis = analyze_content(text, user_age=request.user_age, context=request.context)
        decision = guard_content(analysis, age=request.user_age)
        _update_stats(analysis.threat_level.value, analysis.threat_type.value, decision.content_blocked)
        results.append({
            "index": i,
            "threat_level": analysis.threat_level.value,
            "threat_type": analysis.threat_type.value,
            "confidence": analysis.confidence,
            "allowed": decision.allowed,
            "explanation": analysis.explanation,
        })

    blocked = sum(1 for r in results if not r["allowed"])
    return {
        "total": len(results),
        "blocked": blocked,
        "safe": len(results) - blocked,
        "results": results,
    }


@app.post("/report")
async def get_report(request: ReportRequest):
    report = generate_report(child_name=request.child_name, days=request.days)
    return report_to_dict(report)


@app.get("/report/summary")
async def quick_summary():
    report = generate_report(child_name="User", days=7)
    return {
        "total_events": report.total_events,
        "blocked_count": report.blocked_count,
        "flagged_count": report.flagged_count,
        "overall_risk": report.overall_risk,
        "top_threats": report.top_threats,
        "recommendations": report.recommendations,
    }
