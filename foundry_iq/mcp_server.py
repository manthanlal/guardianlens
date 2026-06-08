"""
GuardianLens — MCP Server
Exposes GuardianLens tools via the Model Context Protocol.
This allows any MCP-compatible AI (Claude, Foundry IQ agents, etc.)
to call GuardianLens safety tools directly.
"""

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)


# ── MCP Tool definitions ──────────────────────────────────────────────────────
# These describe our tools in MCP-compatible format.
# Foundry IQ agents can discover and call these automatically.

MCP_TOOLS = [
    {
        "name": "scan_content",
        "description": (
            "Analyze text content for cybercrime patterns, grooming language, "
            "hate speech, harassment, scams, and adult content. "
            "Returns threat level, type, confidence, and recommended action."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The text content to analyze for safety threats.",
                },
                "user_age": {
                    "type": "integer",
                    "description": "Age of the user (enables minor protection if under 18).",
                },
                "context": {
                    "type": "string",
                    "description": "Context of the message: 'dm', 'email', 'social_media', 'comment'.",
                    "enum": ["dm", "email", "social_media", "comment", "chat"],
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "scan_url",
        "description": (
            "Scan a URL for phishing, malware, adult content, and unsafe redirects. "
            "Checks against known threat patterns and optionally against Google Safe Browsing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The URL to scan for safety threats.",
                },
                "user_age": {
                    "type": "integer",
                    "description": "Age of the user (enables stricter filtering for minors).",
                },
            },
            "required": ["url"],
        },
    },
    {
        "name": "full_guard",
        "description": (
            "Run complete safety analysis on both text content and a URL simultaneously. "
            "Best for scanning social media posts that contain both text and links."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text content to analyze."},
                "url":  {"type": "string", "description": "URL to scan."},
                "user_age": {"type": "integer", "description": "Age of the user."},
            },
        },
    },
    {
        "name": "get_threat_intelligence",
        "description": (
            "Query the threat intelligence knowledge base for detailed information "
            "about a specific threat type. Returns explanation, risk factors, "
            "and recommended actions grounded in security knowledge."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "threat_type": {
                    "type": "string",
                    "description": "The threat type to look up.",
                    "enum": [
                        "phishing", "grooming", "scam", "hate_speech",
                        "harassment", "cyberbullying", "extremism", "adult_content",
                    ],
                },
            },
            "required": ["threat_type"],
        },
    },
    {
        "name": "generate_safety_report",
        "description": (
            "Generate a safety summary report for a guardian/parent. "
            "Returns blocked count, flagged items, top threats, and recommendations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "child_name": {"type": "string", "description": "Name of the child being monitored."},
                "days": {"type": "integer", "description": "Number of days to include (default: 7)."},
            },
        },
    },
]


# ── MCP Tool executor ─────────────────────────────────────────────────────────

def execute_tool(tool_name: str, arguments: dict) -> dict:
    """
    Execute a GuardianLens MCP tool by name.
    Called by MCP-compatible clients (Foundry IQ agents, Claude, etc.)
    """
    try:
        if tool_name == "scan_content":
            return _tool_scan_content(arguments)
        elif tool_name == "scan_url":
            return _tool_scan_url(arguments)
        elif tool_name == "full_guard":
            return _tool_full_guard(arguments)
        elif tool_name == "get_threat_intelligence":
            return _tool_get_threat_intelligence(arguments)
        elif tool_name == "generate_safety_report":
            return _tool_generate_report(arguments)
        else:
            return {"error": f"Unknown tool: {tool_name}"}
    except Exception as e:
        logger.error(f"MCP tool error [{tool_name}]: {e}")
        return {"error": str(e)}


def _tool_scan_content(args: dict) -> dict:
    from agent.content_analyzer import analyze_content
    from agent.age_guard import guard_content
    from foundry_iq.knowledge_connector import enrich_safety_decision

    analysis = analyze_content(
        text=args["text"],
        user_age=args.get("user_age"),
        context=args.get("context"),
    )
    decision = guard_content(analysis, age=args.get("user_age"))

    # Enrich with Foundry IQ if threat detected
    enriched = None
    if analysis.threat_type.value != "none":
        enriched = enrich_safety_decision(
            content=args["text"],
            local_threat_type=analysis.threat_type.value,
            local_confidence=analysis.confidence,
        )

    result = {
        "threat_level": analysis.threat_level.value,
        "threat_type": analysis.threat_type.value,
        "confidence": enriched.blended_confidence if enriched else analysis.confidence,
        "explanation": enriched.foundry_explanation if enriched else analysis.explanation,
        "citations": enriched.foundry_citations if enriched else [],
        "grounded": enriched.grounded if enriched else False,
        "intelligence_source": enriched.source if enriched else "local",
        "recommended_action": analysis.recommended_action,
        "is_safe_for_minors": analysis.is_safe_for_minors,
        "flagged_phrases": analysis.flagged_phrases,
        "allowed": decision.allowed,
        "alert_guardian": decision.alert_guardian,
        "alert_message": decision.alert_message,
    }
    return result


def _tool_scan_url(args: dict) -> dict:
    from agent.url_scanner import scan_url
    from agent.age_guard import guard_url

    scan = scan_url(url=args["url"], user_age=args.get("user_age"))
    decision = guard_url(scan, age=args.get("user_age"))

    return {
        "url": scan.url,
        "risk": scan.risk.value,
        "confidence": scan.confidence,
        "reasons": scan.reasons,
        "final_destination": scan.final_destination,
        "is_safe_for_minors": scan.is_safe_for_minors,
        "recommended_action": scan.recommended_action,
        "allowed": decision.allowed,
        "alert_guardian": decision.alert_guardian,
        "alert_message": decision.alert_message,
    }


def _tool_full_guard(args: dict) -> dict:
    from agent.age_guard import full_guard

    results = full_guard(
        text=args.get("text"),
        url=args.get("url"),
        age=args.get("user_age"),
    )

    output = {}
    if "content" in results:
        a = results["content"]["analysis"]
        d = results["content"]["decision"]
        output["content"] = {
            "threat_level": a.threat_level.value,
            "threat_type": a.threat_type.value,
            "allowed": d.allowed,
            "alert_message": d.alert_message,
        }
    if "url" in results:
        s = results["url"]["scan"]
        d = results["url"]["decision"]
        output["url"] = {
            "risk": s.risk.value,
            "allowed": d.allowed,
            "alert_message": d.alert_message,
        }
    return output


def _tool_get_threat_intelligence(args: dict) -> dict:
    from foundry_iq.knowledge_connector import query_threat_intelligence, FALLBACK_KNOWLEDGE

    threat_type = args["threat_type"]
    response = query_threat_intelligence(
        query=f"Explain the threat '{threat_type}' and how to protect against it.",
        context=threat_type,
    )
    kb = FALLBACK_KNOWLEDGE.get(threat_type, {})

    return {
        "threat_type": threat_type,
        "explanation": response.answer,
        "citations": response.citations,
        "risk_factors": kb.get("risk_factors", []),
        "recommended_action": kb.get("recommended_action", "block_and_notify"),
        "grounded": response.grounded,
        "source": response.source,
    }


def _tool_generate_report(args: dict) -> dict:
    from agent.report_generator import generate_report, report_to_dict

    report = generate_report(
        child_name=args.get("child_name", "User"),
        days=args.get("days", 7),
    )
    return report_to_dict(report)


# ── MCP Protocol handlers ─────────────────────────────────────────────────────

def handle_mcp_request(request: dict) -> dict:
    """
    Handle an incoming MCP protocol request.
    Supports: tools/list, tools/call
    """
    method = request.get("method", "")

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {"tools": MCP_TOOLS},
        }

    elif method == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        result = execute_tool(tool_name, arguments)

        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2),
                    }
                ]
            },
        }

    elif method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "guardianlens-mcp",
                    "version": "2.0.0",
                    "description": "AI-powered social media safety agent MCP server",
                },
            },
        }

    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }
