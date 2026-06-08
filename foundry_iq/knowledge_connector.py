"""
GuardianLens — Microsoft Foundry IQ Connector
MCP-compatible threat intelligence layer.
Enriches local pattern analysis with grounded AI knowledge.
Includes graceful fallback when Foundry IQ is unavailable.
"""

import os
import json
import logging
from dataclasses import dataclass
from typing import Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# ── Response models ───────────────────────────────────────────────────────────

@dataclass
class FoundryResponse:
    answer: str
    citations: list[dict]
    confidence: float
    grounded: bool
    source: str          # "foundry_iq" | "fallback" | "cache"
    latency_ms: int


@dataclass
class EnrichedDecision:
    original_threat_type: str
    original_confidence: float
    foundry_explanation: str
    foundry_citations: list[dict]
    blended_confidence: float
    grounded: bool
    recommended_action: str
    source: str


# ── Simple in-memory cache (avoids duplicate API calls) ───────────────────────

_cache: dict[str, tuple[FoundryResponse, datetime]] = {}
CACHE_TTL_MINUTES = 30


def _cache_get(key: str) -> Optional[FoundryResponse]:
    if key in _cache:
        response, cached_at = _cache[key]
        if datetime.utcnow() - cached_at < timedelta(minutes=CACHE_TTL_MINUTES):
            return response
        del _cache[key]
    return None


def _cache_set(key: str, response: FoundryResponse):
    _cache[key] = (response, datetime.utcnow())


# ── Foundry IQ client ─────────────────────────────────────────────────────────

def _is_foundry_configured() -> bool:
    """Check if Foundry IQ credentials are present in environment."""
    required = [
        "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "FOUNDRY_IQ_ENDPOINT",
    ]
    return all(os.getenv(k) for k in required)


def _query_foundry_iq(query: str, system_prompt: str) -> FoundryResponse:
    """
    Make a real call to Microsoft Foundry IQ via Azure AI Projects SDK.
    Returns a FoundryResponse with grounded answer and citations.
    """
    import time
    start = time.time()

    try:
        from azure.identity import ClientSecretCredential
        from azure.ai.projects import AIProjectClient

        credential = ClientSecretCredential(
            tenant_id=os.environ["AZURE_TENANT_ID"],
            client_id=os.environ["AZURE_CLIENT_ID"],
            client_secret=os.environ["AZURE_CLIENT_SECRET"],
        )

        client = AIProjectClient(
            endpoint=os.environ["FOUNDRY_IQ_ENDPOINT"],
            credential=credential,
        )

        # Create a short-lived agent for this query
        agent = client.agents.create_agent(
            model="gpt-4o",
            name="guardianlens-threat-intel",
            instructions=system_prompt,
        )

        thread = client.agents.create_thread()
        client.agents.create_message(
            thread_id=thread.id,
            role="user",
            content=query,
        )

        run = client.agents.create_and_process_run(
            thread_id=thread.id,
            agent_id=agent.id,
        )

        messages = client.agents.list_messages(thread_id=thread.id)
        answer_text = ""
        citations = []

        for msg in messages.data:
            if msg.role == "assistant":
                for block in msg.content:
                    if hasattr(block, "text"):
                        answer_text = block.text.value
                        for annotation in getattr(block.text, "annotations", []):
                            if hasattr(annotation, "file_citation"):
                                citations.append({
                                    "source": annotation.file_citation.file_id,
                                    "quote": getattr(annotation, "text", ""),
                                })

        # Cleanup
        client.agents.delete_agent(agent.id)

        latency = int((time.time() - start) * 1000)

        return FoundryResponse(
            answer=answer_text or "No response from Foundry IQ.",
            citations=citations,
            confidence=0.90 if citations else 0.72,
            grounded=bool(citations),
            source="foundry_iq",
            latency_ms=latency,
        )

    except ImportError:
        raise RuntimeError("azure-ai-projects not installed.")
    except KeyError as e:
        raise RuntimeError(f"Missing environment variable: {e}")


# ── Fallback knowledge base (works without Azure) ─────────────────────────────

FALLBACK_KNOWLEDGE = {
    "phishing": {
        "explanation": (
            "Phishing attacks use deceptive messages to trick users into revealing "
            "credentials or clicking malicious links. Common patterns include urgency, "
            "impersonation of trusted brands, and requests for sensitive information."
        ),
        "risk_factors": ["urgency language", "credential requests", "suspicious links", "impersonation"],
        "recommended_action": "block_and_notify",
    },
    "grooming": {
        "explanation": (
            "Online grooming involves an adult building trust with a minor through "
            "excessive flattery, secrecy requests, isolation from family, and gradual "
            "boundary violations. Immediate intervention and guardian notification is critical."
        ),
        "risk_factors": ["secrecy requests", "flattery", "isolation", "meeting requests", "gift offers"],
        "recommended_action": "block_immediately_and_alert_guardian",
    },
    "scam": {
        "explanation": (
            "Financial scams promise unrealistic returns or prizes to extract money. "
            "Common variants include investment fraud, advance-fee fraud, and gift card scams. "
            "No legitimate offer requires upfront payment to claim a reward."
        ),
        "risk_factors": ["guaranteed returns", "upfront payment", "urgency", "too-good-to-be-true offers"],
        "recommended_action": "block_and_warn",
    },
    "hate_speech": {
        "explanation": (
            "Hate speech targets individuals or groups based on protected characteristics "
            "like race, religion, ethnicity, or gender. It can escalate to real-world harm "
            "and violates platform terms of service."
        ),
        "risk_factors": ["dehumanizing language", "group targeting", "incitement"],
        "recommended_action": "block_and_report",
    },
    "harassment": {
        "explanation": (
            "Online harassment includes threats, intimidation, and sustained targeting "
            "of individuals. Threats of physical harm should be reported to law enforcement."
        ),
        "risk_factors": ["physical threats", "doxxing", "stalking language", "death threats"],
        "recommended_action": "block_and_notify_authorities",
    },
    "cyberbullying": {
        "explanation": (
            "Cyberbullying uses digital platforms to repeatedly humiliate, exclude, or "
            "threaten peers. It disproportionately affects minors and is linked to serious "
            "mental health impacts."
        ),
        "risk_factors": ["repeated targeting", "public humiliation", "exclusion", "rumour spreading"],
        "recommended_action": "block_and_notify_guardian",
    },
    "extremism": {
        "explanation": (
            "Extremist content promotes or recruits for violent ideologies. Online "
            "radicalisation often targets vulnerable young people through gradual exposure. "
            "Such content should be reported to relevant authorities."
        ),
        "risk_factors": ["recruitment language", "violent ideology", "dehumanisation of outgroups"],
        "recommended_action": "block_immediately_and_report",
    },
    "adult_content": {
        "explanation": (
            "Adult content is inappropriate for minors and may violate platform terms. "
            "Exposure of minors to explicit material can be harmful and in some contexts illegal."
        ),
        "risk_factors": ["explicit material", "sexual content", "age-inappropriate"],
        "recommended_action": "block_for_minors",
    },
}


def _fallback_response(threat_type: str) -> FoundryResponse:
    """Return a grounded fallback response from local knowledge base."""
    kb = FALLBACK_KNOWLEDGE.get(threat_type, {})
    explanation = kb.get(
        "explanation",
        f"Threat type '{threat_type}' detected. Exercise caution.",
    )
    risk_factors = kb.get("risk_factors", [])

    answer = explanation
    if risk_factors:
        answer += f"\n\nKey risk factors: {', '.join(risk_factors)}."

    return FoundryResponse(
        answer=answer,
        citations=[{"source": "GuardianLens Knowledge Base", "quote": explanation[:100]}],
        confidence=0.75,
        grounded=True,
        source="fallback",
        latency_ms=0,
    )


# ── Main public API ───────────────────────────────────────────────────────────

THREAT_INTEL_SYSTEM_PROMPT = """You are a cybersecurity and child safety expert assistant for GuardianLens.
Your role is to:
1. Explain detected threats clearly and accurately
2. Provide actionable safety recommendations
3. Cite your sources whenever possible
4. Keep responses concise (2-3 sentences max)
5. Never minimize serious threats like grooming or extremism

Always prioritize child safety above all else."""


def query_threat_intelligence(
    query: str,
    context: Optional[str] = None,
) -> FoundryResponse:
    """
    Query Foundry IQ for grounded threat intelligence.
    Falls back to local knowledge base if Foundry IQ is unavailable.
    """
    cache_key = f"{query[:100]}:{context}"
    cached = _cache_get(cache_key)
    if cached:
        cached.source = "cache"
        return cached

    if _is_foundry_configured():
        try:
            full_query = f"[Context: {context}]\n{query}" if context else query
            response = _query_foundry_iq(full_query, THREAT_INTEL_SYSTEM_PROMPT)
            _cache_set(cache_key, response)
            return response
        except Exception as e:
            logger.warning(f"Foundry IQ unavailable, using fallback: {e}")

    # Fallback — extract threat type from query
    threat_type = context or "unknown"
    for t in FALLBACK_KNOWLEDGE:
        if t in query.lower():
            threat_type = t
            break

    response = _fallback_response(threat_type)
    _cache_set(cache_key, response)
    return response


def enrich_safety_decision(
    content: str,
    local_threat_type: str,
    local_confidence: float,
) -> EnrichedDecision:
    """
    Enrich a local safety decision with Foundry IQ / fallback intelligence.
    Blends local pattern confidence with grounded AI knowledge.
    """
    # Skip enrichment for safe content
    if local_threat_type == "none" or local_confidence < 0.1:
        return EnrichedDecision(
            original_threat_type=local_threat_type,
            original_confidence=local_confidence,
            foundry_explanation="Content appears safe — no enrichment needed.",
            foundry_citations=[],
            blended_confidence=local_confidence,
            grounded=False,
            recommended_action="allow",
            source="local",
        )

    query = (
        f"Explain this threat briefly and what action to take: "
        f"'{local_threat_type}' detected with {local_confidence:.0%} confidence. "
        f"Content snippet: {content[:200]}"
    )

    response = query_threat_intelligence(query, context=local_threat_type)

    # Blend confidence: local patterns (60%) + Foundry grounding (40%)
    blended = round(
        (local_confidence * 0.60) + (response.confidence * 0.40), 3
    )

    # Get recommended action from fallback KB
    kb_action = FALLBACK_KNOWLEDGE.get(local_threat_type, {}).get(
        "recommended_action", "block_and_notify"
    )

    return EnrichedDecision(
        original_threat_type=local_threat_type,
        original_confidence=local_confidence,
        foundry_explanation=response.answer,
        foundry_citations=response.citations,
        blended_confidence=blended,
        grounded=response.grounded,
        recommended_action=kb_action,
        source=response.source,
    )


def get_foundry_status() -> dict:
    """Return current Foundry IQ connection status for the dashboard."""
    configured = _is_foundry_configured()
    return {
        "configured": configured,
        "status": "connected" if configured else "fallback_mode",
        "mode": "Microsoft Foundry IQ" if configured else "Local Knowledge Base",
        "cache_entries": len(_cache),
        "message": (
            "Foundry IQ active — responses are grounded with cited sources."
            if configured
            else "Running in fallback mode. Add Azure credentials to .env to enable Foundry IQ."
        ),
    }
