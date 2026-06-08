"""
GuardianLens — Microsoft Foundry IQ Connector
Connects to Microsoft Foundry IQ for grounded, cited threat intelligence.
Reduces hallucination on safety-critical decisions.
"""

import os
from dataclasses import dataclass
from typing import Optional

from azure.identity import ClientSecretCredential
from azure.ai.projects import AIProjectClient


@dataclass
class FoundryResponse:
    answer: str
    citations: list[dict]
    confidence: float
    grounded: bool


def _get_client() -> AIProjectClient:
    """Initialize the Azure AI Projects client using env credentials."""
    credential = ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"],
    )
    return AIProjectClient(
        endpoint=os.environ["FOUNDRY_IQ_ENDPOINT"],
        credential=credential,
    )


def query_threat_intelligence(
    query: str,
    context: Optional[str] = None,
) -> FoundryResponse:
    """
    Query Foundry IQ for grounded threat intelligence.

    Args:
        query: The safety question or URL/content to evaluate.
        context: Optional context (e.g. "url_scan", "content_analysis").

    Returns:
        FoundryResponse with grounded answer, citations, and confidence.
    """
    try:
        client = _get_client()

        system_prompt = (
            "You are a cybersecurity and child safety expert. "
            "Answer questions about online threats, phishing, grooming, "
            "and harmful content accurately and concisely. "
            "Always cite your sources. If unsure, say so."
        )

        full_query = query
        if context:
            full_query = f"[Context: {context}]\n{query}"

        # Use Foundry IQ agent for grounded retrieval
        agent = client.agents.create_agent(
            model="gpt-4o",
            name="guardianlens-threat-intel",
            instructions=system_prompt,
        )

        thread = client.agents.create_thread()
        client.agents.create_message(
            thread_id=thread.id,
            role="user",
            content=full_query,
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
                        # Extract citations from annotations
                        for annotation in getattr(block.text, "annotations", []):
                            if hasattr(annotation, "file_citation"):
                                citations.append({
                                    "source": annotation.file_citation.file_id,
                                    "quote": getattr(annotation, "text", ""),
                                })

        # Clean up
        client.agents.delete_agent(agent.id)

        return FoundryResponse(
            answer=answer_text or "No response from Foundry IQ.",
            citations=citations,
            confidence=0.85 if citations else 0.5,
            grounded=bool(citations),
        )

    except Exception as e:
        # Graceful fallback — return a safe default
        return FoundryResponse(
            answer=f"Foundry IQ unavailable: {str(e)}. Using local analysis only.",
            citations=[],
            confidence=0.0,
            grounded=False,
        )


def enrich_safety_decision(
    content: str,
    local_threat_type: str,
    local_confidence: float,
) -> dict:
    """
    Enrich a local safety decision with Foundry IQ intelligence.
    Combines local pattern matching with grounded AI knowledge.

    Args:
        content: The text or URL being analyzed.
        local_threat_type: Threat type from local analysis.
        local_confidence: Confidence from local analysis.

    Returns:
        Enriched decision dict with combined confidence and explanation.
    """
    if local_confidence < 0.3:
        # Low local confidence — ask Foundry IQ
        query = f"Is this content safe? Analyze for threats: {content[:500]}"
        response = query_threat_intelligence(query, context="content_analysis")
    else:
        # High local confidence — just get context from Foundry IQ
        query = (
            f"Briefly explain the threat pattern '{local_threat_type}' "
            f"and how to recognize it. One paragraph."
        )
        response = query_threat_intelligence(query, context="threat_explanation")

    # Blend local + Foundry confidence
    blended_confidence = (
        (local_confidence * 0.6) + (response.confidence * 0.4)
        if response.grounded
        else local_confidence
    )

    return {
        "foundry_answer": response.answer,
        "foundry_citations": response.citations,
        "foundry_grounded": response.grounded,
        "blended_confidence": round(blended_confidence, 3),
        "local_threat_type": local_threat_type,
        "local_confidence": local_confidence,
    }
