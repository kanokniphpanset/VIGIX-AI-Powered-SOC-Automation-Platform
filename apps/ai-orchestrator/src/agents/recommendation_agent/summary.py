"""
build_summary — RecommendationAgent's one LLM call: a single grounded
investigation-summary paragraph over the already-selected recommendations,
using the same LlamaProvider/PromptLoader/fallback pattern
llm_analyst_agent/agent.py already uses for its own summary call.

This is the ONLY place an LLM touches RecommendationAgent's output —
selector.py's own reason/rationale text is deterministic, template-built
from real evidence/framework/playbook data, never LLM-written, so a
hallucinated citation/technique/evidence item can never reach a
per-recommendation field. The LLM here is handed only recommendation
titles/categories and the missing-evidence list already computed by
selector.py — it cannot add, remove, or reprioritize anything (spec
section 14: "LLM must NOT invent evidence / NIST references / MITRE
techniques").
"""

from __future__ import annotations

import logging

from resources.prompt_loader import PromptLoader
from src.agents.recommendation_agent.models import Recommendation
from src.config.settings import settings
from src.llm.llama_provider import LlamaProvider

logger = logging.getLogger("soar.ai-orchestrator")

_llm = LlamaProvider(settings.llm_base_url, settings.llm_model, settings.llm_timeout_seconds, api_key=settings.llm_api_key)
_prompts = PromptLoader()

_MIN_VALID_RESPONSE_LENGTH = 10


def _fallback_summary(
    incident_type: str,
    classification_confidence: float,
    recommendations: list[Recommendation],
    missing_evidence: list[str],
) -> str:
    categories = sorted({r.category.value for r in recommendations})
    category_text = ", ".join(categories) if categories else "no categories (insufficient evidence)"
    missing_text = (
        f" {len(missing_evidence)} catalog recommendation(s) could not be included for lack of supporting evidence."
        if missing_evidence
        else ""
    )
    return (
        f"Incident classified as {incident_type} (confidence {classification_confidence:.2f}). "
        f"{len(recommendations)} evidence-backed recommendation(s) selected across: {category_text}.{missing_text}"
    )


async def build_summary(
    state: dict,
    incident_type: str,
    classification_confidence: float,
    recommendations: list[Recommendation],
    missing_evidence: list[str],
) -> tuple[str, str | None]:
    """Returns (summary_text, fallback_trace_or_None)."""
    fallback = _fallback_summary(incident_type, classification_confidence, recommendations, missing_evidence)
    alert_id = state.get("alert_id", "unknown")

    try:
        system = _prompts.get_by_id("recommendation-agent.summary.system")
        if system is None:
            raise RuntimeError("prompt resource 'recommendation-agent.summary.system' not found under resources/prompts/")
        user = _prompts.render(
            "recommendation-agent.summary.user",
            incident_type=incident_type,
            classification_confidence=classification_confidence,
            recommendation_titles=[f"{r.category.value}: {r.title}" for r in recommendations] or ["(none selected)"],
            missing_evidence=missing_evidence or ["(none)"],
            alert_text=state.get("alert_text", ""),
        )
    except Exception as exc:
        logger.warning("RecommendationAgent: prompt loading failed for summary (alert_id=%s): %s — using fallback", alert_id, exc)
        return fallback, "RecommendationAgent: prompt loading failed, used fallback summary"

    try:
        text = await _llm.complete(system.template, user)
    except Exception as exc:
        logger.warning(
            "RecommendationAgent: LLM unavailable for summary (alert_id=%s, %s) — using fallback",
            alert_id,
            exc.__class__.__name__,
        )
        return fallback, f"RecommendationAgent: LLM unavailable ({exc.__class__.__name__}), used fallback summary"

    if not text or len(text.strip()) < _MIN_VALID_RESPONSE_LENGTH:
        logger.warning("RecommendationAgent: LLM returned an empty/degenerate summary (alert_id=%s) — using fallback", alert_id)
        return fallback, "RecommendationAgent: invalid LLM response, used fallback summary"

    return text.strip(), None
