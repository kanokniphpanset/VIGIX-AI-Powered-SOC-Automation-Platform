from src.graph.state import AgentState
from src.llm.llama_provider import LlamaProvider
from src.config.settings import settings
from .prompts import (
    SUMMARY_SYSTEM_PROMPT,
    RECOMMENDATION_SYSTEM_PROMPT,
    build_summary_prompt,
    build_recommendation_prompt,
)

_llm = LlamaProvider(settings.llm_base_url, settings.llm_model)


def _fallback_summary(state: AgentState) -> str:
    """Deterministic summary used if the LLM endpoint is unreachable — keeps the
    pipeline usable before Ollama/vLLM is set up, instead of hard failing."""
    severity = state.get("severity_prediction", "unknown")
    technique_names = ", ".join(t["name"] for t in state.get("mitre_techniques", [])) or "none identified"
    return (
        f"Alert classified as {severity} severity. "
        f"MITRE techniques observed: {technique_names}. "
        f"{len(state.get('iocs', []))} IOC(s) extracted for review."
    )


def _fallback_recommendation(state: AgentState) -> str:
    if state.get("risk_score", 0) >= 70:
        return "Isolate affected host, rotate any exposed credentials, and escalate to on-call analyst for manual review."
    return "Monitor the affected asset and correlate with related alerts over the next 24 hours."


async def run(state: AgentState) -> AgentState:
    """
    LlmAnalystAgent — asks Llama 3.1 8B Instruct (via Ollama/vLLM, see
    llm/llama_provider.py) for a plain-language summary and a set of
    recommended next actions. Falls back to a deterministic template if the
    LLM endpoint isn't reachable, so the pipeline still completes.
    """
    new_trace_entries: list[str] = []

    try:
        summary = await _llm.complete(SUMMARY_SYSTEM_PROMPT, build_summary_prompt(dict(state)))
    except Exception as exc:
        summary = _fallback_summary(state)
        new_trace_entries.append(f"LlmAnalystAgent: LLM unavailable ({exc.__class__.__name__}), used fallback summary")

    try:
        recommendation = await _llm.complete(
            RECOMMENDATION_SYSTEM_PROMPT, build_recommendation_prompt(dict(state))
        )
    except Exception as exc:
        recommendation = _fallback_recommendation(state)
        new_trace_entries.append(
            f"LlmAnalystAgent: LLM unavailable ({exc.__class__.__name__}), used fallback recommendation"
        )

    new_trace_entries.append("LlmAnalystAgent: summary and recommendation generated")

    return {"llm_summary": summary, "llm_recommendation": recommendation, "trace": new_trace_entries}
