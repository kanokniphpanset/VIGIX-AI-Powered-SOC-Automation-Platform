"""
recommendations.py — POST /recommendations/generate, called by apps/backend's
LlmRecommendationAgent (GenerateRecommendationUseCase -> IRecommendationAgentPort).

Flow: the backend sends {context, prompt} — `context` is the authoritative
RecommendationContextDto built from Postgres, `prompt` is the backend's
RecommendationPromptBuilder output (rules + allowlists + output contract).
This endpoint adds REAL RAG retrieval (RagRetriever -> backend
/api/v1/knowledge/search -> Qdrant) as grounding, asks the LLM for ONE
candidate as strict JSON, and shape-checks it. Nothing here is trusted
downstream: the backend RecommendationValidator re-verifies every code,
evidence ref and target before anything is persisted.

Failure is explicit, never papered over with a template/heuristic candidate
(VIGIX: no fake recommendation when the AI produced no valid result):
  503 LLM_UNAVAILABLE      the LLM call failed
  504 LLM_TIMEOUT          the LLM did not answer in time
  502 INVALID_LLM_OUTPUT   not JSON / wrong shape / no steps (after one re-ask)
  422 PROMPT_MISSING       the backend sent no prompt

Does NOT import rag_agent.agent or the LangGraph pipeline — this endpoint is
retrieval + one LLM call (plus one re-ask if the reply is not a parseable candidate).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from resources.prompt_loader import PromptLoader
from src.agents.rag_agent.retriever import RagRetriever
from src.agents.rag_agent.vector_search_client import VectorSearchClient
from src.config.settings import settings
from src.embeddings.bge_embedding_provider import BgeEmbeddingProvider
from src.llm.llama_provider import LlamaProvider

logger = logging.getLogger("soar.ai-orchestrator")

router = APIRouter()

_embedding_provider = BgeEmbeddingProvider(settings.embedding_model)
_vector_search_client = VectorSearchClient(settings.backend_url, service_token=settings.backend_service_token or None)
_retriever = RagRetriever(_embedding_provider, _vector_search_client, top_k=5, playbook_top_k=3)
_llm = LlamaProvider(settings.llm_base_url, settings.llm_model, settings.llm_timeout_seconds, api_key=settings.llm_api_key)
_prompts = PromptLoader()

_RAG_TIMEOUT_SECONDS = 30.0
SYSTEM_PROMPT_ID = "recommendation-agent.generate.system"
_JSON_RETRIES = 1  # re-asks after an unparseable reply


class GenerateRecommendationRequest(BaseModel):
    context: dict[str, Any]
    prompt: str | None = None


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CandidateInstruction(_Strict):
    """One ordered operational instruction of an action-level step (Task 10.3)."""

    order: int = Field(ge=1)
    instruction: str = Field(min_length=1)
    target: str | None = None
    expectedResult: str | None = None


class CandidateStep(_Strict):
    """Mirrors apps/backend RecommendationCandidateDto's candidateStepSchema v2 (strict).

    One step = ONE response Action on ONE target, expanded into concrete instructions.
    Never a VIGIX Core Flow phase (validate / monitor / re-hunt / approval ...).
    """

    stepOrder: int = Field(ge=1)
    action: str = Field(min_length=1)
    objective: str = Field(min_length=1)
    responsibleRole: str = Field(min_length=1)
    target: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    evidenceRefs: list[str] = Field(default_factory=list)
    instructions: list[CandidateInstruction] = Field(min_length=1)
    playbook: str = Field(min_length=1)
    runbook: str = Field(min_length=1)
    verificationCriteria: str = Field(min_length=1)
    expectedResult: str | None = None
    missingEvidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    requiresApprovalSuggested: bool | None = None


class Candidate(_Strict):
    summary: str = Field(min_length=1)
    steps: list[CandidateStep] = Field(min_length=1)


def _build_query(context: dict[str, Any]) -> str:
    tactics = [m.get("tactic") for m in context.get("mitreMappings", []) if m.get("tactic")]
    technique_ids = [m.get("techniqueId") for m in context.get("mitreMappings", []) if m.get("techniqueId")]
    ioc_types = [i.get("iocType") for i in context.get("iocs", []) if i.get("iocType")]
    parts = ["response action runbook"]
    playbook = context.get("playbook") or {}
    if playbook.get("incidentType"):
        parts.append(str(playbook["incidentType"]))
    parts.extend(p.get("actionName", "") for p in context.get("actionProcedures", []) or [])
    parts.extend(tactics)
    parts.extend(technique_ids)
    parts.extend(ioc_types)
    parts.append(context.get("incidentTitle", ""))
    return " ".join(p for p in parts if p)


async def _retrieved_knowledge(context: dict[str, Any]) -> str:
    """RAG grounding section appended to the backend prompt. Retrieval failure is disclosed, not fatal —
    the allowlisted runbooks are already in the prompt; RAG only ranks them."""
    try:
        result = await asyncio.wait_for(_retriever.retrieve_playbooks(_build_query(context)), timeout=_RAG_TIMEOUT_SECONDS)
    except Exception as exc:  # noqa: BLE001 - disclosed in the prompt below
        logger.warning("recommendations.generate: RAG retrieval failed (%s)", exc.__class__.__name__)
        return "Retrieved knowledge (RAG): unavailable for this request."
    if result.status != "OK" or not result.documents:
        return "Retrieved knowledge (RAG): no relevant runbook retrieved."
    lines = ["Retrieved knowledge (RAG, most relevant first):"]
    for doc in result.documents[:3]:
        code = (doc.get("metadata") or {}).get("runbookCode") or doc.get("doc_id") or doc.get("id")
        snippet = " ".join((doc.get("content") or "").split())[:400]
        lines.append(f"  - {code}: {doc.get('title')} (score={float(doc.get('score') or 0.0):.4f}) — {snippet}")
    return "\n".join(lines)


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


def parse_candidate(text: str) -> Candidate:
    """Strict: one JSON object (code fences tolerated), matching Candidate. Raises ValueError otherwise."""
    cleaned = _FENCE.sub("", (text or "").strip())
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("LLM response contains no JSON object")
    try:
        # First complete JSON object only: trailing text/duplicate objects after it are ignored
        # (the object itself is still validated strictly below and again by the backend).
        payload, _ = json.JSONDecoder().raw_decode(cleaned[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM response is not valid JSON: {exc.msg}") from exc
    try:
        return Candidate.model_validate(payload)
    except ValidationError as exc:
        # Name the offending fields: this text is fed back to the model on the re-ask and lands in the backend audit log.
        details = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()[:5])
        raise ValueError(f"LLM response does not match the candidate schema: {exc.error_count()} error(s) — {details}") from exc


def _fail(status: int, code: str, message: str) -> HTTPException:
    logger.warning("recommendations.generate: %s — %s", code, message)
    return HTTPException(status_code=status, detail={"error": code, "message": message})


@router.post("/generate")
async def generate_recommendation(request: GenerateRecommendationRequest) -> dict[str, Any]:
    if not request.prompt or not request.prompt.strip():
        raise _fail(422, "PROMPT_MISSING", "The backend must send the RecommendationPromptBuilder prompt.")

    system = _prompts.get_by_id(SYSTEM_PROMPT_ID)
    if system is None:
        raise _fail(503, "LLM_UNAVAILABLE", f"prompt resource '{SYSTEM_PROMPT_ID}' not found")

    user = f"{request.prompt.strip()}\n\n{await _retrieved_knowledge(request.context)}"

    # One re-ask when the reply is not parseable JSON (the model occasionally emits a broken object and the
    # gateway does not support JSON mode). The re-asked reply is validated exactly like the first — never repaired.
    last_error = ""
    for attempt in range(1 + _JSON_RETRIES):
        prompt = user if attempt == 0 else f"{user}\n\nYour previous reply was rejected: {last_error}. Reply with the ONE JSON object only."
        try:
            text = await asyncio.wait_for(_llm.complete(system.template, prompt), timeout=settings.llm_timeout_seconds)
        except asyncio.TimeoutError as exc:
            raise _fail(504, "LLM_TIMEOUT", f"LLM did not answer within {settings.llm_timeout_seconds}s") from exc
        except Exception as exc:  # noqa: BLE001 - any provider failure is "unavailable", never a fallback
            raise _fail(503, "LLM_UNAVAILABLE", f"LLM call failed ({exc.__class__.__name__})") from exc
        try:
            return parse_candidate(text).model_dump(exclude_none=True)
        except ValueError as exc:
            last_error = str(exc)
    raise _fail(502, "INVALID_LLM_OUTPUT", last_error)
