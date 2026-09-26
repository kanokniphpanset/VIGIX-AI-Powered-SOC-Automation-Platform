"""
GroundedContextBuilder (Phase D) — assembles the single grounded-context
object the LLM synthesis step (agent.py) and the final output contract are
both built from. Purely deterministic formatting/aggregation over already-
retrieved, already-re-ranked documents — no LLM calls, no fabrication.

The four hallucination-control flags (knowledgeStatus, playbookStatus,
noRelevantPlaybook, insufficientKnowledge) are this module's whole reason
for existing: they are computed *exclusively* from whether retrieval
actually returned documents surviving RagConfig.relevance_threshold
(reranker.filter_by_relevance already did that filtering — this module
just asks "is the list non-empty?"). Nothing here ever asks an LLM whether
a match is "good enough", and nothing downstream (recommendation_builder.py
in particular) is allowed to treat a MATCHED status as anything other than
what filter_by_relevance actually decided — mirrors mitre_agent's own
NO_SUPPORTED_MAPPING "never guess, never let the model assert its own
grounding" philosophy (see mitre_agent/technique_mapper.py).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.contracts.response_phase import map_lifecycle_phase_to_response_phase

from .context_builder import build_sources
from .retriever import SourceRetrievalStatus
from .types import InvestigationContext, KnowledgeReference, PlaybookReference


@dataclass
class GroundedContext:
    investigationSummary: str
    relevantKnowledge: list[dict]
    relevantPlaybooks: list[dict]
    evidenceSummary: dict
    mitreContext: list[dict]
    sourceReferences: list[dict]
    confidence: float
    limitations: list[str]
    knowledgeStatus: str  # "NO_MATCH" | "MATCHED"
    playbookStatus: str  # "NO_MATCH" | "MATCHED"
    noRelevantPlaybook: bool
    insufficientKnowledge: bool

    def to_dict(self) -> dict:
        return {
            "investigationSummary": self.investigationSummary,
            "relevantKnowledge": self.relevantKnowledge,
            "relevantPlaybooks": self.relevantPlaybooks,
            "evidenceSummary": self.evidenceSummary,
            "mitreContext": self.mitreContext,
            "sourceReferences": self.sourceReferences,
            "confidence": self.confidence,
            "limitations": self.limitations,
            "knowledgeStatus": self.knowledgeStatus,
            "playbookStatus": self.playbookStatus,
            "noRelevantPlaybook": self.noRelevantPlaybook,
            "insufficientKnowledge": self.insufficientKnowledge,
        }


_EXCERPT_LENGTH = 500


def _excerpt(document: dict) -> str:
    return (document.get("content") or "")[:_EXCERPT_LENGTH]


class GroundedContextBuilder:
    def build(
        self,
        investigation_context: InvestigationContext,
        knowledge_documents: list[dict],
        playbook_documents: list[dict],
        knowledge_retrieval_status: SourceRetrievalStatus,
        playbook_retrieval_status: SourceRetrievalStatus,
    ) -> GroundedContext:
        # The ONLY inputs to these four flags: whether retrieval, after
        # re-ranking and relevance filtering, actually left anything in
        # each list. Never influenced by retrieval_status, confidence, or
        # any later LLM step — see this module's own docstring.
        knowledge_status = "MATCHED" if knowledge_documents else "NO_MATCH"
        playbook_status = "MATCHED" if playbook_documents else "NO_MATCH"
        insufficient_knowledge = knowledge_status == "NO_MATCH"
        no_relevant_playbook = playbook_status == "NO_MATCH"

        relevant_knowledge = [
            KnowledgeReference(
                documentId=document.get("documentId", ""),
                title=document.get("title", ""),
                source=document.get("source", ""),
                sourceProvider=(document.get("metadata") or {}).get("sourceProvider"),
                score=float(document.get("score") or 0.0),
                excerpt=_excerpt(document),
                documentReference=(document.get("metadata") or {}).get("documentReference", ""),
                chunkId=document.get("chunkId"),
                sourceRepository=(document.get("metadata") or {}).get("sourceRepository"),
                sourcePath=(document.get("metadata") or {}).get("sourcePath"),
                rerankBreakdown=document.get("rerankBreakdown") or {},
            ).to_dict()
            for document in knowledge_documents
        ]
        relevant_playbooks = [
            PlaybookReference(
                documentId=document.get("documentId", ""),
                title=document.get("title", ""),
                sourceProvider=(document.get("metadata") or {}).get("sourceProvider"),
                scenario=(document.get("metadata") or {}).get("scenario"),
                phase=(document.get("metadata") or {}).get("phase"),
                score=float(document.get("score") or 0.0),
                excerpt=_excerpt(document),
                documentReference=(document.get("metadata") or {}).get("documentReference", ""),
                chunkId=document.get("chunkId"),
                sourceRepository=(document.get("metadata") or {}).get("sourceRepository"),
                sourcePath=(document.get("metadata") or {}).get("sourcePath"),
                responsePhase=map_lifecycle_phase_to_response_phase((document.get("metadata") or {}).get("phase")),
                rerankBreakdown=document.get("rerankBreakdown") or {},
            ).to_dict()
            for document in playbook_documents
        ]

        # Reuses context_builder.build_sources rather than re-deriving
        # source-dedup logic a second time — one unique entry per
        # documentId across BOTH sets (a source reference doesn't care
        # which collection it came from).
        source_references = build_sources(knowledge_documents + playbook_documents)

        mitre_context = [
            {"techniqueId": technique.technique_id, "techniqueName": technique.technique_name}
            for technique in investigation_context.mitreTechniques
        ]

        evidence_summary = {
            "iocCount": len(investigation_context.iocs),
            "behaviors": investigation_context.behaviors,
            "evidence": investigation_context.evidence,
        }

        scores = [float(document.get("score") or 0.0) for document in (knowledge_documents + playbook_documents)]
        confidence = round(sum(scores) / len(scores), 4) if scores else 0.0

        limitations: list[str] = []
        if insufficient_knowledge:
            limitations.append("No relevant knowledge base content was found above the configured relevance threshold.")
        if no_relevant_playbook:
            limitations.append(
                "No relevant response playbook was found — no automated containment/eradication guidance is available; manual analyst review is required."
            )
        if knowledge_retrieval_status != "OK":
            limitations.append(f"Knowledge base search degraded ({knowledge_retrieval_status}) — results may be incomplete.")
        if playbook_retrieval_status != "OK":
            limitations.append(f"Playbook search degraded ({playbook_retrieval_status}) — results may be incomplete.")

        investigation_summary = (
            f"Alert {investigation_context.alertId or 'unknown'} classified as "
            f"{investigation_context.alertClassification} (risk: {investigation_context.incidentRisk or 'unknown'}). "
            f"{len(investigation_context.iocs)} IOC(s) and {len(investigation_context.mitreTechniques)} "
            "MITRE technique(s) observed."
        )
        if investigation_context.scenario:
            investigation_summary += f" Scenario: {investigation_context.scenario}."

        return GroundedContext(
            investigationSummary=investigation_summary,
            relevantKnowledge=relevant_knowledge,
            relevantPlaybooks=relevant_playbooks,
            evidenceSummary=evidence_summary,
            mitreContext=mitre_context,
            sourceReferences=source_references,
            confidence=confidence,
            limitations=limitations,
            knowledgeStatus=knowledge_status,
            playbookStatus=playbook_status,
            noRelevantPlaybook=no_relevant_playbook,
            insufficientKnowledge=insufficient_knowledge,
        )
