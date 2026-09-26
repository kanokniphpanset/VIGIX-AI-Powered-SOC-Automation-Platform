"""Graph nodes. A node calls one agent / tool and writes the result into the state. No business logic here."""
from __future__ import annotations

from typing import Any

from .state import GraphState


def extract_ioc(state: GraphState) -> dict[str, Any]:
    """tools.ioc_extraction_tool -> {"iocs": [...]}"""
    raise NotImplementedError


def threat_intel(state: GraphState) -> dict[str, Any]:
    """agents.threat_intel_agent -> {"ti_results": [...]}"""
    raise NotImplementedError


def mitre(state: GraphState) -> dict[str, Any]:
    """agents.mitre_agent -> {"mitre": [...]}"""
    raise NotImplementedError


def rag(state: GraphState) -> dict[str, Any]:
    """runbook.resolver builds the snapshot; agents.rag_agent adds supporting text -> {"runbook_snapshot": {...}}"""
    raise NotImplementedError


def analyst(state: GraphState) -> dict[str, Any]:
    """agents.llm_analyst_agent -> {"analyst_report": {...}}"""
    raise NotImplementedError


def validation(state: GraphState) -> dict[str, Any]:
    """agents.validation_agent -> {"validation": {...}, "validation_retries": n}"""
    raise NotImplementedError


def decision(state: GraphState) -> dict[str, Any]:
    """agents.decision_agent -> {"decision": {...}}"""
    raise NotImplementedError


def recommendation(state: GraphState) -> dict[str, Any]:
    """agents.recommendation_agent -> {"plan": {...}}; services.response_plan_service validates before saving."""
    raise NotImplementedError
