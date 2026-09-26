import operator
from typing import Annotated, Any, TypedDict


class AgentState(TypedDict, total=False):
    """Shared state threaded through every LangGraph node.
    Nodes return only the keys they changed; LangGraph merges them.
    NOTE: no key may share a name with a node ("mitre", "validation", ...)."""

    # --- input ---
    alert_id: str
    tenant_id: str
    graph_run_id: str
    siem_source: str
    raw_alert: dict[str, Any]
    normalized_alert: dict[str, Any]
    alert_text: str
    severity: str
    asset_id: str
    asset_known: bool
    asset_criticality: Any
    organization_regulated: bool
    business_policy_tags: Any

    # --- threat intel ---
    iocs: list[dict[str, Any]]
    threat_intel_report: dict[str, Any]

    # --- mitre ---
    mitre_techniques: list[dict[str, Any]]
    mitre_mapping_report: dict[str, Any]

    # --- rag ---
    rag_result: dict[str, Any]

    # --- llm analyst ---
    llm_summary: str
    # "LLM" when llm_summary is a real LLM analysis, "FAILED" when the LLM call failed (llm_summary empty).
    analysis_source: str
    llm_recommendation: str
    llm_key_findings: Any

    # --- validation ---
    validation_passed: bool
    validation_status: str
    validation_notes: Any
    validation_checks: Any
    validation_retries: int
    retry_count: int

    # --- classification / recommendation / decision ---
    classification: dict[str, Any]
    investigation_recommendation_report: dict[str, Any]
    decision: Any
    decision_result: Any
    requires_approval: bool

    # --- business / feedback (agents removed, keys still read) ---
    kpi_snapshot: Any
    feedback_logged: bool

    # --- scaffold-era fields (kept so existing callers don't break) ---
    incident_id: str
    alert: dict[str, Any]
    ti_results: list[dict[str, Any]]
    runbook_snapshot: dict[str, Any]
    analyst_report: dict[str, Any]
    plan: dict[str, Any]
    cycle: int
    parent_plan_id: str | None
    trigger: str
    evidence_ids: list[str]

    # --- accumulators (each node appends) ---
    trace: Annotated[list[str], operator.add]
    errors: Annotated[list[dict[str, Any]], operator.add]
    structured_errors: Annotated[list[dict[str, Any]], operator.add]


# Alias: nodes.py / edges.py import the scaffold name.
GraphState = AgentState