import operator
from typing import Annotated, Literal, TypedDict


class Ioc(TypedDict, total=False):
    ioc_type: str  # ip | domain | hash | url
    ioc_value: str
    source: str
    reputation_score: float | None
    raw_response: dict
    # Richer explainable-verdict fields produced by ThreatIntelAgent's scoring
    # service. Optional so existing consumers (feature_engineering.py,
    # api/database.py) that only read the fields above are unaffected.
    verdict: str  # MALICIOUS | SUSPICIOUS | CLEAN | UNKNOWN
    risk_level: str  # LOW | MEDIUM | HIGH | CRITICAL
    threat_score: float  # 0-100
    confidence: float  # 0-1
    malicious: bool
    suspicious: bool
    categories: list[str]
    sources: list[str]
    explanation: list[str]
    analyzed_at: str
    providers: list[dict]


class MitreTechniqueMatch(TypedDict, total=False):
    technique_id: str
    name: str
    tactic: str
    confidence: float


class RagMatch(TypedDict, total=False):
    kind: str  # playbook | sop | similar_incident
    id: str
    title: str
    score: float


class AgentState(TypedDict, total=False):
    """
    Shared state threaded through every node in the LangGraph pipeline.
    Each agent reads what it needs and writes its own slice back.
    """

    # Input
    alert_id: str
    tenant_id: str
    graph_run_id: str
    raw_alert: dict
    siem_source: str
    alert_text: str  # flattened text used for embeddings / LLM context

    # ThreatIntelAgent output
    iocs: list[Ioc]
    # Full structured report (summary/highest-risk/overall verdict) — see
    # agents/threat_intel_agent/types.py::ThreatIntelReport. Kept as a plain
    # dict here (not the dataclass) since AgentState is a TypedDict threaded
    # through LangGraph and persisted as JSON.
    threat_intel_report: dict

    # MitreAgent output
    mitre_techniques: list[MitreTechniqueMatch]

    # RagAgent output
    rag_matches: list[RagMatch]

    # MlRiskAgent output
    risk_score: float
    severity_prediction: str
    confidence_score: float

    # LlmAnalystAgent output
    llm_summary: str
    llm_recommendation: str

    # ValidationAgent output
    validation_passed: bool
    validation_notes: list[str]

    # DecisionAgent output
    decision: Literal["auto_response", "human_approval", "dismiss"]
    requires_approval: bool

    # BusinessAnalyticsAgent output
    kpi_snapshot: dict

    # FeedbackAgent output
    feedback_logged: bool

    # Control
    retry_count: int
    # Annotated with operator.add so parallel nodes (threat_intel, mitre, rag all
    # run in the same superstep) can each append their own trace entry without
    # LangGraph treating it as a conflicting write to the same key — each node
    # returns only its own new entry as a one-item list, and the reducer
    # concatenates them (and every other node's) across the whole run.
    trace: Annotated[list[str], operator.add]
