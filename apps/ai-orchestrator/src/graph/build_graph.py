from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

from src.graph.state import GraphState
from src.graph.router import after_validation, after_decision
from src.graph import checkpointer as checkpointer_module
from src.agents.threat_intel_agent import agent as threat_intel_agent
from src.agents.mitre_agent import agent as mitre_agent
from src.agents.rag_agent import agent as rag_agent
from src.agents.llm_analyst_agent import agent as llm_analyst_agent
from src.agents.validation_agent import agent as validation_agent
from src.agents.decision_agent import agent as decision_agent
from src.agents.classification_agent import agent as classification_agent
from src.agents.recommendation_agent import agent as recommendation_agent


def build_graph(checkpointer: AsyncPostgresSaver | None = None):
    """
    Wires all 9 agents into a single LangGraph StateGraph.

    Shape:
      START -> threat_intel -> mitre -> rag   (sequential enrichment; no ML severity node)
            -> llm_analyst
            -> validation
                 -> (fail, retries left) -> threat_intel        (loop back)

                 -> (pass)               -> recommendation_agent
            -> recommendation_agent -> decision_agent -> END  (all outcomes converge here)
            

    recommendation_agent (Investigation -> Recommendation capability — see
    agents/recommendation_agent/) sits strictly between validation and
    decision_agent: it reads the same already-enriched AgentState
    decision_agent itself reads (evidence/classification/mitre/threat
    intel/risk), and decision_agent's own PolicyContext/PolicyEngine/
    ApprovalEngine remain completely untouched by it — the recommendation
    report rides alongside in AgentState for persistence/audit only (see
    api/output_contract.py).

    threat_intel -> mitre -> rag is sequential (not a parallel fan-out) on
    purpose: RagAgent's query builder reads MitreAgent's technique matches and
    ThreatIntelAgent's IOC-derived malware family/threat categories out of
    AgentState (see rag_agent/query_builder.py::extract_query_input) to build
    a grounded semantic query. Running them in parallel would mean RagAgent
    fires before either has written its output, so it must run strictly after
    both.
    """
    graph = StateGraph(GraphState)

    graph.add_node("threat_intel", threat_intel_agent.run)
    graph.add_node("mitre", mitre_agent.run)
    graph.add_node("rag", rag_agent.run)
    graph.add_node("llm_analyst", llm_analyst_agent.run)
    graph.add_node("validation", validation_agent.run)
    graph.add_node("recommendation_agent", recommendation_agent.run)
    # NOTE: named "decision_agent", not "decision" — AgentState already has a
    # field called "decision" (the agent's own output value), and LangGraph
    # forbids a node name colliding with a state key.
    graph.add_node("decision_agent", decision_agent.run)

    # Sequential enrichment chain: threat_intel -> mitre -> rag (VIGIX has no AI severity node).
    # Each node reads the prior nodes' output out of AgentState (see the
    # module docstring above for why rag specifically needs this ordering).
    graph.add_edge(START, "threat_intel")
    graph.add_edge("threat_intel", "mitre")
    graph.add_edge("mitre", "rag")

    graph.add_edge("rag", "llm_analyst")
    graph.add_edge("llm_analyst", "validation")

    graph.add_conditional_edges(
        "validation",
        after_validation,
        {"retry": "threat_intel", "proceed": "recommendation_agent"},
    )
    graph.add_edge("recommendation_agent", "decision_agent")

    graph.add_conditional_edges(
        "decision_agent",
        after_decision,
        {
            "auto_response": END,
            "human_approval": END,
            "dismiss": END,
            "escalate": END,
        },
    )

    
    # Phase 4 — persistent PostgreSQL checkpointing (spec section 9).
    # `checkpointer` defaults to None so this function (and the
    # module-level `compiled_graph` singleton below) stays safe to call at
    # plain import time — e.g. pytest collecting this module — with no
    # running event loop required. Real requests get a checkpointer-bound
    # graph via get_checkpointed_graph() instead (see below).
    return graph.compile(checkpointer=checkpointer)


def build_analysis_graph():
    """
    Universal Analysis Graph (LangGraph Integration task; decision_agent
    added in the Decision Agent + Policy Engine task) — the
    normalization-driven pipeline behind POST /pipeline/alerts. Deliberately
    a SEPARATE graph from build_graph()'s existing 9-node one above: no
    validation retry loop, no business_analytics, no feedback, no SOAR
    execution. decision_agent here is the SAME module/logic
    (agents/decision_agent/) build_graph()'s own 9-node graph already uses
    — not a second implementation — it now simply consumes
    state["classification"] too (decision_engine.py::build_policy_context,
    extended, not rewritten). This graph stops at DecisionResult — SOAR
    execution is a later phase, and /pipeline/run (with its full
    validation/decision/business/feedback flow) is left completely
    untouched.

    Shape:
      START -> threat_intel -> mitre -> rag -> llm_analyst -> classification_agent -> recommendation_agent -> decision_agent -> END

    Every step is sequential (real data dependencies: mitre reads threat_intel_report; rag's query builder reads
    mitre's techniques and threat_intel's IOC data; llm_analyst reads rag_result). There is NO ML severity node:
    VIGIX's severity is the Wazuh rule-level mapping done by the backend and passed in as state["severity"]; no
    agent generates, suggests or changes it.

    No extra try/except wrapping is added around any node here: threat_intel,
    mitre, rag, and llm_analyst each already catch their own risky operations
    and never raise out of run() (see each module's own docstring/code —
    verified, not assumed, before writing this function); classification_agent has its
    own last-resort try/except (contracts/error_builder.py::build_error).
    Partial failure isolation is therefore already structural at the agent
    level — this graph does not need to implement it again.

    Not named "classification" — AgentState already has a `classification`
    field, and LangGraph forbids a node name colliding with a state key
    (same reason the graph above names its decision node "decision_agent",
    not "decision"). decision_agent.run() already has its own top-level
    try/except that fails SAFE to human_approval_required (never crashes,
    never defaults to an automatic/destructive outcome — see
    decision_agent/agent.py::_fail_safe_result), so it needs no extra
    wrapping here either.

    No checkpointer: this graph is a single-shot, non-resumable analysis
    (no retry loop exists to resume), so — per this task's own "do not
    introduce persistence unless required" boundary — it is never compiled
    against Postgres, unlike build_graph()'s checkpointed graph.
    """
    graph = StateGraph(GraphState)

    graph.add_node("threat_intel", threat_intel_agent.run)
    graph.add_node("mitre", mitre_agent.run)
    graph.add_node("rag", rag_agent.run)
    graph.add_node("llm_analyst", llm_analyst_agent.run)
    graph.add_node("classification_agent", classification_agent.run)
    graph.add_node("recommendation_agent", recommendation_agent.run)
    graph.add_node("decision_agent", decision_agent.run)

    graph.add_edge(START, "threat_intel")
    graph.add_edge("threat_intel", "mitre")
    graph.add_edge("mitre", "rag")
    graph.add_edge("rag", "llm_analyst")
    graph.add_edge("llm_analyst", "classification_agent")
    graph.add_edge("classification_agent", "recommendation_agent")
    graph.add_edge("recommendation_agent", "decision_agent")
    graph.add_edge("decision_agent", END)

    return graph.compile()


# Checkpointer-free singleton — safe to import anywhere (tests included),
# never touches Postgres. NOT what real /pipeline/run requests use.
compiled_graph = build_graph()

# The Universal Analysis Graph singleton — used directly by
# api/routes/ingest_alert.py (POST /pipeline/alerts). No lazy
# checkpointer-bound variant exists for this graph (see build_analysis_graph's
# own docstring for why), so this is what real requests use too, not just tests.
analysis_graph = build_analysis_graph()

_checkpointed_graph = None


async def get_checkpointed_graph():
    """
    Lazily builds (once) and returns a graph compiled with the real
    PostgreSQL-backed checkpointer, for run_pipeline.py's actual request
    path. Cached after first call — init_checkpointer() itself is already
    idempotent, but there's no need to recompile the graph on every
    request either.
    """
    global _checkpointed_graph
    if _checkpointed_graph is not None:
        return _checkpointed_graph
    real_checkpointer = await checkpointer_module.init_checkpointer()
    _checkpointed_graph = build_graph(checkpointer=real_checkpointer)
    return _checkpointed_graph
