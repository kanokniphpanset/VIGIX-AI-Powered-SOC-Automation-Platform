from langgraph.graph import StateGraph, START, END

from src.graph.state import AgentState
from src.graph.router import after_validation, after_decision
from src.agents.threat_intel_agent import agent as threat_intel_agent
from src.agents.mitre_agent import agent as mitre_agent
from src.agents.rag_agent import agent as rag_agent
from src.agents.ml_risk_agent import agent as ml_risk_agent
from src.agents.llm_analyst_agent import agent as llm_analyst_agent
from src.agents.validation_agent import agent as validation_agent
from src.agents.decision_agent import agent as decision_agent
from src.agents.business_analytics_agent import agent as business_analytics_agent
from src.agents.feedback_agent import agent as feedback_agent


def build_graph():
    """
    Wires all 9 agents into a single LangGraph StateGraph.

    Shape:
      START -> [threat_intel, mitre, rag]  (parallel fan-out)
            -> ml_risk                      (fan-in: waits for all three)
            -> llm_analyst
            -> validation
                 -> (fail, retries left) -> threat_intel   (loop back)
                 -> (pass)               -> decision_agent
            -> decision_agent -> business_analytics  (all three decision outcomes converge here)
            -> feedback -> END
    """
    graph = StateGraph(AgentState)

    graph.add_node("threat_intel", threat_intel_agent.run)
    graph.add_node("mitre", mitre_agent.run)
    graph.add_node("rag", rag_agent.run)
    graph.add_node("ml_risk", ml_risk_agent.run)
    graph.add_node("llm_analyst", llm_analyst_agent.run)
    graph.add_node("validation", validation_agent.run)
    # NOTE: named "decision_agent", not "decision" — AgentState already has a
    # field called "decision" (the agent's own output value), and LangGraph
    # forbids a node name colliding with a state key.
    graph.add_node("decision_agent", decision_agent.run)
    graph.add_node("business_analytics", business_analytics_agent.run)
    graph.add_node("feedback", feedback_agent.run)

    # Parallel fan-out from START — LangGraph runs nodes with no dependency
    # edge between them in the same superstep.
    graph.add_edge(START, "threat_intel")
    graph.add_edge(START, "mitre")
    graph.add_edge(START, "rag")

    # Fan-in: ml_risk only runs once all three enrichment nodes have completed.
    graph.add_edge("threat_intel", "ml_risk")
    graph.add_edge("mitre", "ml_risk")
    graph.add_edge("rag", "ml_risk")

    graph.add_edge("ml_risk", "llm_analyst")
    graph.add_edge("llm_analyst", "validation")

    graph.add_conditional_edges(
        "validation",
        after_validation,
        {"retry": "threat_intel", "proceed": "decision_agent"},
    )

    graph.add_conditional_edges(
        "decision_agent",
        after_decision,
        {
            "auto_response": "business_analytics",
            "human_approval": "business_analytics",
            "dismiss": "business_analytics",
        },
    )

    graph.add_edge("business_analytics", "feedback")
    graph.add_edge("feedback", END)

    return graph.compile()


compiled_graph = build_graph()
