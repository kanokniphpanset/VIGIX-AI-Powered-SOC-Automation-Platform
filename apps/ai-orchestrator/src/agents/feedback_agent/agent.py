from src.graph.state import AgentState


async def run(state: AgentState) -> AgentState:
    """
    FeedbackAgent — closes out the pipeline run. In the automated (non-approval)
    path there's no analyst feedback yet, so this just marks the run complete.
    Actual analyst feedback (rating, comments, playbook suggestions) is
    submitted later via the backend's POST /api/v1/feedback endpoint and
    written to analyst_feedback — this node's job is to make sure a run always
    terminates cleanly, whether or not feedback exists yet.
    """
    return {"feedback_logged": True, "trace": ["FeedbackAgent: pipeline run complete"]}
