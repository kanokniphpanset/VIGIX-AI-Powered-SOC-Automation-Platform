import logging
import httpx

logger = logging.getLogger("soar.ai-orchestrator")


async def notify_backend_of_decision(
    backend_url: str,
    incident_id: str,
    title: str,
    severity: str,
    summary: str,
    decision: str,
    risk_score: float,
) -> None:
    """
    Calls the backend's POST /api/v1/webhooks/orchestrator/callback after a
    pipeline run completes and its results are persisted. The backend decides
    what to do with the decision (currently: trigger the n8n playbook-runner
    workflow via IWorkflowEnginePort) — this function's only job is to hand
    off the outcome, not to know or care what happens next.

    Failure here is logged, not raised — the incident and all agent results
    are already saved by the time this runs, so a failed callback shouldn't
    turn a successful pipeline run into a 500 response.
    """
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(
                f"{backend_url.rstrip('/')}/api/v1/webhooks/orchestrator/callback",
                json={
                    "incidentId": incident_id,
                    "title": title,
                    "severity": severity,
                    "summary": summary,
                    "decision": decision,
                    "riskScore": risk_score,
                },
            )
            res.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Failed to notify backend of decision for incident %s: %s", incident_id, exc)
