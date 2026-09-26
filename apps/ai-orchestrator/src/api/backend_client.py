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
    llm_model: str | None = None,
    service_token: str | None = None,
) -> None:
    """
    Calls the backend's POST /api/v1/webhooks/orchestrator/callback after a
    pipeline run completes and its results are persisted. The backend decides
    what to do with the decision (currently: trigger the n8n playbook-runner
    workflow via IWorkflowEnginePort) — this function's only job is to hand
    off the outcome, not to know or care what happens next.

    Phase 9: also carries which model actually produced this analysis
    (llm_model) — the real settings.llm_model, not a placeholder (VIGIX has no ML severity model) — so the backend's audit trail can
    record "ai_model_invoked" with genuine model identity instead of omitting
    it. Both optional: a caller with nothing to report just omits them.

    Phase 5.8: `service_token` (settings.backend_service_token) authenticates
    this call as the real ai-orchestrator service — the backend now rejects
    this callback without it (see orchestratorAuth.middleware.ts). Sent as a
    standard `Authorization: Bearer` header, never logged; an empty/unset
    token is still sent (as no header at all) rather than raising here, so a
    misconfigured deployment fails loudly with the backend's own 401 in its
    logs instead of a confusing exception in this one.

    Failure here is logged, not raised — the incident and all agent results
    are already saved by the time this runs, so a failed callback shouldn't
    turn a successful pipeline run into a 500 response.
    """
    headers = {"Authorization": f"Bearer {service_token}"} if service_token else {}
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
                    "llmModel": llm_model,
                },
                headers=headers,
            )
            res.raise_for_status()
    except httpx.HTTPError as exc:
        logger.warning("Failed to notify backend of decision for incident %s: %s", incident_id, exc)
