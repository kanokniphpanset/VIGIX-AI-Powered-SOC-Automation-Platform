import logging
from fastapi import APIRouter

router = APIRouter()
logger = logging.getLogger("soar.ai-orchestrator")


@router.get("/{tenant_id}")
def get_kpis(tenant_id: str) -> dict:
    """
    KPI endpoint placeholder.

    BusinessAnalyticsAgent is not part of the current AI Orchestrator
    execution flow, so KPI computation is intentionally disabled for now.
    """
    return {
        "tenant_id": tenant_id,
        "status": "not_implemented",
        "message": "Business analytics KPI computation is disabled",
    }
