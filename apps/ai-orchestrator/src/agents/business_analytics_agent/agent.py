from src.graph.state import AgentState
from src.config.settings import settings
from .kpi_calculators import compute_kpis


async def run(state: AgentState) -> AgentState:
    """
    BusinessAnalyticsAgent — computes MTTD, MTTR, automation rate, analyst time
    saved, and cost saving for the tenant, reading real data from Postgres.
    Runs after every pipeline completion so the executive dashboard KPIs
    (see docs/architecture) stay current without a separate batch job.
    """
    try:
        kpis = compute_kpis(settings.database_url, state["tenant_id"])
    except Exception as exc:
        return {
            "kpi_snapshot": {},
            "trace": [f"BusinessAnalyticsAgent: KPI computation failed ({exc.__class__.__name__})"],
        }

    return {
        "kpi_snapshot": kpis,
        "trace": [f"BusinessAnalyticsAgent: automation_rate={kpis['automation_rate_pct']}%"],
    }
