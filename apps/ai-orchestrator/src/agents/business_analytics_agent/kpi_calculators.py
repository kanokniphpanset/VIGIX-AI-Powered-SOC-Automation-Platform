import psycopg
from datetime import datetime, timedelta


def compute_kpis(database_url: str, tenant_id: str) -> dict:
    """
    Computes MTTD/MTTR/automation rate over the trailing 30 days for a tenant,
    reading directly from the same Postgres tables the backend writes to
    (incidents, agent_executions, decisions). This is a read-only query —
    BusinessAnalyticsAgent never writes to incidents/alerts, only to its own
    kpi_metrics snapshot (persisted by the caller in database.py).
    """
    since = datetime.utcnow() - timedelta(days=30)

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    COUNT(*) AS total_incidents,
                    AVG(mttd_seconds) FILTER (WHERE mttd_seconds IS NOT NULL) AS mttd_avg,
                    AVG(mttr_seconds) FILTER (WHERE mttr_seconds IS NOT NULL) AS mttr_avg
                FROM incidents
                WHERE tenant_id = %s AND opened_at >= %s
                """,
                (tenant_id, since),
            )
            row = cur.fetchone()
            total_incidents, mttd_avg, mttr_avg = row or (0, None, None)

            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE decision_type = 'auto_response') AS auto_count,
                    COUNT(*) AS total_decisions
                FROM decisions d
                JOIN incidents i ON i.id = d.incident_id
                WHERE i.tenant_id = %s AND d.created_at >= %s
                """,
                (tenant_id, since),
            )
            auto_count, total_decisions = cur.fetchone() or (0, 0)

    automation_rate = round((auto_count / total_decisions) * 100, 1) if total_decisions else 0.0

    # Analyst time saved / cost saving are illustrative estimates — replace the
    # per-incident minute/dollar assumptions with your SOC's actual figures.
    minutes_saved_per_automated_incident = 25
    analyst_hourly_cost_usd = 45

    analyst_time_saved_hours = round((auto_count * minutes_saved_per_automated_incident) / 60, 1)
    cost_saving_usd = round(analyst_time_saved_hours * analyst_hourly_cost_usd, 2)

    return {
        "total_incidents": total_incidents,
        "mttd_avg_seconds": float(mttd_avg) if mttd_avg is not None else None,
        "mttr_avg_seconds": float(mttr_avg) if mttr_avg is not None else None,
        "automation_rate_pct": automation_rate,
        "analyst_time_saved_hours": analyst_time_saved_hours,
        "cost_saving_usd": cost_saving_usd,
        "period_days": 30,
    }
