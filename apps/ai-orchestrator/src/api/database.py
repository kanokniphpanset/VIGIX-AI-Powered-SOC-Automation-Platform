import json
import uuid
from datetime import datetime, timezone
import psycopg


def fetch_alert(database_url: str, alert_id: str, tenant_id: str) -> dict | None:
    """Reads the alert row the backend already saved (via POST /webhooks/siem/:source)."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, tenant_id, external_alert_id, siem_source, raw_payload, severity, status, received_at
                FROM alerts
                WHERE id = %s AND tenant_id = %s
                """,
                (alert_id, tenant_id),
            )
            row = cur.fetchone()
            if not row:
                return None
            columns = [
                "id", "tenant_id", "external_alert_id", "siem_source",
                "raw_payload", "severity", "status", "received_at",
            ]
            return dict(zip(columns, row))


def create_agent_execution(database_url: str, incident_id: str) -> str:
    """Creates the agent_executions row that ties this LangGraph run to an incident."""
    execution_id = str(uuid.uuid4())
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_executions (id, incident_id, graph_run_id, status, started_at)
                VALUES (%s, %s, %s, 'running', %s)
                """,
                (execution_id, incident_id, execution_id, datetime.now(timezone.utc)),
            )
        conn.commit()
    return execution_id


def ensure_incident_for_alert(database_url: str, alert: dict) -> str:
    """
    Creates an incident for the alert if one doesn't already exist, so the AI
    pipeline always has an incident_id to attach its results to. Mirrors what
    CreateIncidentFromAlert.usecase.ts does on the backend side — this is the
    orchestrator's own copy since it runs as an independent service and
    shouldn't have to call back into the Node backend just to get an id.
    """
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM incidents WHERE alert_id = %s", (alert["id"],))
            existing = cur.fetchone()
            if existing:
                return existing[0]

            incident_id = str(uuid.uuid4())
            raw_payload = alert["raw_payload"]
            title = (
                raw_payload.get("rule", {}).get("description")
                if isinstance(raw_payload.get("rule"), dict)
                else raw_payload.get("rule") or raw_payload.get("search_name") or raw_payload.get("title")
            ) or f"Incident from {alert['siem_source']} alert {alert['external_alert_id']}"

            cur.execute(
                """
                INSERT INTO incidents (id, tenant_id, alert_id, title, status, priority, opened_at)
                VALUES (%s, %s, %s, %s, 'investigating', %s, %s)
                """,
                (incident_id, alert["tenant_id"], alert["id"], title, alert["severity"], datetime.now(timezone.utc)),
            )
            cur.execute(
                """
                INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, occurred_at)
                VALUES (%s, %s, 'created', %s, 'ai-orchestrator', %s)
                """,
                (
                    str(uuid.uuid4()),
                    incident_id,
                    f"Incident opened automatically by AI pipeline from {alert['siem_source']} alert",
                    datetime.now(timezone.utc),
                ),
            )
        conn.commit()
    return incident_id


def persist_agent_results(database_url: str, execution_id: str, incident_id: str, state: dict) -> None:
    """
    Writes every agent's output to agent_results, plus the structured tables
    (threat_intel_iocs, mitre_mappings, risk_scores, decisions) so the
    dashboard's existing GET /incidents/:id/* endpoints have real data to serve.
    """
    now = datetime.now(timezone.utc)

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            agent_outputs = {
                "threat_intel": {"iocs": state.get("iocs", [])},
                "mitre": {"mitre_techniques": state.get("mitre_techniques", [])},
                "rag": {"rag_matches": state.get("rag_matches", [])},
                "ml_risk": {
                    "risk_score": state.get("risk_score"),
                    "severity_prediction": state.get("severity_prediction"),
                    "confidence_score": state.get("confidence_score"),
                },
                "llm_analyst": {
                    "llm_summary": state.get("llm_summary"),
                    "llm_recommendation": state.get("llm_recommendation"),
                },
                "validation": {
                    "validation_passed": state.get("validation_passed"),
                    "validation_notes": state.get("validation_notes", []),
                },
                "decision": {
                    "decision": state.get("decision"),
                    "requires_approval": state.get("requires_approval"),
                },
                "business_analytics": state.get("kpi_snapshot", {}),
                "feedback": {"feedback_logged": state.get("feedback_logged", False)},
            }

            for agent_name, output in agent_outputs.items():
                cur.execute(
                    """
                    INSERT INTO agent_results (id, agent_execution_id, agent_name, output, confidence, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()),
                        execution_id,
                        agent_name,
                        json.dumps(output, default=str),
                        state.get("confidence_score"),
                        now,
                    ),
                )

            for ioc in state.get("iocs", []):
                cur.execute(
                    """
                    INSERT INTO threat_intel_iocs (id, incident_id, ioc_type, ioc_value, source, reputation_score, raw_response)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()), incident_id, ioc["ioc_type"], ioc["ioc_value"],
                        ioc.get("source", "aggregated"), ioc.get("reputation_score"),
                        json.dumps(ioc.get("raw_response", {}), default=str),
                    ),
                )

            for technique in state.get("mitre_techniques", []):
                cur.execute(
                    """
                    INSERT INTO mitre_mappings (id, incident_id, technique_id, tactic, confidence)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (str(uuid.uuid4()), incident_id, technique["technique_id"], technique["tactic"], technique.get("confidence")),
                )

            if state.get("risk_score") is not None:
                cur.execute(
                    """
                    INSERT INTO risk_scores (id, incident_id, score, severity_prediction, confidence_score, model_version)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()), incident_id, state["risk_score"], state.get("severity_prediction"),
                        state.get("confidence_score"), "xgboost-bootstrap-v1",
                    ),
                )

            if state.get("decision"):
                cur.execute(
                    """
                    INSERT INTO decisions (id, incident_id, decision_type, risk_threshold_used, requires_approval)
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        str(uuid.uuid4()), incident_id, state["decision"],
                        state.get("risk_score", 0.0), state.get("requires_approval", False),
                    ),
                )

            cur.execute(
                """
                UPDATE agent_executions
                SET status = 'completed', completed_at = %s, trace = %s
                WHERE id = %s
                """,
                (now, json.dumps(state.get("trace", []), default=str), execution_id),
            )

            cur.execute(
                """
                INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, occurred_at)
                VALUES (%s, %s, 'ai_analysis_complete', %s, 'ai-orchestrator', %s)
                """,
                (
                    str(uuid.uuid4()), incident_id,
                    f"AI pipeline completed: decision={state.get('decision')}, risk_score={state.get('risk_score')}",
                    now,
                ),
            )
        conn.commit()
