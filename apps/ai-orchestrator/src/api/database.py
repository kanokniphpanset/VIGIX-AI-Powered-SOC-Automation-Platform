import json
import uuid
from datetime import datetime, timezone
import psycopg



def _parse_iso_datetime(value: str | None) -> datetime | None:
    """DecisionResult's JSON-mode dump serializes datetimes as ISO-8601
    strings (see decision_agent/models.py's to_json()/model_dump(mode="json"))
    — this turns one back into a real datetime for a timestamptz column.
    Never fabricates a value: returns None if absent or unparseable."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def get_incident_title(database_url: str, incident_id: str) -> str:
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT title FROM incidents WHERE id = %s", (incident_id,))
            row = cur.fetchone()
            return row[0] if row else "Untitled incident"


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
    """Creates a NEW agent_executions row, self-contained — the fallback
    path for a /pipeline/run call with no execution_id (e.g. manual/local
    testing). The normal Phase 4 path uses ensure_execution_record()
    instead, against a row the backend webhook already created."""
    execution_id = str(uuid.uuid4())
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO agent_executions (id, incident_id, graph_run_id, status, started_at)
                VALUES (%s, %s, %s, 'RUNNING', %s)
                """,
                (execution_id, incident_id, execution_id, datetime.now(timezone.utc)),
            )
        conn.commit()
    return execution_id


def incident_for_execution(database_url: str, execution_id: str) -> str | None:
    """
    Incident of a backend-created (queued) AgentExecution. The backend creates the
    incident at ingestion and queues this row for it, so a queued run never needs —
    and must never — open an incident of its own.
    """
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT incident_id FROM agent_executions WHERE id = %s", (execution_id,))
            row = cur.fetchone()
    return row[0] if row and row[0] else None


def ensure_execution_record(database_url: str, execution_id: str | None, incident_id: str) -> str:
    """
    Phase 4 — the normal path. If the backend already created an
    AgentExecution row (execution_id given), backfill its incident_id
    (unknown at webhook-time — see the Prisma schema's own comment on
    AgentExecution) and mark it RUNNING; never creates a second row for
    the same alert. Falls back to create_agent_execution() for backward
    compatibility when no execution_id is supplied at all.
    """
    if not execution_id:
        return create_agent_execution(database_url, incident_id)

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE agent_executions
                SET incident_id = %s, status = 'RUNNING'
                WHERE id = %s
                """,
                (incident_id, execution_id),
            )
            if cur.rowcount == 0:
                # The id was supplied but doesn't exist — never silently
                # invent a row under a caller-supplied id; the backend is
                # the source of truth for execution identity.
                raise ValueError(f"AgentExecution {execution_id} not found — cannot backfill incident_id")
        conn.commit()
    return execution_id


def mark_execution_failed(database_url: str, execution_id: str, error_code: str, error_message: str) -> None:
    """Spec section 14's structured-error contract, persisted. Called from
    run_pipeline.py's own exception handler — the one path that previously
    left agent_executions permanently stuck at RUNNING with no
    completed_at (a real gap found during Phase 1's audit)."""
    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE agent_executions
                SET status = 'FAILED', error_code = %s, error_message = %s, completed_at = %s
                WHERE id = %s AND status NOT IN ('SUCCESS', 'PARTIAL_SUCCESS', 'FAILED', 'CANCELLED')
                """,
                (error_code, error_message[:2000], datetime.now(timezone.utc), execution_id),
            )
        conn.commit()


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


def final_execution_status(state: dict, output_contract: dict | None) -> tuple[str, str | None, str | None]:
    """
    Status written on agent_executions for a completed graph run: the output contract's own status, which counts
    BOTH legacy `errors` and structured errors (output_contract._compute_status) — a structured-only error (e.g. a
    RAG failure, a crashed validation) is no longer reported as SUCCESS. FAILED (a CRITICAL error, e.g. the LLM
    analysis failed) carries that error's code and message so the backend and the SOC see why.
    """
    if output_contract is None:
        return ("PARTIAL_SUCCESS" if state.get("errors") else "SUCCESS"), None, None
    status = output_contract.get("status") or "SUCCESS"
    if status != "FAILED":
        return status, None, None
    critical = next((e for e in output_contract.get("errors") or [] if e.get("severity") == "CRITICAL"), None) or {}
    return "FAILED", critical.get("code") or "AI_ANALYSIS_FAILED", (critical.get("message") or "AI analysis failed")[:2000]


def persist_agent_results(database_url: str, execution_id: str, incident_id: str, state: dict, output_contract: dict | None = None) -> None:
    """
    Writes every agent's output to agent_results, plus the structured tables
    (threat_intel_iocs, mitre_mappings, risk_scores, decisions) so the
    dashboard's existing GET /incidents/:id/* endpoints have real data to serve.
    """
    now = datetime.now(timezone.utc)
    # Phase 5.6 — the complete DecisionResult DecisionAgent produced, already
    # sitting in state in full (see decision_agent/agent.py::run()). Nothing
    # here is recomputed; every field below is read straight off this dict.
    decision_result = state.get("decision_result") or {}
    decision_id = str(uuid.uuid4()) if state.get("decision") else None

    with psycopg.connect(database_url) as conn:
        with conn.cursor() as cur:
            agent_outputs = {
                "threat_intel": {"iocs": state.get("iocs", []), "report": state.get("threat_intel_report", {})},
                "mitre": {"mitre_techniques": state.get("mitre_techniques", []), "report": state.get("mitre_mapping_report", {})},
                "rag": state.get("rag_result", {}),
                "llm_analyst": {
                    # "LLM" (real model answer, with the model) or "FAILED" — read by the backend to show / trust
                    # only real LLM analyses (backend domain/ai/analysisSource.ts). Never a fallback template.
                    "analysis_source": state.get("analysis_source"),
                    "model": (state.get("analyst_report") or {}).get("model"),
                    "llm_summary": state.get("llm_summary"),
                    "llm_recommendation": state.get("llm_recommendation"),
                    "llm_key_findings": state.get("llm_key_findings", []),
                },
                "validation": {
                    "validation_passed": state.get("validation_passed"),
                    "validation_notes": state.get("validation_notes", []),
                    "validation_status": state.get("validation_status"),
                    "validation_checks": state.get("validation_checks", []),
                },
                # Investigation -> Recommendation capability
                # (agents/recommendation_agent/) — the full
                # InvestigationRecommendationReport, already JSON-safe (see
                # recommendation_agent/agent.py::run()). Persisted through
                # this SAME generic agent_results mechanism as every other
                # agent — no new table/migration needed.
                "recommendation_agent": state.get("investigation_recommendation_report", {}),
                # Phase 5.6: the full DecisionResult, not just the 2 flat
                # fields every other agent's own entry used to be the only
                # exception to — falls back to the old shape if a caller
                # somehow reaches this with no decision_result at all.
                "decision": decision_result or {
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
                        None,
                        now,
                    ),
                )

            if decision_id:
                # Phase 8: recommended_action_ids is the real bridge the
                # backend's ResponseService reads to know which Response
                # Action Catalog action(s) an approved decision should
                # execute — previously decision_result.recommendedActions
                # was computed here but never persisted anywhere.
                recommended_action_ids = [
                    action.get("actionId")
                    for action in decision_result.get("recommendedActions", [])
                    if action.get("actionId")
                ]
                # Phase 5.6 — the rest of DecisionResult, persisted in full.
                # Inserted BEFORE threat_intel_iocs/mitre_mappings/risk_scores
                # below so their new (nullable) decision_id FK references a
                # row that already exists.
                approval_required = decision_result.get("approvalRequired") or {}
                evidence_summary = decision_result.get("evidenceSummary") or {}
                audit_information = decision_result.get("auditInformation") or {}
                audit_trace = {
                    "sourceDecisionId": audit_information.get("decisionId"),
                    "generatedBy": audit_information.get("generatedBy"),
                    "trace": audit_information.get("trace", []),
                }
                cur.execute(
                    """
                    INSERT INTO decisions (
                        id, incident_id, decision_type, risk_threshold_used, requires_approval, recommended_action_ids,
                        priority, approval_tier, execution_mode, confidence, correlation_id, policy_registry_version,
                        expiration_time, execution_id, recommended_actions, approval_requirement, policy_provenance,
                        evidence_summary, audit_trace, reasons, conditions, primary_asset_id, asset_criticality
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        decision_id, incident_id, state["decision"],
                        None, state.get("requires_approval", False),  # risk_threshold_used: legacy, no risk score any more
                        recommended_action_ids,
                        decision_result.get("priority"),
                        approval_required.get("tier"),
                        decision_result.get("executionMode"),
                        evidence_summary.get("confidenceScore"),
                        audit_information.get("correlationId"),
                        audit_information.get("policyRegistryVersion"),
                        _parse_iso_datetime(decision_result.get("expirationTime")),
                        execution_id,
                        json.dumps(decision_result.get("recommendedActions", []), default=str),
                        json.dumps(approval_required, default=str),
                        json.dumps(decision_result.get("policyIds", []), default=str),
                        json.dumps(evidence_summary, default=str),
                        json.dumps(audit_trace, default=str),
                        decision_result.get("reason", []),
                        decision_result.get("conditions", []),
                        # Increment 1 (NIST asset-criticality wiring) — the
                        # Decision Engine already computes both of these
                        # (see decision_engine.py::build_policy_context());
                        # this just persists what was previously discarded
                        # after the policy evaluation, so the backend's
                        # Automation Gate can cross-check it independently.
                        state.get("asset_id"),
                        state.get("asset_criticality"),
                    ),
                )

            # Idempotent per incident: a re-run (manual Run / Re-run AI Analysis)
            # must not duplicate an IOC or technique the incident already has.
            # On the first run for an incident nothing exists, so this is a no-op.
            for ioc in state.get("iocs", []):
                cur.execute(
                    """
                    INSERT INTO threat_intel_iocs (id, incident_id, ioc_type, ioc_value, source, reputation_score, raw_response)
                    SELECT %s, %s, %s, %s, %s, %s, %s
                    WHERE NOT EXISTS (
                        SELECT 1 FROM threat_intel_iocs WHERE incident_id = %s AND ioc_type = %s AND ioc_value = %s
                    )
                    """,
                    (
                        str(uuid.uuid4()), incident_id, ioc["ioc_type"], ioc["ioc_value"],
                        ioc.get("source", "aggregated"), ioc.get("reputation_score"),
                        json.dumps(ioc.get("raw_response", {}), default=str),
                        incident_id, ioc["ioc_type"], ioc["ioc_value"],
                    ),
                )

            # Columns match prisma/schema.prisma's MitreMapping; MitreAgent emits camelCase keys.
            for technique in state.get("mitre_techniques", []):
                technique_id = technique.get("techniqueId") or technique.get("technique_id")
                if not technique_id:
                    continue
                cur.execute(
                    """
                    INSERT INTO mitre_mappings (id, incident_id, technique_id, tactic, confidence)
                    SELECT %s, %s, %s, %s, %s
                    WHERE NOT EXISTS (SELECT 1 FROM mitre_mappings WHERE incident_id = %s AND technique_id = %s)
                    """,
                    (
                        str(uuid.uuid4()), incident_id, technique_id,
                        technique.get("tactic") or "", technique.get("confidence"),
                        incident_id, technique_id,
                    ),
                )

            # No AI severity: VIGIX's severity is the Wazuh rule-level mapping (backend). Nothing is written to risk_scores.

            # Spec section 10: partial provider failures (e.g. a threat-intel
            # provider timing out) are PARTIAL_SUCCESS, not FAILED — the graph
            # still produced a real result from incomplete evidence. A CRITICAL
            # error (the LLM analysis itself failed) is FAILED with its code.
            final_status, error_code, error_message = final_execution_status(state, output_contract)
            cur.execute(
                """
                UPDATE agent_executions
                SET status = %s, error_code = %s, error_message = %s, completed_at = %s, trace = %s, output_contract = %s
                WHERE id = %s
                """,
                (
                    final_status,
                    error_code,
                    error_message,
                    now,
                    json.dumps(state.get("trace", []), default=str),
                    json.dumps(output_contract, default=str) if output_contract is not None else None,
                    execution_id,
                ),
            )

            cur.execute(
                """
                INSERT INTO incident_timeline (id, incident_id, event_type, description, actor, occurred_at)
                VALUES (%s, %s, 'ai_analysis_complete', %s, 'ai-orchestrator', %s)
                """,
                (
                    str(uuid.uuid4()), incident_id,
                    (
                        f"AI analysis FAILED ({error_code}): {error_message} — no AI analysis was produced."
                        if final_status == "FAILED"
                        else f"AI pipeline completed: decision={state.get('decision')} (advisory). Severity stays the Wazuh severity ({state.get('severity') or 'unknown'})."
                    ),
                    now,
                ),
            )
        conn.commit()
