-- reset-eval-db.sql — run ONLY against the evaluation database (soar_eval).
-- Clears workflow/transactional data so a Clean Run starts empty; keeps the Knowledge Base
-- (actions, mitre_techniques, playbooks + steps, policies + rules, runbooks) plus tenants/users/recipients.
-- Also drops policies that are NOT part of the seeded baseline (analyst-created RESPONSE_GUIDANCE group
-- policies "RG-*"): they steer allowed actions per incident group and would leak earlier experiments
-- into a Clean Run. Each removal is echoed so it is recorded in the run log, never silent.
\set ON_ERROR_STOP on
DO $$ BEGIN
  IF current_database() <> 'soar_eval' THEN RAISE EXCEPTION 'refusing to reset database %', current_database(); END IF;
END $$;

SELECT 'removing non-baseline policy: ' || code AS note FROM policies WHERE code LIKE 'RG-%';
DELETE FROM policy_rules WHERE policy_id IN (SELECT id FROM policies WHERE code LIKE 'RG-%');
DELETE FROM policies WHERE code LIKE 'RG-%';

TRUNCATE TABLE
  alerts, alert_scenario_tags, analyst_feedback, incidents, incident_alerts, incident_timeline,
  investigations, evidence, evidence_iocs, threat_intel_iocs, mitre_mappings, risk_scores, decisions,
  agent_executions, agent_results, recommendations, recommendation_steps, playbook_snapshots,
  response_plans, approvals, step_executions, verifications, playbook_executions, kpi_metrics,
  audit_logs, in_app_notifications, in_app_notification_reads, notification_deliveries,
  checkpoints, checkpoint_blobs, checkpoint_writes
RESTART IDENTITY CASCADE;

SELECT 'KB after reset' AS note,
  (SELECT count(*) FROM actions) AS actions, (SELECT count(*) FROM mitre_techniques) AS mitre,
  (SELECT count(*) FROM playbooks) AS playbooks, (SELECT count(*) FROM playbook_steps) AS playbook_steps,
  (SELECT count(*) FROM policies) AS policies, (SELECT count(*) FROM runbooks) AS runbooks,
  (SELECT count(*) FROM tenants) AS tenants, (SELECT count(*) FROM alerts) AS alerts, (SELECT count(*) FROM incidents) AS incidents;
