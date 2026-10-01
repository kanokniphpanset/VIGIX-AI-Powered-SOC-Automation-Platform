-- final-db-metrics.sql — the FINAL evaluation KPIs as plain SQL over PostgreSQL (no application code).
--
-- Usage (psql, against the final evaluation database):
--   psql -d soar_final_eval -f final-db-case-map.sql -f final-db-metrics.sql
-- final-db-case-map.sql creates the temp table final_cases(case_id, incident_id, expected_playbook, allowed_actions) —
-- the mapping of each test case to its incident and the FROZEN Ground Truth expectations (groundTruthReal.ts).
-- It is the only non-database input. Everything below reads: alerts, incidents, investigations, recommendations,
-- recommendation_steps, playbook_snapshots, playbooks, actions, approvals, response_plans, step_executions,
-- verifications, audit_logs, threat_intel_iocs, evidence, evidence_iocs.
--
-- NOTE stage 4 = the investigation exists and has started; an investigation is closed (COMPLETED) by the verification step, which is stage 11/12.
-- Metric → table → fields → calculation
--   Investigation Time    investigations.started_at, recommendations.created_at   T_Recommendation − T_InvestigationStart
--   Time-to-Decision      recommendations.created_at, approvals.decided_at         T_IR_Decision − T_Recommendation
--   Recommendation Compl. recommendation_steps(action_id,target,requires_approval), playbook_snapshots(playbook_code,
--                         policy_result), actions(enabled), threat_intel_iocs, evidence(_iocs), approvals(approval_role)
--   Workflow Completion   existence of the 12 workflow stages per incident
--   Intervention Rate     threat_intel_iocs.created_by <> 'system'
--   Retry Rate            audit_logs(action='RECOMMENDATION_GENERATION_FAILED', metadata.reason)
--   Verification          verifications(result, after_state->>'evidenceSource', matching_events, ...)

\pset format aligned
\echo '=== M1 Investigation Time (seconds) ==='
create temp view v_rec1 as
  select fc.case_id, fc.incident_id, r.id as rec_id, r.created_at as rec_at, r.snapshot_id, r.status as rec_status
  from final_cases fc
  join lateral (select * from recommendations x where x.incident_id = fc.incident_id and x.investigation_number = 1 order by x.recommendation_number limit 1) r on true;
create temp view v_inv as
  select v.case_id, round(extract(epoch from (v.rec_at - i.started_at))::numeric, 3) as seconds
  from v_rec1 v join investigations i on i.incident_id = v.incident_id and i.investigation_number = 1;
select * from v_inv order by case_id;
select count(*) n, round(avg(seconds), 3) mean, round((percentile_cont(0.5) within group (order by seconds))::numeric, 3) median,
       round(stddev_samp(seconds), 3) sd, min(seconds) min, max(seconds) max from v_inv;
select fc.case_id as case_without_recommendation from final_cases fc where fc.case_id not in (select case_id from v_rec1);

\echo '=== M2 Time-to-Decision (seconds, first IR decision) ==='
create temp view v_plan as
  select v.case_id, v.incident_id, v.rec_id, v.rec_at, rp.id as plan_id, rp.status as plan_status, rp.executed_at, rp.completed_at
  from v_rec1 v join lateral (select * from response_plans p where p.recommendation_id = v.rec_id order by p.created_at limit 1) rp on true;
create temp view v_ttd as
  select p.case_id, round(extract(epoch from (d.decided_at - p.rec_at))::numeric, 3) as seconds, d.status, d.approval_role
  from v_plan p join lateral (select * from approvals a where a.response_id = p.plan_id and a.status in ('approved','rejected') order by a.decided_at limit 1) d on true;
select * from v_ttd order by case_id;
select count(*) n, round(avg(seconds), 3) mean, round((percentile_cont(0.5) within group (order by seconds))::numeric, 3) median,
       round(stddev_samp(seconds), 3) sd, min(seconds) min, max(seconds) max from v_ttd;
select case_id as case_without_ir_decision from v_rec1 where case_id not in (select case_id from v_ttd);

\echo '=== M3 Recommendation Compliance — the six criteria recomputed in SQL ==='
create temp view v_steps as
  select v.case_id, v.incident_id, v.rec_id, rs.step_order, act.code as action, act.enabled as action_enabled, rs.target, rs.requires_approval,
         ps.playbook_code, ps.policy_result -> act.code as policy
  from v_rec1 v
  join recommendation_steps rs on rs.recommendation_id = v.rec_id and rs.action_id is not null
  left join actions act on act.id = rs.action_id
  left join playbook_snapshots ps on ps.id = v.snapshot_id
  where v.rec_status = 'VALIDATED';
create temp view v_targets as
  select fc.case_id, t.ioc_value as value
  from final_cases fc join threat_intel_iocs t on t.incident_id = fc.incident_id
  where t.created_by is not null and t.created_by <> 'system'                      -- analyst-confirmed IOCs
  union
  select fc.case_id, t.ioc_value from final_cases fc
    join investigations i on i.incident_id = fc.incident_id
    join evidence e on e.investigation_id = i.id
    join evidence_iocs ei on ei.evidence_id = e.id
    join threat_intel_iocs t on t.id = ei.ioc_id                                    -- evidence-linked IOCs
  union
  select fc.case_id, a.raw_payload -> 'agent' ->> 'name' from final_cases fc
    join incidents inc on inc.id = fc.incident_id join alerts a on a.id = inc.alert_id   -- affected host
  union
  select fc.case_id, e.structured_data ->> 'agent' from final_cases fc
    join investigations i on i.incident_id = fc.incident_id join evidence e on e.investigation_id = i.id
  where e.structured_data ->> 'agent' is not null;
create temp view v_criteria as
  select fc.case_id,
    bool_and(s.action = any (fc.allowed_actions))                                                        as attack_alignment,
    bool_and(s.target in (select value from v_targets t where t.case_id = fc.case_id))                  as evidence_support,
    bool_and(coalesce(s.action_enabled, false))                                                          as knowledge_validity,
    bool_and(s.policy is not null and (s.policy ->> 'approvalRequired')::boolean = s.requires_approval and (s.policy ->> 'responsibleRole') is not null) as policy_compliance,
    max(s.playbook_code) = max(fc.expected_playbook)
      and bool_and(s.action in (select jsonb_array_elements_text(pb.trigger_conditions -> 'allowedActions') from playbooks pb where pb.code = s.playbook_code)) as playbook_alignment
  from final_cases fc join v_steps s on s.case_id = fc.case_id group by fc.case_id;
create temp view v_approval as
  select fc.case_id,
    (select bool_or(s.requires_approval or coalesce((s.policy ->> 'approvalRequired')::boolean, false)) from v_steps s where s.case_id = fc.case_id) as needs_approval,
    (select min(s.policy ->> 'approvalRole') from v_steps s where s.case_id = fc.case_id and s.policy ->> 'approvalRole' is not null) as expected_role,
    (select a.approval_role from v_plan p join approvals a on a.response_id = p.plan_id where p.case_id = fc.case_id and a.status in ('approved','rejected') order by a.created_at desc limit 1) as used_role,
    exists (select 1 from v_plan p join approvals a on a.response_id = p.plan_id where p.case_id = fc.case_id and a.status in ('approved','rejected') and a.decided_at is not null) as decided
  from final_cases fc;
create temp view v_compliance as
  select c.case_id, c.attack_alignment, c.evidence_support, c.knowledge_validity, c.policy_compliance, c.playbook_alignment,
         (case when a.needs_approval then a.decided and a.used_role is not null and (a.expected_role is null or a.used_role = a.expected_role) else true end) as approval_correctness
  from v_criteria c join v_approval a on a.case_id = c.case_id;
select *, (attack_alignment and evidence_support and knowledge_validity and policy_compliance and playbook_alignment and approval_correctness) as compliant
from v_compliance order by case_id;
select count(*) evaluated_recommendations,
       count(*) filter (where attack_alignment and evidence_support and knowledge_validity and policy_compliance and playbook_alignment and approval_correctness) compliant,
       round(100.0 * count(*) filter (where attack_alignment and evidence_support and knowledge_validity and policy_compliance and playbook_alignment and approval_correctness) / nullif(count(*), 0), 2) compliance_pct,
       count(*) filter (where attack_alignment) attack_alignment, count(*) filter (where evidence_support) evidence_support,
       count(*) filter (where knowledge_validity) knowledge_validity, count(*) filter (where policy_compliance) policy_compliance,
       count(*) filter (where playbook_alignment) playbook_alignment, count(*) filter (where approval_correctness) approval_correctness
from v_compliance;

\echo '=== M4 Workflow Completion (12 stages from the database) ==='
create temp view v_workflow as
  select fc.case_id,
    exists (select 1 from incidents i join alerts a on a.id = i.alert_id where i.id = fc.incident_id)                                         as s1_alert,
    exists (select 1 from audit_logs l where l.action in ('ALERT_ESCALATED_TO_INCIDENT','ALERT_ROUTED_TO_TRIAGE') and l.entity_id = (select alert_id from incidents where id = fc.incident_id)) as s2_triage,
    exists (select 1 from incidents where id = fc.incident_id)                                                                                as s3_incident,
    exists (select 1 from investigations i where i.incident_id = fc.incident_id and i.investigation_number = 1 and i.started_at is not null)    as s4_investigation,
    exists (select 1 from agent_results ar join agent_executions ae on ae.id = ar.agent_execution_id where ae.incident_id = fc.incident_id and ar.agent_name = 'llm_analyst') as s5_ai_analysis,
    exists (select 1 from recommendations r where r.incident_id = fc.incident_id and r.status in ('VALIDATED','SUPERSEDED'))                  as s6_recommendation,
    exists (select 1 from v_rec1 v join playbook_snapshots ps on ps.id = v.snapshot_id where v.case_id = fc.case_id and ps.policy_result <> '{}'::jsonb) as s7_policy,
    exists (select 1 from v_plan p join audit_logs l on l.action = 'RESPONSE_PLAN_CREATED' and l.entity_id = p.plan_id where p.case_id = fc.case_id) as s8_response_ticket,
    exists (select 1 from v_ttd t where t.case_id = fc.case_id)                                                                               as s9_ir_decision,
    exists (select 1 from v_plan p where p.case_id = fc.case_id and p.plan_status = 'COMPLETED')                                              as s10_response_completed,
    exists (select 1 from v_plan p join verifications v on v.response_id = p.plan_id where p.case_id = fc.case_id)                            as s11_verification,
    exists (select 1 from v_plan p join verifications v on v.response_id = p.plan_id join incidents i on i.id = fc.incident_id
            where p.case_id = fc.case_id and ((v.result = 'RESOLVED' and i.status = 'resolved' and exists (select 1 from audit_logs l where l.action = 'INCIDENT_RESOLVED' and l.entity_id = fc.incident_id))
                                           or (v.result <> 'RESOLVED' and i.status <> 'resolved'))) as s12_final_state_supported
  from final_cases fc;
select *, (s1_alert and s2_triage and s3_incident and s4_investigation and s5_ai_analysis and s6_recommendation and s7_policy and s8_response_ticket and s9_ir_decision and s10_response_completed and s11_verification and s12_final_state_supported) as complete
from v_workflow order by case_id;
select count(*) evaluated_cases, count(*) filter (where s1_alert and s2_triage and s3_incident and s4_investigation and s5_ai_analysis and s6_recommendation and s7_policy and s8_response_ticket and s9_ir_decision and s10_response_completed and s11_verification and s12_final_state_supported) complete,
       round(100.0 * count(*) filter (where s1_alert and s2_triage and s3_incident and s4_investigation and s5_ai_analysis and s6_recommendation and s7_policy and s8_response_ticket and s9_ir_decision and s10_response_completed and s11_verification and s12_final_state_supported) / count(*), 2) pct
from v_workflow;

\echo '=== M5 Intervention (analyst-added or analyst-confirmed IOCs) ==='
select fc.case_id, count(*) filter (where t.created_by is not null and t.created_by <> 'system') as analyst_iocs
from final_cases fc left join threat_intel_iocs t on t.incident_id = fc.incident_id group by fc.case_id order by fc.case_id;
select count(*) filter (where n > 0) intervention_cases, count(*) cases, round(100.0 * count(*) filter (where n > 0) / count(*), 2) pct
from (select fc.case_id, count(*) filter (where t.created_by is not null and t.created_by <> 'system') n from final_cases fc left join threat_intel_iocs t on t.incident_id = fc.incident_id group by fc.case_id) x;

\echo '=== M6 Recommendation retries (failed generation calls by reason; AI_UNAVAILABLE = infrastructure) ==='
select fc.case_id, l.metadata ->> 'reason' as reason, count(*) as failed_calls
from final_cases fc join audit_logs l on l.action = 'RECOMMENDATION_GENERATION_FAILED' and l.entity_id = fc.incident_id
group by 1, 2 order by 1, 2;
select count(distinct fc.case_id) filter (where l.metadata ->> 'reason' <> 'AI_UNAVAILABLE') cases_with_model_or_evidence_retry,
       count(*) filter (where l.metadata ->> 'reason' <> 'AI_UNAVAILABLE') retry_count_excluding_infrastructure,
       count(*) filter (where l.metadata ->> 'reason' = 'AI_UNAVAILABLE') infrastructure_failed_calls
from final_cases fc join audit_logs l on l.action = 'RECOMMENDATION_GENERATION_FAILED' and l.entity_id = fc.incident_id;

\echo '=== M7 Verification (REAL_WAZUH vs MOCK are never mixed) ==='
select p.case_id, case v.after_state ->> 'evidenceSource' when 'WAZUH_INDEXER' then 'REAL_WAZUH' when 'MOCK_REHUNT' then 'MOCK' else 'MANUAL_ENTRY' end as mode,
       v.result, v.matching_events, v.ioc_recurrence, v.spread_detected, v.threat_contained,
       round(extract(epoch from (v.verified_at - (select l.created_at from audit_logs l where l.action = 'REHUNT_STARTED' and l.entity_id = p.plan_id)))::numeric, 3) as verification_seconds
from v_plan p join verifications v on v.response_id = p.plan_id order by p.case_id;
select case v.after_state ->> 'evidenceSource' when 'WAZUH_INDEXER' then 'REAL_WAZUH' when 'MOCK_REHUNT' then 'MOCK' else 'MANUAL_ENTRY' end as mode, v.result, count(*)
from v_plan p join verifications v on v.response_id = p.plan_id group by 1, 2 order by 1, 2;
select p.case_id as rehunt_error_case, l.metadata ->> 'code' as code from v_plan p join audit_logs l on l.action = 'REHUNT_FAILED' and l.entity_id = p.plan_id order by 1;

\echo '=== M8 Principles checked in the database ==='
select 'incident priority equals Wazuh-derived alert severity (mismatches)' as check_name, count(*) as violations
from final_cases fc join incidents i on i.id = fc.incident_id join alerts a on a.id = i.alert_id where lower(i.priority) <> lower(a.severity)
union all
select 'severity change / validation audit records (AI must not change severity)', count(*) from audit_logs where action in ('SEVERITY_VALIDATED','INCIDENT_SEVERITY_CHANGED')
union all
select 'resolved incidents without a RESOLVED verification', count(*) from final_cases fc join incidents i on i.id = fc.incident_id
  where i.status = 'resolved' and not exists (select 1 from verifications v where v.incident_id = fc.incident_id and v.result = 'RESOLVED')
union all
select 'executed tickets without an approved IR_TEAM decision', count(*) from v_plan p
  where p.executed_at is not null and not exists (select 1 from approvals a where a.response_id = p.plan_id and a.status = 'approved' and a.approval_role = 'IR_TEAM' and a.decided_at <= p.executed_at)
union all
select 'step executions on a ticket whose latest decision is not approved', count(*) from step_executions se join response_plans rp on rp.id = se.plan_id
  where not exists (select 1 from approvals a where a.response_id = rp.id and a.status = 'approved');
