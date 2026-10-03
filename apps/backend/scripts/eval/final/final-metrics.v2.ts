/**
 * [Mock Evaluation v2 copy of final-metrics.ts: ONLY null-guards on r.safety for attempted cases without a plan (TC-08 had no valid recommendation); formulas unchanged]
 * final-metrics.ts — computes the FINAL evaluation KPIs from PostgreSQL and writes results/final-evaluation/final-*.json.
 *
 *   cd apps/backend && EVAL_DB=soar_final_eval EVAL_ADD_DB=soar_final_eval . scripts/eval/eval-env.sh
 *   FINAL_MAIN_RUN=final-main-real-wazuh-20261001 FINAL_REJECT_RUN=final-ir-reject-real-wazuh-20261001 \
 *   npx ts-node --transpile-only scripts/eval/final/final-metrics.ts
 *
 * Every number is recomputed from the database (alerts, incidents, investigations, recommendations,
 * recommendation_steps, playbook_snapshots, approvals, response_plans, step_executions, verifications, audit_logs,
 * threat_intel_iocs, evidence, agent_results). run.json files are used ONLY to know which incident belongs to which
 * test case and which frozen Ground Truth applies; the stored run.json results are then cross-checked against the
 * database and every disagreement is reported. No LLM is involved anywhere. Read-only.
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { collectEvaluationCase, knownActionCodes } from "../../../src/evaluation/EvaluationService";
import { findActionKnowledge } from "../../../src/domain/knowledge/actionKnowledge";
import { iocKind } from "../../../src/domain/knowledge/knowledgeTypes";

const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
const RES = path.join(ROOT, "results");
const OUT = process.env.EVAL_OUT_ROOT ? path.resolve(process.env.EVAL_OUT_ROOT) : path.join(RES, "final-evaluation");
const DATA = path.join(OUT, "data");
const MAIN = process.env.FINAL_MAIN_RUN ?? "final-main-real-wazuh-20261001";
const REJ = process.env.FINAL_REJECT_RUN ?? "final-ir-reject-real-wazuh-20261001";
const r2 = (x: number) => Math.round(x * 100) / 100;
const r3 = (x: number) => Math.round(x * 1000) / 1000;
const pct = (n: number, d: number) => (d ? r2((n / d) * 100) : null);
const sec = (a: Date | null | undefined, b: Date | null | undefined) => (a && b ? r3((b.getTime() - a.getTime()) / 1000) : null);
const iso = (d: Date | null | undefined) => d?.toISOString?.() ?? null;
const J = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
const maybe = (p: string) => (fs.existsSync(p) ? J(p) : null);
function stats(xs: (number | null | undefined)[]) {
  const v = xs.filter((x): x is number => typeof x === "number" && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return { n: 0, mean: null, median: null, sd: null, min: null, max: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const median = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
  const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : 0;
  return { n: v.length, mean: r3(mean), median: r3(median), sd: r3(sd), min: v[0], max: v[v.length - 1] };
}

(async () => {
  const prisma = new PrismaClient();
  const q = <T = any>(sql: string, ...p: unknown[]) => prisma.$queryRawUnsafe<T[]>(sql, ...p);
  const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  if (!dbName.endsWith("_eval") || dbName === "soar_eval") throw new Error(`refusing to read '${dbName}' as the FINAL database`);
  const known = await knownActionCodes(prisma);
  const run = J(path.join(RES, "runs", MAIN, "run.json"));
  const rejRun = maybe(path.join(RES, "runs", REJ, "run.json"));
  fs.mkdirSync(DATA, { recursive: true });
  const crossDiffs: string[] = [];

  // ------------------------------------------------------------------ per-case database audit
  async function auditCase(c: any, label: string) {
    const row: any = { case_id: c.caseId, attack: c.attackName, run: label, environmentStatus: c.environmentStatus ?? "AVAILABLE", incident_id: c.incidentId ?? null };
    if (!c.incidentId) return row;
    const id = c.incidentId as string;
    const [alert] = await q("select id, external_alert_id, severity, received_at, created_at, raw_payload from alerts where id::text = (select alert_id::text from incidents where id::text=$1)", id);
    const [inc] = await q("select status, priority, opened_at, closed_at, investigation_number from incidents where id::text=$1", id);
    const [inv1] = await q("select id, started_at, completed_at, status from investigations where incident_id::text=$1 and investigation_number=1", id);
    const recs = await q("select id, recommendation_number, investigation_number, status, created_at, snapshot_id from recommendations where incident_id::text=$1 order by recommendation_number", id);
    const rec1 = recs.find((r: any) => Number(r.investigation_number) === 1) ?? null;
    const failed = await q("select created_at, metadata from audit_logs where action='RECOMMENDATION_GENERATION_FAILED' and entity_id::text=$1 order by created_at", id);
    const iocs = await q("select ioc_type, ioc_value, created_by, source from threat_intel_iocs where incident_id::text=$1", id);
    const iocAudits = await q("select actor, metadata from audit_logs where action='IOC_CREATED' and (metadata->>'incidentId'=$1 or entity_id::text in (select id::text from investigations where incident_id::text=$1))", id);
    const llm = await q("select ar.output->>'model' m from agent_results ar join agent_executions ae on ae.id=ar.agent_execution_id where ae.incident_id::text=$1 and ar.agent_name='llm_analyst' limit 1", id);
    const rag = await q("select ar.output->>'status' s from agent_results ar join agent_executions ae on ae.id=ar.agent_execution_id where ae.incident_id::text=$1 and ar.agent_name='rag' limit 1", id);
    const cti = await q("select ar.output->'report'->'summary'->>'total' t, (select string_agg(distinct p->>'status', ',') from jsonb_array_elements(coalesce(ar.output->'report'->'indicators','[]'::jsonb)) i, jsonb_array_elements(coalesce(i->'providers','[]'::jsonb)) p) st from agent_results ar join agent_executions ae on ae.id=ar.agent_execution_id where ae.incident_id::text=$1 and ar.agent_name='threat_intel' limit 1", id);
    row.alert = { externalId: alert?.external_alert_id, severityAssignedByVigix: alert?.severity, wazuhRuleLevel: alert?.raw_payload?.rule?.level, ruleId: alert?.raw_payload?.rule?.id, mitre: alert?.raw_payload?.rule?.mitre?.id ?? [], agent: alert?.raw_payload?.agent?.name, wazuhTimestamp: iso(alert?.received_at), ingestedAt: iso(alert?.created_at) };
    row.incident = { status: inc?.status, priority: inc?.priority, openedAt: iso(inc?.opened_at), investigationNumber: inc?.investigation_number };
    row.environment = { llmModelRecorded: llm[0]?.m ?? null, ragStatus: rag[0]?.s ?? null, ctiIndicatorsTotal: cti[0]?.t ?? null, ctiProviderStatuses: cti[0]?.st ?? null };
    row.retries = { failedGenerationCalls: failed.length, details: failed.map((f: any) => ({ at: iso(f.created_at), reason: f.metadata?.reason ?? null, attempts: f.metadata?.attempts ?? null, violations: (f.metadata?.violations ?? []).map((v: string) => String(v).slice(0, 200)), firstAttemptViolations: (f.metadata?.firstAttemptViolations ?? []).map((v: string) => String(v).slice(0, 200)), retryError: f.metadata?.retryError ?? null })) };
    const cls = (reason: string | null) => (reason === "AI_UNAVAILABLE" ? "INFRASTRUCTURE" : reason === "INVALID_AI_OUTPUT" ? "MODEL_OUTPUT_REJECTED_BY_VALIDATOR" : reason === "INSUFFICIENT_EVIDENCE" || reason === "NO_NEW_RECOMMENDATION" ? "EVIDENCE_GATE_BEFORE_AI" : reason === "DUPLICATE_RECOMMENDATION" ? "MODEL_REPEATED_EARLIER_RECOMMENDATION" : "OTHER");
    row.retries.byClass = failed.reduce((a: any, f: any) => { const k = cls(f.metadata?.reason ?? null); a[k] = (a[k] ?? 0) + 1; return a; }, {});
    row.retries.modelCaused = (row.retries.byClass.MODEL_OUTPUT_REJECTED_BY_VALIDATOR ?? 0) + (row.retries.byClass.MODEL_REPEATED_EARLIER_RECOMMENDATION ?? 0);
    row.retries.infrastructureCaused = row.retries.byClass.INFRASTRUCTURE ?? 0;
    row.iocs = { total: iocs.length, systemExtracted: iocs.filter((i: any) => !i.created_by || i.created_by === "system").length, analystAdded: iocs.filter((i: any) => i.created_by && i.created_by !== "system").map((i: any) => ({ type: i.ioc_type, value: i.ioc_value, by: i.created_by, source: i.source })), iocCreatedAuditRecords: iocAudits.length };

    if (rec1) {
      const steps = await q("select rs.step_order, act.code action, rs.target, rs.requires_approval, rs.evidence from recommendation_steps rs left join actions act on act.id=rs.action_id where rs.recommendation_id::text=$1 order by rs.step_order", rec1.id);
      const [snap] = await q("select playbook_code, policy_result from playbook_snapshots where id::text=$1", rec1.snapshot_id);
      const plans = await q("select id, status, target, created_at, executed_at, completed_at, recommendation_step_id from response_plans where recommendation_id::text=$1 order by created_at", rec1.id);
      const plan = plans[0] ?? null;
      const apprs = plan ? await q("select id, status, approval_role, decided_by, decided_at, created_at from approvals where response_id::text=$1 order by created_at", plan.id) : [];
      const au = async (action: string) => (plan ? (await q("select created_at, actor, metadata from audit_logs where action=$1 and entity_id::text=$2 order by created_at", action, plan.id)) : []);
      const [planCreated] = await au("RESPONSE_PLAN_CREATED"), [respStarted] = await au("RESPONSE_STARTED"), [respCompleted] = await au("RESPONSE_COMPLETED"), [rehuntStarted] = await au("REHUNT_STARTED"), [rehuntFailed] = await au("REHUNT_FAILED");
      const [ver] = plan ? await q("select id, result, wazuh_index, matching_events, ioc_recurrence, spread_detected, threat_contained, affected_hosts, verified_at, verified_by, time_range_start, time_range_end, after_state, before_state from verifications where response_id::text=$1", plan.id) : [];
      const [verAudit] = ver ? await q("select created_at from audit_logs where action='VERIFICATION_COMPLETED' and entity_id::text=$1", ver.id) : [];
      const resolvedAudit = await q("select created_at, actor, metadata from audit_logs where action='INCIDENT_RESOLVED' and entity_id::text=$1", id);
      const escalated = await q("select action, created_at from audit_logs where action in ('INCIDENT_ESCALATED','INVESTIGATION_ESCALATED','INVESTIGATION_REOPENED') and entity_id::text=$1", id);
      const stepExec = plan ? Number((await q("select count(*)::int n from step_executions where plan_id::text=$1", plan.id))[0].n) : 0;
      const dpol = (snap?.policy_result ?? {}) as Record<string, any>;
      const decision = apprs.find((a: any) => a.status === "approved" || a.status === "rejected") ?? null;
      row.recommendation = { id: rec1.id, status: rec1.status, createdAt: iso(rec1.created_at), recommendationCountInIncident: recs.length, playbook: snap?.playbook_code ?? null, steps: steps.map((s: any) => ({ order: s.step_order, action: s.action, target: s.target, requiresApproval: s.requires_approval, evidenceRefs: s.evidence })) };
      row.policy = dpol;
      row.plan = plan ? { id: plan.id, status: plan.status, target: plan.target, socActor: planCreated?.actor ?? null, plansForThisRecommendation: plans.length } : null;
      row.approvals = apprs.map((a: any) => ({ status: a.status, role: a.approval_role, decidedBy: a.decided_by, decidedAt: iso(a.decided_at) }));
      row.verification = ver ? { id: ver.id, mode: ver.after_state?.evidenceSource === "WAZUH_INDEXER" ? "REAL_WAZUH" : ver.after_state?.evidenceSource === "MOCK_REHUNT" ? "MOCK" : "MANUAL_ENTRY", evidenceSource: ver.after_state?.evidenceSource, result: ver.result, index: ver.wazuh_index, matchingEvents: ver.matching_events, iocRecurrence: ver.ioc_recurrence, spreadDetected: ver.spread_detected, threatContained: ver.threat_contained, affectedHosts: ver.affected_hosts, searchedIocs: ver.after_state?.searchedIocs ?? ver.before_state?.criteria?.iocs ?? [], windowStart: iso(ver.time_range_start), windowEnd: iso(ver.time_range_end) } : null;
      row.rehuntFailed = rehuntFailed ? { code: rehuntFailed.metadata?.code ?? null, message: rehuntFailed.metadata?.message ?? null } : null;
      row.escalation = escalated.map((e: any) => `${e.action}@${iso(e.created_at)}`);
      row.incidentFinal = { status: inc?.status, resolvedAuditActor: resolvedAudit[0]?.actor ?? null, resolvedAuditLinkedVerification: resolvedAudit[0]?.metadata?.verificationId ?? null };
      row.safety = { stepExecutionsForPlan: stepExec, approvalBeforeExecution: plan ? (!plan.executed_at || (decision?.decided_at && decision.decided_at <= plan.executed_at)) : null, resolvedOnlyWithResolvedVerification: inc?.status !== "resolved" || (ver?.result === "RESOLVED" && resolvedAudit.length > 0) };
      const T = { alertWazuh: alert?.received_at, alertIngested: alert?.created_at, incidentOpened: inc?.opened_at, invStart: inv1?.started_at, rec: rec1.created_at, decision: decision?.decided_at ?? null, responseStart: respStarted?.created_at ?? null, responseDone: respCompleted?.created_at ?? plan?.completed_at ?? null, rehuntStart: rehuntStarted?.created_at ?? null, verificationEnd: ver?.verified_at ?? rehuntFailed?.created_at ?? null };
      row.timestamps = Object.fromEntries(Object.entries(T).map(([k, v]) => [k, iso(v as Date | null)]));
      row.times = { investigationSeconds: sec(T.invStart, T.rec), timeToDecisionSeconds: sec(T.rec, T.decision), detectionToResponseSeconds: sec(T.alertIngested, T.responseStart), detectionToResponseFromWazuhTimestampSeconds: sec(T.alertWazuh, T.responseStart), verificationSeconds: ver ? sec(T.rehuntStart, ver.verified_at) : null, rehuntErrorSeconds: !ver && rehuntFailed ? sec(T.rehuntStart, rehuntFailed.created_at) : null };
      const order = ["alertWazuh", "alertIngested", "incidentOpened", "invStart", "rec", "decision", "responseStart", "responseDone", "rehuntStart", "verificationEnd"] as const;
      const present = order.filter((k) => T[k]);
      row.timestampsMonotonic = present.every((k, i) => i === 0 || (T[present[i - 1]] as Date).getTime() <= (T[k] as Date).getTime());
      const [aiN] = await q("select count(*)::int n from agent_results ar join agent_executions ae on ae.id=ar.agent_execution_id where ae.incident_id::text=$1 and ar.agent_name='llm_analyst'", id);
      const [triage] = await q("select count(*)::int n from audit_logs where entity_id::text=$1 and action in ('ALERT_ESCALATED_TO_INCIDENT','ALERT_ROUTED_TO_TRIAGE')", alert.id);
      const stages = {
        "1_alert_ingested": !!alert, "2_triage": triage.n > 0, "3_incident": !!inc, "4_investigation_started": !!inv1 && !!inv1.started_at, "5_ai_analysis": aiN.n > 0, "6_recommendation_validated": recs.some((r: any) => r.status === "VALIDATED" || r.status === "SUPERSEDED"),
        "7_policy_evaluated": !!snap && Object.keys(dpol).length > 0, "8_response_ticket_created_by_soc": !!plan && !!planCreated, "9_ir_decision": !!decision, "10_response_or_manual_response_completed": plan?.status === "COMPLETED", "11_verification_rehunt": !!ver,
        "12_final_state_supported": !!ver && ((ver.result === "RESOLVED" && inc?.status === "resolved" && resolvedAudit.length > 0) || (ver.result !== "RESOLVED" && inc?.status !== "resolved")),
      };
      row.workflowStages = stages;
      const firstMissing = Object.entries(stages).find(([, v]) => !v);
      row.workflowComplete = !firstMissing;
      row.stoppedAt = firstMissing ? firstMissing[0] : null;
    } else {
      row.workflowStages = { "1_alert_ingested": !!alert, "3_incident": !!inc }; row.workflowComplete = false; row.stoppedAt = "6_recommendation_validated";
      row.recommendation = null; row.times = {}; row.policy = {};
    }

    // ---- deterministic re-score (the frozen evaluator) against the frozen Ground Truth, from the database
    const gt = c.groundTruth;
    const sc = await collectEvaluationCase(prisma, { ...gt, knownFindings: [] }, known, id);
    row.rescored = { compliance: sc.recommendationCompliance, checks: sc.compliance ? { attackAlignment: sc.compliance.attackAlignment, evidenceSupport: sc.compliance.evidenceSupport, knowledgeValidity: sc.compliance.knowledgeValidity, policyCompliance: sc.compliance.policyCompliance, playbookAlignment: sc.compliance.playbookAlignment, approvalCorrectness: sc.compliance.approvalCorrectness } : null, failedChecks: sc.compliance?.failedChecks ?? [], retries: sc.invalidOutputCount, verificationMode: sc.verificationMode, verificationResult: sc.verificationResult };
    row.expected = { playbook: gt.expectedPlaybook, allowedActions: gt.allowedActions, preferredActions: gt.expectedActions, preferredTargets: gt.expectedTargets, severity: gt.expectedSeverity, mitre: gt.expectedMitre };
    // target kind of every step (supplementary, not a compliance criterion)
    const hosts = new Set<string>([row.alert?.agent].filter(Boolean));
    row.targetChecks = (row.recommendation?.steps ?? []).map((s: any) => { const kind = findActionKnowledge(s.action)?.targetKind ?? null; const ioc = iocs.find((i: any) => i.ioc_value === s.target); const k = hosts.has(s.target) ? "host" : ioc ? iocKind(ioc.ioc_type) : null; return { action: s.action, target: s.target, expectedKind: kind, actualKind: k, kindMatches: kind === null || kind === k, selfTargetingEndpointIp: c.simulation?.facts?.endpointIp ? s.target === c.simulation.facts.endpointIp && ["ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP"].includes(s.action) : false }; });
    // cross-check against what the run recorded
    if (c.recommendationCompliance !== undefined && c.recommendationCompliance !== sc.recommendationCompliance) crossDiffs.push(`${label} ${c.caseId}: compliance run.json=${c.recommendationCompliance} db=${sc.recommendationCompliance}`);
    if (c.invalidOutputCount !== undefined && c.invalidOutputCount !== failed.length) crossDiffs.push(`${label} ${c.caseId}: failed generation calls run.json=${c.invalidOutputCount} db=${failed.length}`);
    row.interventions = c.interventions ?? [];
    row.interventionFromDb = row.iocs.analystAdded.length > 0;
    row.infrastructureEvents = (run.infrastructureEvents ?? []).filter((e: any) => e.case === c.caseId);
    row.observations = c.observations ?? [];
    row.iocRecallBeforeCorrection = c.iocRecall ?? null;
    row.wazuhExpectation = c.wazuh ? { ruleMatch: c.wazuh.ruleMatch, levelMatch: c.wazuh.levelMatch, mitreMatch: c.wazuh.mitreMatch } : null;
    row.irReject = c.irReject ?? null;
    if (c.investigationTimeSeconds != null && row.times?.investigationSeconds != null && Math.abs(c.investigationTimeSeconds - row.times.investigationSeconds) > 0.02) crossDiffs.push(`${label} ${c.caseId}: investigation time run.json=${c.investigationTimeSeconds} db=${row.times.investigationSeconds}`);
    return row;
  }

  const cases: any[] = [];
  for (const c of run.cases) cases.push(await auditCase(c, MAIN));
  const rejectCases: any[] = [];
  if (rejRun) for (const c of rejRun.cases) rejectCases.push(await auditCase(c, REJ));

  const attempted = cases.filter((r) => r.environmentStatus !== "ENVIRONMENT_UNAVAILABLE");
  const withRec = attempted.filter((r) => r.rescored?.compliance && r.rescored.compliance !== "NOT_EVALUATED");
  const compliant = withRec.filter((r) => r.rescored.compliance === "COMPLIANT");

  // ------------------------------------------------------------------ KPI 1: Recommendation Compliance
  const crit = ["attackAlignment", "evidenceSupport", "knowledgeValidity", "policyCompliance", "playbookAlignment", "approvalCorrectness"];
  const userCriteriaMap = { "Action correctness": "attackAlignment (action inside the Ground Truth allowed set)", "Target correctness": "evidenceSupport (target is a recorded value of the kind the action operates on — kind enforced by the validator, membership by the evaluator)", "Evidence support": "evidenceSupport + validator required-evidence gate (a VALIDATED recommendation has its required evidence recorded)", "Action catalog validity": "knowledgeValidity (action exists and is enabled in the Action Catalog)", "Policy compliance": "policyCompliance (step approval flag == Policy snapshot, responsible role present)", "Playbook / Runbook alignment": "playbookAlignment (selected playbook == Ground Truth and every action inside it)", "(additional, kept from the frozen evaluator)": "approvalCorrectness (approval role matches Policy and a human decision exists)" };
  const complianceJson = {
    kpi: "Recommendation Compliance", formula: "compliant recommendations / evaluated recommendations × 100", source: "PostgreSQL (recommendations, recommendation_steps, playbook_snapshots, approvals) scored by EvaluationService.evaluateCompliance against the frozen Ground Truth", database: dbName, run: MAIN,
    result: { numerator: compliant.length, denominator: withRec.length, pct: pct(compliant.length, withRec.length), denominatorAttemptedCases: attempted.length, pctOfAttemptedCases: pct(compliant.length, attempted.length), attemptedWithoutValidRecommendation: attempted.filter((r) => !withRec.includes(r)).map((r) => r.case_id) },
    criteria: Object.fromEntries(crit.map((k) => [k, { passed: withRec.filter((r) => r.rescored.checks?.[k]).length, of: withRec.length }])), criteriaMapping: userCriteriaMap,
    notMerged: "Negative Validation (controlled invalid recommendations) and Human/Policy Validation (governance gates) are reported in their own files and are NOT part of this rate: their denominators and definitions differ.",
    records: withRec.map((r) => ({ incident_id: r.incident_id, tc: r.case_id, recommended_actions: r.recommendation.steps.map((s: any) => s.action), recommended_targets: r.recommendation.steps.map((s: any) => s.target), evidence_used: { ioc_count: r.iocs.total, analyst_added_iocs: r.iocs.analystAdded.length, step_evidence_refs: r.recommendation.steps.map((s: any) => s.evidenceRefs) }, action_catalog_match: r.rescored.checks.knowledgeValidity, policy_result: r.rescored.checks.policyCompliance, policy_snapshot: r.policy, playbook_result: { selected: r.recommendation.playbook, expected: r.expected.playbook, aligned: r.rescored.checks.playbookAlignment }, criteria: r.rescored.checks, compliance_result: r.rescored.compliance, failure_reason: r.rescored.failedChecks.join(" | ") || null, supplementary_target_checks: r.targetChecks })),
    notEvaluated: attempted.filter((r) => !withRec.includes(r)).map((r) => ({ incident_id: r.incident_id, tc: r.case_id, reason: r.observations.find((o: string) => /NO_VALID|INFRASTRUCTURE|ALERT_MISSING/.test(o)) ?? "no validator-passing recommendation", retries: r.retries })),
  };

  // ------------------------------------------------------------------ KPI 2/3: times
  const invS = attempted.map((r) => r.times?.investigationSeconds);
  const ttdS = attempted.map((r) => r.times?.timeToDecisionSeconds);
  const missingInv = attempted.filter((r) => r.times?.investigationSeconds == null).map((r) => ({ tc: r.case_id, reason: r.recommendation ? "timestamp missing" : "no recommendation was created, so T_Recommendation does not exist" }));
  const missingTtd = attempted.filter((r) => r.times?.timeToDecisionSeconds == null).map((r) => ({ tc: r.case_id, reason: !r.recommendation ? "no recommendation" : "no IR decision recorded" }));
  const investigationJson = { kpi: "Investigation Time", formula: "T_Recommendation − T_InvestigationStart", unit: "seconds", source: "investigations.started_at (investigation #1) and recommendations.created_at (recommendation #1 of investigation #1)", stats: stats(invS), missingRecords: missingInv, perCase: attempted.map((r) => ({ tc: r.case_id, incident_id: r.incident_id, investigationStart: r.timestamps?.invStart ?? null, recommendationAt: r.timestamps?.rec ?? null, seconds: r.times?.investigationSeconds ?? null })), timingMode: "uninterrupted scripted pass (no manual gap); includes the third-party/self-hosted LLM latency and any model retries" };
  const decisionJson = { kpi: "Time-to-Decision", formula: "T_IR_Decision − T_Recommendation", unit: "seconds", source: "approvals.decided_at (first IR decision of the case's response ticket) and recommendations.created_at", stats: stats(ttdS), casesWithoutIrDecision: missingTtd, decisionActorNote: "every IR decision in this evaluation is a scripted call of the real DecideApproval use case with the IR_TEAM role; the value is the latency of that scripted decision, not human deliberation", perCase: attempted.map((r) => ({ tc: r.case_id, recommendationAt: r.timestamps?.rec ?? null, irDecisionAt: r.timestamps?.decision ?? null, seconds: r.times?.timeToDecisionSeconds ?? null, decidedBy: r.approvals?.find((a: any) => a.status !== "pending")?.decidedBy ?? null })) };

  // ------------------------------------------------------------------ KPI 4: workflow completion
  const wfDone = attempted.filter((r) => r.workflowComplete);
  const workflowJson = { kpi: "Workflow Completion Rate", formula: "cases reaching a valid final workflow state / evaluated cases × 100", definition: "all 12 stages present in the database and the final state supported by workflow evidence: RESOLVED only with a RESOLVED verification and an INCIDENT_RESOLVED audit record (never because an incident was merely closed); a non-RESOLVED verification must leave the incident unresolved", source: "alerts, audit_logs, incidents, investigations, agent_results, recommendations, playbook_snapshots, response_plans, approvals, verifications", result: { numerator: wfDone.length, denominator: attempted.length, pct: pct(wfDone.length, attempted.length), pctOfAllTen: pct(wfDone.length, cases.length) }, incomplete: attempted.filter((r) => !r.workflowComplete).map((r) => ({ tc: r.case_id, stoppedAtStage: r.stoppedAt, reason: r.rehuntFailed ? `re-hunt ${r.rehuntFailed.code}: ${r.rehuntFailed.message}` : !r.recommendation ? "no validator-passing recommendation" : "see stages" })), perCase: attempted.map((r) => ({ tc: r.case_id, complete: r.workflowComplete, stoppedAt: r.stoppedAt, stages: r.workflowStages })) };

  // ------------------------------------------------------------------ KPI 5: intervention
  const interv = attempted.filter((r) => r.interventionFromDb || r.interventions.length);
  const reasonOf = (r: any) => (/EMAIL/.test(JSON.stringify(r.iocs.analystAdded) + JSON.stringify(r.interventions)) ? "Missing IOC / target not evidence-linked (e-mail)" : /PROCESS|COMMAND/.test(JSON.stringify(r.iocs.analystAdded) + JSON.stringify(r.interventions)) ? "Missing evidence (COMMAND_LINE / process)" : "Missing IOC / evidence not linked");
  const interventionJson = { kpi: "Intervention Rate", formula: "cases requiring analyst intervention / evaluated cases × 100", definition: "an analyst correction was applied because the AI recommendation could not safely proceed (the system had its first 2 attempts; corrections are only IOC confirmations/additions that the alert itself evidences; nothing is corrected silently)", source: "threat_intel_iocs.created_by <> 'system' (database) cross-checked with the interventions recorded by the harness", result: { numerator: interv.length, denominator: attempted.length, pct: pct(interv.length, attempted.length) }, dbVsHarnessAgree: interv.every((r) => r.interventionFromDb === (r.interventions.length > 0)), cases: interv.map((r) => ({ tc: r.case_id, incident_id: r.incident_id, reason: reasonOf(r), evidenceCondition: { expectedIocsMissingBeforeCorrection: r.iocRecallBeforeCorrection?.missing ?? null, validatorRejections: r.retries.details.map((d: any) => d.violations).flat().slice(0, 6) }, analystActions: r.iocs.analystAdded, result_after_intervention: { recommendation: r.rescored.compliance, workflowComplete: r.workflowComplete, verification: r.verification ? `${r.verification.result} (${r.verification.mode})` : null } })), casesWithoutIntervention: attempted.filter((r) => !interv.includes(r)).map((r) => r.case_id) };

  // ------------------------------------------------------------------ KPI 6: retry
  const retried = attempted.filter((r) => r.retries.failedGenerationCalls > 0);
  const modelRetried = attempted.filter((r) => r.retries.modelCaused > 0 || (r.retries.byClass.EVIDENCE_GATE_BEFORE_AI ?? 0) > 0);
  const infraOnly = attempted.filter((r) => r.retries.infrastructureCaused > 0);
  const retryJson = { kpi: "Recommendation Retry Rate", formula: "cases requiring at least one recommendation retry / evaluated cases × 100", definition: "a retry = a failed recommendation-generation call (RECOMMENDATION_GENERATION_FAILED) after which another call was needed. Infrastructure failures are separated: they are NOT counted in the rate and NOT treated as model inconsistency", source: "audit_logs (action = RECOMMENDATION_GENERATION_FAILED, metadata.reason / violations)", result: { numerator: modelRetried.length, denominator: attempted.length, pct: pct(modelRetried.length, attempted.length), totalRetryCount: attempted.reduce((a, r) => a + r.retries.modelCaused + (r.retries.byClass.EVIDENCE_GATE_BEFORE_AI ?? 0), 0), averageRetriesPerCase: r2(attempted.reduce((a, r) => a + r.retries.modelCaused + (r.retries.byClass.EVIDENCE_GATE_BEFORE_AI ?? 0), 0) / (attempted.length || 1)), note: "total retry count is a COUNT, not a percentage" }, allFailedGenerationCallsIncludingInfrastructure: attempted.reduce((a, r) => a + r.retries.failedGenerationCalls, 0), infrastructure: { casesWithInfrastructureFailure: infraOnly.map((r) => r.case_id), failedCalls: attempted.reduce((a, r) => a + r.retries.infrastructureCaused, 0), harnessInfrastructureEvents: run.infrastructureEvents ?? [], note: "infrastructure failures (LLM endpoint timeout / connection error) are reported here and excluded from the retry rate" }, perCase: attempted.map((r) => ({ tc: r.case_id, incident_id: r.incident_id, failedGenerationCalls: r.retries.failedGenerationCalls, byClass: r.retries.byClass, retryCausedByModelOutput: r.retries.modelCaused > 0, retryCausedByEvidenceGate: (r.retries.byClass.EVIDENCE_GATE_BEFORE_AI ?? 0) > 0, retryCausedByInfrastructure: r.retries.infrastructureCaused > 0, initialRecommendationRejected: r.retries.details[0] ? { reason: r.retries.details[0].reason, violations: r.retries.details[0].violations, firstAttemptViolations: r.retries.details[0].firstAttemptViolations } : null, retryReasons: [...new Set(r.retries.details.map((d: any) => d.reason))], finalRecommendation: r.recommendation ? { playbook: r.recommendation.playbook, steps: r.recommendation.steps.map((s: any) => `${s.action} → ${s.target}`) } : null, finalOutcome: r.recommendation ? `VALIDATED (${r.rescored.compliance})` : r.observations.find((o: string) => /NO_VALID|INFRASTRUCTURE/.test(o)) ?? "no recommendation" })) };

  // ------------------------------------------------------------------ KPI 7: verification
  const mock = J(path.join(RES, "archive", fs.readdirSync(path.join(RES, "archive")).filter((d) => d.startsWith("mock-run-pre-real-")).sort().pop()!, "evaluation.json"));
  const executed = attempted.filter((r) => r.plan?.status === "COMPLETED");
  const realV = executed.filter((r) => r.verification?.mode === "REAL_WAZUH");
  const outcome = (r: any) => (r.verification ? (r.verification.result === "RESOLVED" ? "RESOLVED" : r.escalation.some((e: string) => e.startsWith("INCIDENT_ESCALATED")) ? "ESCALATED" : r.verification.spreadDetected ? "SPREAD" : r.verification.threatContained === false ? "NOT_CONTAINED" : "NOT_RESOLVED") : r.rehuntFailed ? "ERROR" : "NOT_VERIFIED");
  const dist: Record<string, number> = {}; for (const r of executed) dist[outcome(r)] = (dist[outcome(r)] ?? 0) + 1;
  const verificationJson = {
    kpi: "Verification Result", real_wazuh: { definition: "re-hunt of the live Wazuh Indexer after the (manually simulated) response; RESOLVED = the verification procedure did not detect the specified recurrence condition within the tested window (not proof of eradication)", cases_with_completed_response: executed.length, verified_real_wazuh: realV.length, verified_percent_of_executed: pct(realV.length, executed.length), outcomeDistribution: dist, resolved: { numerator: dist.RESOLVED ?? 0, denominator: executed.length, pct: pct(dist.RESOLVED ?? 0, executed.length) }, escalatedObserved: (dist.ESCALATED ?? 0) > 0, escalatedNote: (dist.ESCALATED ?? 0) > 0 ? "" : "ESCALATED (3 re-hunt rounds reached) did not occur and was not induced in this evaluation", perCase: executed.map((r) => ({ tc: r.case_id, type: "REAL_WAZUH", expected: "RESOLVED (no recurrence of the contained indicators after the simulated response)", actual: outcome(r), final_state: r.incident.status, evidence: r.verification ? { index: r.verification.index, matchingEvents: r.verification.matchingEvents, iocRecurrence: r.verification.iocRecurrence, spreadDetected: r.verification.spreadDetected, threatContained: r.verification.threatContained, searchedIocs: r.verification.searchedIocs, window: [r.verification.windowStart, r.verification.windowEnd] } : { error: r.rehuntFailed } })) },
    mock: { source: "archived MOCK baseline run (frozen, NOT re-run): CleanRehuntAdapter — NO_MATCH is simulated", cases: mock.cases.length, verificationCompleted: mock.cases.filter((c: any) => c.verificationMode === "MOCK" && c.verificationResult).length, resolved: mock.cases.filter((c: any) => c.verificationResult === "RESOLVED").length, note: "completion of a mock verification shows the workflow can reach verification; it is NOT evidence that any threat was removed. TC-01 of that archive is a hybrid (real alert + mock verification).", perCase: mock.cases.map((c: any) => ({ tc: c.caseId, type: "MOCK", expected: "RESOLVED (simulated)", actual: c.verificationResult, final_state: c.finalStatus })) },
    notMixed: "MOCK and REAL_WAZUH are reported in separate objects and never combined.",
  };

  // ------------------------------------------------------------------ safety / principle checks from the database
  const sev = attempted.every((r) => String(r.incident.priority).toLowerCase() === String(r.alert.severityAssignedByVigix).toLowerCase());
  const sevMap = attempted.every((r) => { const l = Number(r.alert.wazuhRuleLevel); const exp = l >= 14 ? "critical" : l >= 11 ? "high" : l >= 7 ? "medium" : "low"; return String(r.alert.severityAssignedByVigix).toLowerCase() === exp; });
  const sevAudit = Number((await q("select count(*)::int n from audit_logs where action in ('SEVERITY_VALIDATED','INCIDENT_SEVERITY_CHANGED')"))[0].n);
  const exec = attempted.filter((r) => r.plan);
  const principles = {
    severity_from_wazuh_not_ai: { ok: sev && sevMap && sevAudit === 0, detail: `incident.priority == alert.severity for ${attempted.length}/${attempted.length}; severity equals the deterministic Wazuh rule-level mapping; severity-change audit records: ${sevAudit}` },
    no_response_executed_without_ir_approval: { ok: exec.every((r) => r.safety?.approvalBeforeExecution !== false) && attempted.every((r) => (r.safety?.stepExecutionsForPlan ?? 0) === 0 || r.approvals.some((a: any) => a.status === "approved")), detail: "every executed ticket has an approved IR_TEAM decision recorded at or before execution" },
    no_incident_closed_by_ai: { ok: attempted.every((r) => (r.safety?.resolvedOnlyWithResolvedVerification ?? true) && (!r.incidentFinal?.resolvedAuditActor || /ir|eval-ir/i.test(r.incidentFinal.resolvedAuditActor))), detail: "every RESOLVED incident has a RESOLVED real verification and an INCIDENT_RESOLVED audit record written by the verification flow (actor = the IR verifier), never by an AI agent" },
    ir_is_decision_authority: { ok: exec.every((r) => r.approvals.every((a: any) => a.status === "pending" || a.role === "IR_TEAM")), detail: "all decided approvals carry approval_role IR_TEAM" },
    timestamps_monotonic: { ok: attempted.filter((r) => r.timestamps).every((r) => r.timestampsMonotonic), detail: "alert ≤ incident ≤ investigation ≤ recommendation ≤ decision ≤ response ≤ verification in every case" },
  };

  // ------------------------------------------------------------------ per-test-case table
  const finalResult = (r: any) => (r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "ENVIRONMENT_UNAVAILABLE" : !r.recommendation ? (r.observations.some((o: string) => /INFRASTRUCTURE_FAILURE/.test(o)) ? "INCOMPLETE" : "FAIL") : r.rescored.compliance !== "COMPLIANT" ? "FAIL" : r.workflowComplete ? "PASS" : "INCOMPLETE");
  const perCase = cases.map((r) => ({
    tc: r.case_id, attack: r.attack, incident_id: r.incident_id, environment_status: r.environmentStatus,
    alert: r.alert ? `Wazuh rule ${r.alert.ruleId} L${r.alert.wazuhRuleLevel} (${r.alert.severityAssignedByVigix}) ${r.alert.mitre.join(",")}` : "ENVIRONMENT_UNAVAILABLE / not ingested",
    investigation: r.times?.investigationSeconds != null ? `${r.times.investigationSeconds}s` : r.recommendation ? "completed" : r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "not attempted (ENVIRONMENT_UNAVAILABLE)" : "completed (no recommendation)",
    recommendation: r.recommendation ? `${r.recommendation.playbook}: ${r.recommendation.steps.map((s: any) => s.action.replace("ACT-", "")).join(", ")} (${r.rescored.compliance})` : r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "not attempted (ENVIRONMENT_UNAVAILABLE)" : "NONE (validator rejected / infrastructure)",
    ir_decision: r.approvals?.length ? `${r.approvals.find((a: any) => a.status !== "pending")?.status ?? "pending"} by ${r.approvals.find((a: any) => a.status !== "pending")?.role ?? "-"} (${r.times.timeToDecisionSeconds}s)` : "none",
    response: r.plan ? r.plan.status : "none",
    verification: r.verification ? `${r.verification.result} (${r.verification.mode})` : r.rehuntFailed ? `ERROR ${r.rehuntFailed.code}` : "not reached",
    intervention: r.interventionFromDb ? reasonOf(r) : "none",
    retry: `${r.retries?.modelCaused ?? 0}${(r.retries?.infrastructureCaused ?? 0) ? ` (+${r.retries.infrastructureCaused} infrastructure)` : ""}`,
    final_result: finalResult(r), stopped_at_stage: r.stoppedAt ?? null,
  }));
  const results = { PASS: perCase.filter((c) => c.final_result === "PASS").length, FAIL: perCase.filter((c) => c.final_result === "FAIL").length, INCOMPLETE: perCase.filter((c) => c.final_result === "INCOMPLETE").length, ENVIRONMENT_UNAVAILABLE: perCase.filter((c) => c.final_result === "ENVIRONMENT_UNAVAILABLE").length };

  // ------------------------------------------------------------------ other evaluations (data/*.json written by the dedicated scripts)
  const cons = maybe(path.join(DATA, "consistency.json")), neg = maybe(path.join(DATA, "negative.json")), base = maybe(path.join(DATA, "baseline.json"));
  const rejectChecks = rejectCases.flatMap((r) => r.irReject?.checks ?? []);
  const gates: any[] = neg?.governance_gates ?? [];
  const humanPolicyChecks = [...gates, ...rejectChecks];
  const negativeJson = neg ? { kpi: "Negative Validation", formula: "rejected invalid recommendations / tested invalid recommendations × 100", database: dbName, summary: neg.summary, scenarios: neg.scenarios.map((s: any) => { const actualLayer = String(s.policy_result).startsWith("POLICY-DERIVED") ? "POLICY" : "VALIDATOR"; return { scenario_id: s.case_id, name: s.scenario, invalid_condition: s.invalid_condition, positive_control: s.positive_control, expected: s.expected_result, expected_layer: s.expected_layer, actual_result: s.actual_result, rejection_layer_actual: actualLayer, layer_matches_expectation: s.expected_layer === actualLayer, rejection_reason: s.violation_codes, validator_result: s.validator_result, policy_result: s.policy_result }; }), tested: neg.scenarios.length, rejected: neg.scenarios.filter((s: any) => s.actual_result === "REJECTED").length, rate: { numerator: neg.scenarios.filter((s: any) => s.actual_result === "REJECTED").length, denominator: neg.scenarios.length, pct: pct(neg.scenarios.filter((s: any) => s.actual_result === "REJECTED").length, neg.scenarios.length) }, note: "the layer is taken from the recorded violation: Policy-derived = responsible-role / approval-waiver rules; evidence required by the Action's own knowledge (e.g. COMMAND_LINE for ACT-KILL-PROCESS) is a validator-layer rejection, not a Policy rejection" } : { kpi: "Negative Validation", status: "NOT AVAILABLE — negative.json not produced" };
  const humanJson = { kpi: "Human / Policy Validation", formula: "passed checks / total checks × 100", sources: ["data/negative.json#governance_gates (real use cases on the final DB)", `results/runs/${REJ}/run.json (IR reject → manual decision → manual response → real re-hunt)`], result: { passed: humanPolicyChecks.filter((g) => g.pass).length, total: humanPolicyChecks.length, pct: pct(humanPolicyChecks.filter((g) => g.pass).length, humanPolicyChecks.length) }, governanceGates: { passed: gates.filter((g) => g.pass).length, total: gates.length }, irRejectFlow: { passed: rejectChecks.filter((g: any) => g.pass).length, total: rejectChecks.length, case: rejectCases[0] ? { tc: rejectCases[0].case_id, incident_id: rejectCases[0].incident_id, finalIncidentStatus: rejectCases[0].incident?.status, verification: rejectCases[0].verification ? `${rejectCases[0].verification.result} (${rejectCases[0].verification.mode})` : rejectCases[0].rehuntFailed ? `ERROR ${rejectCases[0].rehuntFailed.code}` : "not reached", responsePlan: rejectCases[0].plan?.status, approvals: rejectCases[0].approvals } : null }, failures: humanPolicyChecks.filter((g) => !g.pass).map((g) => ({ id: g.id, scenario: g.scenario, expected: g.expected, actual: g.actual })), checks: humanPolicyChecks.map((g: any) => ({ id: g.id, scenario: g.scenario, expected: g.expected, actual: g.actual, pass: g.pass })) };
  const consistencyJson = cons ? { kpi: "Recommendation Consistency", formula: "consistent validated primary recommendations / total repeated runs", definition: cons.definition, database: dbName, source_run: cons.source_run, repetitions: cons.repetitions, cases: cons.cases, overall: { numerator: cons.overall.consistent_runs, denominator: cons.overall.runs, pct: cons.overall.consistency_pct, perCaseMeanPct: cons.overall.per_case_mean_pct, perCaseSdPct: cons.overall.per_case_sd_pct }, mainActionConsistency: cons.perCase.map((c: any) => ({ tc: c.case_id, consistent: c.consistent_runs, runs: c.runs, pct: c.consistency_pct, distribution: c.distribution })), stepSetConsistency: { numerator: cons.perCase.reduce((a: number, c: any) => a + c.step_set_agreement_runs, 0), denominator: cons.overall.runs, pct: r2((cons.perCase.reduce((a: number, c: any) => a + c.step_set_agreement_runs, 0) / cons.overall.runs) * 100), perCase: cons.perCase.map((c: any) => ({ tc: c.case_id, runs: c.step_set_agreement_runs, of: c.runs, pct: c.step_set_agreement_pct })) }, infrastructureFailures: { count: cons.infrastructure_failure_count ?? 0, listed: cons.infrastructure_failures ?? [], note: "excluded from the denominator; the repetition was repeated after the LLM endpoint recovered and is labelled rerun_after_infrastructure_failure" }, reruns: (cons.runs ?? []).filter((r: any) => r.rerun_after_infrastructure_failure).map((r: any) => ({ case_id: r.case_id, repetition: r.repetition })), previousResultForComparisonOnly: "29/30 = 96.67% (additional evaluation, 2026-09-30) — not used for the final value", records: cons.runs.map((r: any) => ({ case_id: r.case_id, repetition: r.repetition, playbook_id: r.playbook_id, primary_action: r.primary_action, target_type: r.target_type, target_value: r.target_value, mitre: r.mitre_technique, recommendation_status: r.recommendation_status, validation_status: r.validation_status, policy_status: r.policy_status, all_steps: r.all_steps?.map((s: any) => `${s.action}>${s.target}`), rerun_after_infrastructure_failure: !!r.rerun_after_infrastructure_failure })) } : { kpi: "Recommendation Consistency", status: "NOT AVAILABLE — consistency.json not produced" };
  const baselineJson = base ? { kpi: "Baseline Comparison", label: base.label, humanStudy: false, mockUsed: false, interpretationRule: "The baseline skips the human decision and the evidence gating of VIGIX; it is a PROCEDURAL REFERENCE only and must not be read as an equivalent, faster or better SOC workflow.", cases: base.summary.plan_created, responsePlans: base.summary.plan_created.numerator, averageActionsPerPlan: base.summary.response_action_count.mean, procedureTimeSeconds: { n: base.cases.filter((c: any) => c.investigation_start).length, ...(() => { const v = base.cases.filter((c: any) => c.investigation_start).map((c: any) => (Date.parse(c.investigation_end) - Date.parse(c.investigation_start)) / 1000); return stats(v); })() }, decisionLatency: null, decisionLatencyReason: "NULL by design: the baseline has no human decision stage and no approval instance", summary: base.summary, previousBaselineForComparisonOnly: { cases: "9/9", avgActions: 2.78, procedureTime: { mean: 0.013, median: 0.010, sd: 0.009, min: 0.008, max: 0.036 } }, perCase: base.cases } : { kpi: "Baseline Comparison", status: "NOT AVAILABLE — baseline.json not produced" };

  // ------------------------------------------------------------------ known findings re-check
  const tc = (id: string) => cases.find((r) => r.case_id === id);
  const t07 = cons?.runs?.filter((r: any) => r.case_id === "TC-07") ?? [];
  const selfSteps = (cons?.runs ?? []).flatMap((r: any) => (r.all_steps ?? []).filter((s: any) => ["ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP"].includes(s.action) && s.target === (run.cases.find((c: any) => c.simulation)?.simulation?.facts?.endpointIp ?? "")).map((s: any) => `${r.case_id}#${r.repetition} ${s.action}`));
  const findings = {
    TC03_email_target: tc("TC-03") ? { observed: { retries: tc("TC-03").retries.byClass, validatorViolations: tc("TC-03").retries.details.map((d: any) => d.violations).flat().slice(0, 5), analystAdded: tc("TC-03").iocs.analystAdded, finalRecommendation: tc("TC-03").recommendation?.steps, compliance: tc("TC-03").rescored?.compliance }, note: "ACT-QUARANTINE-EMAIL needs an evidence-backed e-mail target; no silent correction occurred — any correction is listed as an intervention" } : null,
    TC08_command_line: tc("TC-08") ? { observed: { retries: tc("TC-08").retries.byClass, violations: tc("TC-08").retries.details.map((d: any) => d.violations).flat().slice(0, 5), analystAdded: tc("TC-08").iocs.analystAdded, finalRecommendation: tc("TC-08").recommendation?.steps, compliance: tc("TC-08").rescored?.compliance } } : null,
    TC07_variation: cons ? { primaryActionDistribution: Object.fromEntries((cons.perCase.find((c: any) => c.case_id === "TC-07")?.distribution ? Object.entries(cons.perCase.find((c: any) => c.case_id === "TC-07").distribution) : [])), isolateEndpointAsPrimaryRuns: t07.filter((r: any) => r.primary_action === "ACT-ISOLATE-ENDPOINT").map((r: any) => r.repetition), selfTargetingIpSteps: selfSteps, mainRunTc07SelfTargeting: tc("TC-07")?.targetChecks?.filter((t: any) => t.selfTargetingEndpointIp) ?? [], classification: "recommendation consistency / step-level variation — NOT a compliance failure unless the six criteria fail (see TC-07 compliance in final-recommendation-compliance.json)" } : null,
    TC09_infrastructure: { infrastructureEventsMainRun: run.infrastructureEvents ?? [], consistencyInfrastructureFailures: cons?.infrastructure_failures ?? [], note: "infrastructure failures are preserved and classified separately from model results" },
    TC10_t1098_playbook: tc("TC-10") ? { selectedPlaybook: tc("TC-10").recommendation?.playbook ?? null, expected: "PB-ACCOUNT-COMPROMISE", note: "T1098 maps to PB-ACCOUNT-COMPROMISE per the frozen Ground Truth; mapping not changed" } : null,
  };

  // ------------------------------------------------------------------ KPI summary
  const kpi = {
    generatedAt: new Date().toISOString(), database: dbName, mainRun: MAIN, rejectRun: REJ, model: (() => { try { const pre = JSON.parse(fs.readFileSync(path.join(OUT, "pre-run-integrity.json"), "utf8")); return { configuredModel: pre.llm?.configuredModel, endpointNote: pre.llm?.endpointNote, endpointReachable: pre.llm?.endpointReachable, source: "pre-run-integrity.json (self-hosted vLLM; OpenRouter is not on this path)" }; } catch { return null; } })(), cases: { total: cases.length, attempted: attempted.length, ...results },
    table: [
      { metric: "Recommendation Compliance", result: complianceJson.result.pct, unit: "%", n: `${complianceJson.result.numerator}/${complianceJson.result.denominator} evaluated; ${complianceJson.result.numerator}/${attempted.length} attempted = ${complianceJson.result.pctOfAttemptedCases}%`, source: "DB", notes: "deterministic six-criterion evaluator vs frozen Ground Truth" },
      { metric: "Investigation Time", result: investigationJson.stats.mean, unit: "seconds", n: investigationJson.stats.n, source: "DB", notes: `median ${investigationJson.stats.median}, SD ${investigationJson.stats.sd}, min ${investigationJson.stats.min}, max ${investigationJson.stats.max}; missing ${missingInv.length}` },
      { metric: "Time-to-Decision", result: decisionJson.stats.mean, unit: "seconds", n: decisionJson.stats.n, source: "DB", notes: `median ${decisionJson.stats.median}, SD ${decisionJson.stats.sd}, min ${decisionJson.stats.min}, max ${decisionJson.stats.max}; scripted IR decision` },
      { metric: "Workflow Completion", result: workflowJson.result.pct, unit: "%", n: `${workflowJson.result.numerator}/${workflowJson.result.denominator}`, source: "DB", notes: "all 12 stages + supported final state" },
      { metric: "Intervention Rate", result: interventionJson.result.pct, unit: "%", n: `${interventionJson.result.numerator}/${interventionJson.result.denominator}`, source: "DB", notes: interventionJson.cases.map((c: any) => `${c.tc}: ${c.reason}`).join("; ") || "none" },
      { metric: "Recommendation Retry Rate", result: retryJson.result.pct, unit: "%", n: `${retryJson.result.numerator}/${retryJson.result.denominator}`, source: "DB", notes: `total retry count ${retryJson.result.totalRetryCount} (a count); infrastructure failures excluded: ${retryJson.infrastructure.failedCalls}` },
      { metric: "Mock Verification", result: pct(verificationJson.mock.verificationCompleted, verificationJson.mock.cases), unit: "%", n: `${verificationJson.mock.verificationCompleted}/${verificationJson.mock.cases}`, source: "DB (archived MOCK baseline, frozen)", notes: "completion of a SIMULATED re-hunt (NO_MATCH simulated); not evidence of threat removal; not re-run" },
      { metric: "Real Wazuh Verification", result: verificationJson.real_wazuh.verified_percent_of_executed, unit: "%", n: `${verificationJson.real_wazuh.verified_real_wazuh}/${verificationJson.real_wazuh.cases_with_completed_response}`, source: "DB", notes: `outcomes ${JSON.stringify(dist)}` },
      { metric: "Recommendation Consistency", result: consistencyJson.overall?.pct ?? "NOT AVAILABLE", unit: "%", n: consistencyJson.overall ? `${consistencyJson.overall.numerator}/${consistencyJson.overall.denominator}` : "-", source: "DB evidence snapshots + live LLM generation (data/consistency.json)", notes: "repeated runs on identical evidence; recommendations not persisted" },
      { metric: "Step-set Consistency", result: consistencyJson.stepSetConsistency?.pct ?? "NOT AVAILABLE", unit: "%", n: consistencyJson.stepSetConsistency ? `${consistencyJson.stepSetConsistency.numerator}/${consistencyJson.stepSetConsistency.denominator}` : "-", source: "data/consistency.json", notes: "complete validated step set identical" },
      { metric: "Negative Validation", result: (negativeJson as any).rate?.pct ?? "NOT AVAILABLE", unit: "%", n: (negativeJson as any).rate ? `${(negativeJson as any).rate.numerator}/${(negativeJson as any).rate.denominator}` : "-", source: "controlled validator scenarios on DB-backed catalog (data/negative.json)", notes: "controlled invalid recommendations; NEG-02 is the Action-Knowledge/validator layer, not a Policy rejection" },
      { metric: "Human/Policy Validation", result: humanJson.result.pct, unit: "%", n: `${humanJson.result.passed}/${humanJson.result.total}`, source: "DB (soar_final_eval) governance gates G0-G16 + IR-reject run IRR-01..IRR-12", notes: "governance gates + IR reject flow" },
    ],
    principles, crossDiffs, findings,
  };

  // ------------------------------------------------------------------ database case map (for final-db-metrics.sql)
  const sqlMap = ["-- generated by final-metrics.ts: maps each test case to its incident and frozen Ground Truth expectations", "create temp table final_cases(case_id text, incident_id text, expected_playbook text, allowed_actions text[]);",
    ...cases.filter((r) => r.incident_id).map((r) => `insert into final_cases values ('${r.case_id}', '${r.incident_id}', '${r.expected.playbook}', ARRAY[${r.expected.allowedActions.map((a: string) => `'${a}'`).join(",")}]);`)].join("\n");

  const W = (f: string, o: unknown) => fs.writeFileSync(path.join(OUT, f), JSON.stringify(o, null, 2));
  W("final-per-test-case.json", { database: dbName, run: MAIN, results, cases: perCase, detailed: cases, supplementaryIrRejectCase: rejectCases });
  W("final-recommendation-compliance.json", complianceJson); W("final-investigation-time.json", investigationJson); W("final-time-to-decision.json", decisionJson);
  W("final-workflow-completion.json", workflowJson); W("final-intervention-rate.json", interventionJson); W("final-retry-rate.json", retryJson);
  W("final-verification.json", verificationJson); W("final-consistency.json", consistencyJson); W("final-negative-validation.json", negativeJson);
  W("final-human-policy-validation.json", humanJson); W("final-baseline-comparison.json", baselineJson); W("final-kpi-summary.json", kpi);
  fs.writeFileSync(path.join(OUT, "final-db-case-map.sql"), sqlMap);
  console.log(JSON.stringify({ results, compliance: complianceJson.result, investigation: investigationJson.stats, ttd: decisionJson.stats, workflow: workflowJson.result, intervention: interventionJson.result, retry: retryJson.result, verification: { dist, mock: `${verificationJson.mock.verificationCompleted}/${verificationJson.mock.cases}` }, principles: Object.fromEntries(Object.entries(principles).map(([k, v]) => [k, v.ok])), crossDiffs }, null, 1));
  await prisma.$disconnect();
})().catch((e) => { console.error("final-metrics crashed:", String(e?.stack ?? e).slice(0, 1500)); process.exit(2); });
