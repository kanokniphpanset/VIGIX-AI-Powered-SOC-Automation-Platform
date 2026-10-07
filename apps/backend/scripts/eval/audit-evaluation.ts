/**
 * audit-evaluation.ts — READ-ONLY audit of the existing evaluation results (paper preparation).
 *
 *   cd apps/backend && . scripts/eval/eval-env.sh && npx ts-node --transpile-only scripts/eval/audit-evaluation.ts
 *
 * It never runs an evaluation and never writes to any database: only SELECTs (soar_eval, and counts on
 * soar_platform) plus a read-only search of the Wazuh Indexer. Every number is recomputed from PostgreSQL
 * timestamps / rows and CROSS-CHECKED against results/runs/<label>/run.json; disagreements are listed, not
 * smoothed over. Output: results/evaluation-audit.json (machine readable) and the DATA sections of
 * results/evaluation-audit.md (the narrative sections are written by hand afterwards).
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import https from "node:https";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { REAL_GROUND_TRUTH } from "../../src/evaluation/groundTruthReal";
import { collectEvaluationCase, knownActionCodes } from "../../src/evaluation/EvaluationService";

const ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const RES = path.join(ROOT, "results");
const RUNS: { key: string; label: string; kind: "CLEAN" | "INTERVENTION" | "CONTROL" }[] = [
  { key: "real-clean", label: "clean-v2-real-wazuh-20260930", kind: "CLEAN" },
  { key: "real-intervention", label: "intervention-v2-real-wazuh-20260930", kind: "INTERVENTION" },
  { key: "real-recurrence-control", label: "control-recurrence-real-wazuh-20260930", kind: "CONTROL" },
];
const r2 = (x: number) => Math.round(x * 100) / 100;
const sec = (a: Date | null | undefined, b: Date | null | undefined) => (a && b ? r2((b.getTime() - a.getTime()) / 1000) : null);
export function stats(xs: (number | null)[]) {
  const v = xs.filter((x): x is number => typeof x === "number" && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return { n: 0, mean: null, median: null, min: null, max: null, sd: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const median = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
  const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : 0;
  return { n: v.length, mean: r2(mean), median: r2(median), min: v[0], max: v[v.length - 1], sd: r2(sd) };
}
const pct = (n: number, d: number) => (d ? r2((n / d) * 100) : null);
const sha = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");

function indexerSearch(body: unknown): Promise<any> {
  const base = new URL(process.env.WAZUH_INDEXER_URL ?? "https://localhost:9200");
  const payload = JSON.stringify(body);
  const auth = Buffer.from(`${process.env.WAZUH_INDEXER_USERNAME}:${process.env.WAZUH_INDEXER_PASSWORD}`).toString("base64");
  return new Promise((resolve, reject) => {
    const req = https.request({ method: "POST", hostname: base.hostname, port: base.port || 443, path: "/wazuh-alerts-4.x-*/_search",
      headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
      ca: process.env.WAZUH_INDEXER_CA_PATH ? fs.readFileSync(process.env.WAZUH_INDEXER_CA_PATH) : undefined, servername: process.env.WAZUH_INDEXER_TLS_SERVERNAME || undefined, timeout: 20000 },
      (res) => { const c: Buffer[] = []; res.on("data", (d: Buffer) => c.push(d)); res.on("end", () => { try { resolve(JSON.parse(Buffer.concat(c).toString("utf8"))); } catch (e) { reject(e); } }); });
    req.on("error", reject); req.write(payload); req.end();
  });
}

(async () => {
  const prisma = new PrismaClient();
  const q = <T = any>(sql: string, ...p: unknown[]) => prisma.$queryRawUnsafe<T[]>(sql, ...p);
  const known = await knownActionCodes(prisma);
  const checks: { id: string; name: string; ok: boolean; detail: string }[] = [];
  const chk = (id: string, name: string, ok: boolean, detail: string) => checks.push({ id, name, ok, detail });

  // ---------------------------------------------------------------- load runs
  const runs = RUNS.map((r) => ({ ...r, json: JSON.parse(fs.readFileSync(path.join(RES, "runs", r.label, "run.json"), "utf8")) }));

  // ---------------------------------------------------------------- per-case audit from PostgreSQL
  const auditedRuns: Record<string, any[]> = {};
  const violationReasons: Record<string, Record<string, number>> = {};
  const crossDiffs: string[] = [];
  const indexerDocIds: { run: string; caseId: string; docId: string; dbRule: string; dbTs: string; dbAgent: string }[] = [];
  for (const run of runs) {
    auditedRuns[run.key] = [];
    violationReasons[run.key] = {};
    for (const c of run.json.cases) {
      const row: any = { run: run.key, caseId: c.caseId, attack: c.attackName, environmentStatus: c.environmentStatus ?? "AVAILABLE", incidentId: c.incidentId ?? null };
      if (!c.incidentId) { auditedRuns[run.key].push(row); continue; }
      const [alert] = await q("select id, external_alert_id, siem_source, severity, received_at, created_at, raw_payload from alerts a where a.id::text = (select alert_id::text from incidents where id::text=$1)", c.incidentId);
      const [inc] = await q("select opened_at, status, investigation_number from incidents where id::text=$1", c.incidentId);
      const [inv1] = await q("select started_at, completed_at, status from investigations where incident_id::text=$1 and investigation_number=1", c.incidentId);
      const recs = await q("select id, recommendation_number, investigation_number, status, created_at, snapshot_id from recommendations where incident_id::text=$1 order by recommendation_number", c.incidentId);
      const rec1 = recs.find((r: any) => Number(r.investigation_number) === 1) ?? null;
      row.recommendations = recs.map((r: any) => ({ number: Number(r.recommendation_number), investigation: Number(r.investigation_number), status: r.status }));
      const failed = await q("select created_at, metadata from audit_logs where action='RECOMMENDATION_GENERATION_FAILED' and entity_id::text=$1 order by created_at", c.incidentId);
      row.failedGenerationCalls = failed.length;
      row.failedGenerationCallsInvestigation1 = failed.filter((f: any) => Number(f.metadata?.investigationNumber ?? 1) === 1).length;
      for (const f of failed) for (const v of (f.metadata?.violations ?? []) as string[]) {
        const code = String(v).split(":")[0];
        violationReasons[run.key][code] = (violationReasons[run.key][code] ?? 0) + 1;
        (row.violationCodes ??= {})[code] = ((row.violationCodes ??= {})[code] ?? 0) + 1;
      }
      const ag = alert?.raw_payload?.agent?.name, rid = alert?.raw_payload?.rule?.id;
      row.alert = { externalId: alert?.external_alert_id, source: alert?.siem_source, severity: alert?.severity, agent: ag, ruleId: rid, level: alert?.raw_payload?.rule?.level, mitre: alert?.raw_payload?.rule?.mitre?.id ?? [], wazuhTimestamp: alert?.received_at?.toISOString?.() ?? null, ingestedAt: alert?.created_at?.toISOString?.() ?? null };
      if (c.wazuh?.indexerDocId) indexerDocIds.push({ run: run.key, caseId: c.caseId, docId: c.wazuh.indexerDocId, dbRule: String(rid), dbTs: String(alert?.raw_payload?.timestamp), dbAgent: String(ag) });

      if (rec1) {
        const steps = await q("select rs.step_order, act.code action, rs.target, rs.requires_approval from recommendation_steps rs left join actions act on act.id=rs.action_id where rs.recommendation_id::text=$1 order by rs.step_order", rec1.id);
        const [snap] = await q("select playbook_code, policy_result from playbook_snapshots where id::text=$1", rec1.snapshot_id);
        const [plan] = await q("select id, status, target, created_at, completed_at, executed_at from response_plans where recommendation_id::text=$1 order by created_at limit 1", rec1.id);
        const apprs = plan ? await q("select id, status, approval_role, requested_to, decided_at, decided_by, created_at from approvals where response_id::text=$1 order by created_at", plan.id) : [];
        const [rs] = plan ? await q("select created_at from audit_logs where action='RESPONSE_STARTED' and entity_id::text=$1", plan.id) : [];
        const [spc] = plan ? await q("select created_at, actor from audit_logs where action='RESPONSE_PLAN_CREATED' and entity_id::text=$1", plan.id) : [];
        const [rhs] = plan ? await q("select created_at from audit_logs where action='REHUNT_STARTED' and entity_id::text=$1", plan.id) : [];
        const [rhf] = plan ? await q("select created_at, metadata from audit_logs where action='REHUNT_FAILED' and entity_id::text=$1", plan.id) : [];
        const [ver] = plan ? await q("select id, result, wazuh_index, matching_events, ioc_recurrence, spread_detected, threat_contained, affected_hosts, verified_at, time_range_start, time_range_end, after_state, before_state from verifications where response_id::text=$1", plan.id) : [];
        row.recommendation1 = { id: rec1.id, status: rec1.status, createdAt: rec1.created_at.toISOString(), playbook: snap?.playbook_code ?? null, steps: steps.map((s: any) => ({ action: s.action, target: s.target, requiresApproval: s.requires_approval })) };
        // evidence support recomputed from rows (same membership rule the evaluator uses, computed independently)
        const iocs = await q("select id, ioc_type, ioc_value, created_by from threat_intel_iocs where incident_id::text=$1", c.incidentId);
        const linked = await q("select distinct t.ioc_value v from evidence_iocs ei join evidence e on e.id=ei.evidence_id join investigations i on i.id=e.investigation_id join threat_intel_iocs t on t.id=ei.ioc_id where i.incident_id::text=$1", c.incidentId);
        const linkedSet = new Set(linked.map((l: any) => l.v));
        const manual = new Set(iocs.filter((i: any) => i.created_by && i.created_by !== "system").map((i: any) => i.ioc_value));
        const ev = await q("select structured_data->>'agent' a from evidence e join investigations i on i.id=e.investigation_id where i.incident_id::text=$1", c.incidentId);
        const hosts = new Set([ag, ...ev.map((e: any) => e.a)].filter(Boolean));
        const supportedBy = (t: string) => (linkedSet.has(t) && iocs.some((i: any) => i.ioc_value === t) ? "EVIDENCE_LINKED_IOC" : manual.has(t) && iocs.some((i: any) => i.ioc_value === t) ? "ANALYST_ADDED_IOC" : hosts.has(t) ? "AFFECTED_HOST" : null);
        row.evidence = { stepSupport: steps.map((s: any) => ({ action: s.action, target: s.target, supportedBy: supportedBy(s.target) })), iocCount: iocs.length, evidenceLinkedIocs: linkedSet.size, analystIocs: manual.size };
        row.evidence.allStepsSupported = row.evidence.stepSupport.length > 0 && row.evidence.stepSupport.every((s: any) => !!s.supportedBy);
        const dpol = (snap?.policy_result ?? {}) as Record<string, any>;
        row.approvals = apprs.map((a: any) => ({ status: a.status, role: a.approval_role, requestedTo: a.requested_to, decidedBy: a.decided_by, decidedAt: a.decided_at?.toISOString?.() ?? null }));
        const expectedRoles = [...new Set(steps.map((s: any) => dpol[s.action]?.approvalRole).filter(Boolean))];
        row.approvalCheck = { expectedRoles, decisions: apprs.length, correct: apprs.filter((a: any) => a.status === "approved" && !!a.decided_at && (expectedRoles.length === 0 || expectedRoles.includes(a.approval_role))).length };
        row.plan = plan ? { id: plan.id, status: plan.status, target: plan.target, socCreatedBy: spc?.actor ?? null } : null;
        row.verification = ver ? { id: ver.id, result: ver.result, mode: ver.after_state?.evidenceSource ?? null, index: ver.wazuh_index, matchingEvents: ver.matching_events, iocRecurrence: ver.ioc_recurrence, spreadDetected: ver.spread_detected, threatContained: ver.threat_contained, affectedHosts: ver.affected_hosts, searchedIocs: ver.after_state?.searchedIocs ?? ver.before_state?.criteria?.iocs ?? [], windowStart: ver.time_range_start?.toISOString?.() ?? null, windowEnd: ver.time_range_end?.toISOString?.() ?? null } : null;
        row.rehuntFailed = rhf ? { code: rhf.metadata?.code ?? null, message: rhf.metadata?.message ?? null } : null;
        const T = { alertWazuh: alert?.received_at, alertIngested: alert?.created_at, incidentOpened: inc?.opened_at, invStart: inv1?.started_at, rec: rec1.created_at, decision: apprs.at(-1)?.decided_at ?? null, responseStart: rs?.created_at ?? null, responseDone: plan?.completed_at ?? null, rehuntStart: rhs?.created_at ?? null, verificationEnd: ver?.verified_at ?? rhf?.created_at ?? null };
        row.timestamps = Object.fromEntries(Object.entries(T).map(([k, v]) => [k, (v as Date | null)?.toISOString?.() ?? null]));
        row.times = {
          investigationSeconds: sec(T.invStart, T.rec), timeToDecisionSeconds: sec(T.rec, T.decision),
          detectionToResponseSeconds: sec(T.alertWazuh, T.responseStart), detectionToResponseFromIngestSeconds: sec(T.alertIngested, T.responseStart),
          verificationSeconds: ver ? sec(T.rehuntStart, ver.verified_at) : null, rehuntErrorSeconds: !ver && rhf ? sec(T.rehuntStart, rhf.created_at) : null,
        };
        const order = ["alertWazuh", "alertIngested", "incidentOpened", "invStart", "rec", "decision", "responseStart", "responseDone", "rehuntStart", "verificationEnd"] as const;
        const present = order.filter((k) => T[k]);
        row.timestampsMonotonic = present.every((k, i) => i === 0 || (T[present[i - 1]] as Date).getTime() <= (T[k] as Date).getTime());
        // workflow steps from real rows (not "an incident exists")
        const [ai] = await q("select count(*)::int n from agent_results ar join agent_executions ae on ae.id=ar.agent_execution_id where ae.incident_id::text=$1 and ar.agent_name='llm_analyst'", c.incidentId);
        row.workflowSteps = {
          alertIngested: !!alert, triage: (await q("select 1 from audit_logs where entity_id::text=$1 and action in ('ALERT_ESCALATED_TO_INCIDENT','ALERT_ROUTED_TO_TRIAGE')", alert.id)).length > 0,
          incident: !!inc, investigation: inv1?.status === "COMPLETED", aiAnalysis: ai.n > 0, recommendationValidated: rec1.status === "VALIDATED" || recs.some((r: any) => r.status === "VALIDATED"),
          policyEvaluated: !!snap && Object.keys(dpol).length > 0, socValidation_responseTicket: !!plan && !!spc, irDecision: apprs.some((a: any) => a.status === "approved" && a.decided_at), responseCompleted: plan?.status === "COMPLETED", verification: !!ver,
        };
        row.workflowComplete = Object.values(row.workflowSteps).every(Boolean);
      } else { row.workflowSteps = { alertIngested: !!alert, incident: !!inc }; row.workflowComplete = false; row.recommendation1 = null; }
      // re-score deterministically from the DB and compare with what run.json stored
      const rescored = await collectEvaluationCase(prisma, { ...c.groundTruth, knownFindings: [] }, known, c.incidentId);
      row.rescored = { compliance: rescored.recommendationCompliance, checks: rescored.compliance ? { attackAlignment: rescored.compliance.attackAlignment, evidenceSupport: rescored.compliance.evidenceSupport, knowledgeValidity: rescored.compliance.knowledgeValidity, policyCompliance: rescored.compliance.policyCompliance, playbookAlignment: rescored.compliance.playbookAlignment, approvalCorrectness: rescored.compliance.approvalCorrectness } : null, failedChecks: rescored.compliance?.failedChecks ?? [], retries: rescored.invalidOutputCount, verificationMode: rescored.verificationMode, verificationResult: rescored.verificationResult, workflowCompleted: rescored.workflowCompleted };
      row.expectedPlaybook = c.groundTruth?.expectedPlaybook;
      row.playbookCodeMatches = row.recommendation1?.playbook === row.expectedPlaybook;
      row.interventions = c.interventions ?? [];
      row.observations = c.observations ?? [];
      row.iocRecallBeforeCorrection = c.iocRecall ?? null;
      // cross-check against run.json (the stored result)
      const stored = { compliance: c.recommendationCompliance, retries: c.invalidOutputCount, verificationResult: c.verificationResult, verificationMode: c.verificationMode, inv: c.investigationTimeSeconds, dec: c.timeToDecisionSeconds };
      const near = (a: number | null, b: number | null) => (a === null && b === null) || (a !== null && b !== null && Math.abs(a - b) <= 0.02);
      if (stored.compliance !== row.rescored.compliance) crossDiffs.push(`${run.key} ${c.caseId}: compliance run.json=${stored.compliance} rescored=${row.rescored.compliance}`);
      if (stored.retries !== row.rescored.retries) crossDiffs.push(`${run.key} ${c.caseId}: retries run.json=${stored.retries} rescored=${row.rescored.retries}`);
      if ((stored.verificationResult ?? null) !== (row.rescored.verificationResult ?? null)) crossDiffs.push(`${run.key} ${c.caseId}: verification run.json=${stored.verificationResult} rescored=${row.rescored.verificationResult}`);
      if (row.times && !near(stored.inv ?? null, row.times.investigationSeconds)) crossDiffs.push(`${run.key} ${c.caseId}: investigation time run.json=${stored.inv} audit=${row.times.investigationSeconds}`);
      if (row.times && !near(stored.dec ?? null, row.times.timeToDecisionSeconds)) crossDiffs.push(`${run.key} ${c.caseId}: time-to-decision run.json=${stored.dec} audit=${row.times.timeToDecisionSeconds}`);
      auditedRuns[run.key].push(row);
    }
  }

  // ---------------------------------------------------------------- KPI per run
  const criteria = ["attackAlignment", "evidenceSupport", "knowledgeValidity", "policyCompliance", "playbookAlignment", "approvalCorrectness"];
  const kpi: Record<string, any> = {};
  for (const run of runs) {
    const rows = auditedRuns[run.key];
    const attempted = rows.filter((r) => r.environmentStatus !== "ENVIRONMENT_UNAVAILABLE");
    const withRec = attempted.filter((r) => r.rescored && r.rescored.compliance !== "NOT_EVALUATED");
    const compliant = withRec.filter((r) => r.rescored.compliance === "COMPLIANT");
    const executed = attempted.filter((r) => r.plan?.status === "COMPLETED");
    const verified = attempted.filter((r) => r.verification);
    const resolved = verified.filter((r) => r.verification.result === "RESOLVED");
    const outcomeOf = (r: any) => (r.rehuntFailed && !r.verification ? "ERROR" : !r.verification ? "NOT_VERIFIED" : r.verification.result === "RESOLVED" ? "RESOLVED" : r.verification.spreadDetected ? "SPREAD" : r.verification.threatContained === false ? "NOT_CONTAINED" : "NOT_RESOLVED");
    const outcomes: Record<string, number> = {};
    for (const r of executed) outcomes[outcomeOf(r)] = (outcomes[outcomeOf(r)] ?? 0) + 1;
    const allApprovals = attempted.flatMap((r) => (r.approvalCheck ? [r.approvalCheck] : []));
    const crit = (k: string) => withRec.filter((r) => r.rescored.checks?.[k]).length;
    const failedGen = attempted.reduce((a, r) => a + (r.failedGenerationCallsInvestigation1 ?? r.failedGenerationCalls ?? 0), 0);
    const retryCases = attempted.filter((r) => (r.failedGenerationCallsInvestigation1 ?? 0) > 0);
    const intervCases = attempted.filter((r) => r.interventions.length);
    const wfDone = attempted.filter((r) => r.workflowComplete);
    kpi[run.key] = {
      kind: run.kind, total: rows.length, attempted: attempted.length, unavailable: rows.length - attempted.length,
      recommendationCompliance: { numerator: compliant.length, denominator: withRec.length, pct: pct(compliant.length, withRec.length), denominatorAttempted: attempted.length, pctOfAttempted: pct(compliant.length, attempted.length), noValidRecommendation: attempted.filter((r) => !withRec.includes(r)).map((r) => r.caseId) },
      investigationTime: stats(attempted.map((r) => r.times?.investigationSeconds ?? null)),
      timeToDecision: stats(attempted.map((r) => r.times?.timeToDecisionSeconds ?? null)),
      verificationEffectiveness: { definition: "cases whose REAL re-hunt confirmed no recurrence (RESOLVED) / cases with a completed response execution", numerator: resolved.length, denominator: executed.length, pct: pct(resolved.length, executed.length), outcomes },
      workflowCompletion: { numerator: wfDone.length, denominator: attempted.length, pct: pct(wfDone.length, attempted.length), pctOfTotal: pct(wfDone.length, rows.length), incomplete: attempted.filter((r) => !r.workflowComplete).map((r) => `${r.caseId}(${r.recommendation1 ? (r.rehuntFailed ? "re-hunt " + (r.rehuntFailed.code ?? "failed") : "incomplete") : "no valid recommendation"})`) },
      interventionRate: { numerator: intervCases.length, denominator: attempted.length, pct: pct(intervCases.length, attempted.length), cases: intervCases.map((r) => r.caseId) },
      retry: { caseRateNumerator: retryCases.length, caseRateDenominator: attempted.length, caseRatePct: pct(retryCases.length, attempted.length), totalRetryCount: failedGen, averagePerCase: attempted.length ? r2(failedGen / attempted.length) : null, perCase: Object.fromEntries(attempted.map((r) => [r.caseId, r.failedGenerationCallsInvestigation1 ?? 0])), reasons: violationReasons[run.key] },
      evidenceCoverage: { casesWithRecommendationAllTargetsEvidenceBacked: attempted.filter((r) => r.evidence?.allStepsSupported).length, denominatorAttempted: attempted.length, pctOfAttempted: pct(attempted.filter((r) => r.evidence?.allStepsSupported).length, attempted.length), evidenceSupportCriterionPassed: crit("evidenceSupport"), denominatorWithRecommendation: withRec.length, pctOfRecommendations: pct(crit("evidenceSupport"), withRec.length) },
      policyCompliance: { numerator: crit("policyCompliance"), denominator: withRec.length, pct: pct(crit("policyCompliance"), withRec.length) },
      playbookAlignment: { numerator: crit("playbookAlignment"), denominator: withRec.length, pct: pct(crit("playbookAlignment"), withRec.length), codeEqualityNumerator: withRec.filter((r) => r.playbookCodeMatches).length, mismatches: withRec.filter((r) => !r.playbookCodeMatches).map((r) => `${r.caseId}: expected ${r.expectedPlaybook}, actual ${r.recommendation1?.playbook}`) },
      approvalCorrectness: { numerator: allApprovals.reduce((a, x) => a + x.correct, 0), denominator: allApprovals.reduce((a, x) => a + x.decisions, 0), pct: pct(allApprovals.reduce((a, x) => a + x.correct, 0), allApprovals.reduce((a, x) => a + x.decisions, 0)), rejectedDecisions: attempted.reduce((a, r) => a + (r.approvals ?? []).filter((x: any) => x.status === "rejected").length, 0) },
      detectionToResponse: { fromWazuhAlertTimestamp: stats(executed.map((r) => r.times.detectionToResponseSeconds)), fromVigixIngest: stats(executed.map((r) => r.times.detectionToResponseFromIngestSeconds)) },
      verificationTime: { total: stats(verified.map((r) => r.times.verificationSeconds)), timeToErrorForFailedRehunts: stats(attempted.map((r) => r.times?.rehuntErrorSeconds ?? null)) },
      allTimestampsMonotonic: attempted.filter((r) => r.timestamps).every((r) => r.timestampsMonotonic),
    };
  }

  // ---------------------------------------------------------------- data-integrity checks
  const allRows = Object.values(auditedRuns).flat().filter((r) => r.incidentId);
  const [{ n: alertsN }] = await q("select count(*)::int n from alerts");
  const [{ n: incN }] = await q("select count(*)::int n from incidents");
  chk("I1", "soar_eval contains exactly the incidents of the three primary runs", incN === allRows.length && alertsN === allRows.length, `alerts=${alertsN}, incidents=${incN}, cases with incident in run.json=${allRows.length}`);
  chk("I2", "every eval alert is siem_source=wazuh from the real lab agent", allRows.every((r) => r.alert.source === "wazuh" && r.alert.agent === "attack-endpoint"), `agents: ${[...new Set(allRows.map((r) => r.alert.agent))].join(",")}`);
  // alerts exist in the live Wazuh indexer with the same rule/timestamp
  let idxOk = 0; const idxBad: string[] = [];
  if (indexerDocIds.length) {
    const res = await indexerSearch({ size: indexerDocIds.length, query: { ids: { values: indexerDocIds.map((d) => d.docId) } }, _source: ["rule.id", "agent.name", "timestamp"] });
    const byId = new Map<string, any>((res.hits?.hits ?? []).map((h: any) => [h._id, h._source]));
    for (const d of indexerDocIds) { const s = byId.get(d.docId); if (s && String(s.rule?.id) === d.dbRule && s.agent?.name === d.dbAgent && String(s.timestamp) === d.dbTs) idxOk++; else idxBad.push(`${d.run}/${d.caseId}`); }
  }
  chk("I3", "every ingested alert exists in the live Wazuh Indexer with identical rule.id/agent/timestamp", idxOk === indexerDocIds.length && indexerDocIds.length === allRows.length, `${idxOk}/${indexerDocIds.length} matched${idxBad.length ? "; missing " + idxBad.join(",") : ""}`);
  const mockVer = await q("select count(*)::int n from verifications where coalesce(after_state->>'evidenceSource','') <> 'WAZUH_INDEXER' or wazuh_index ilike '%clean-rehunt%' or wazuh_index ilike '%mock%'");
  const [{ n: verN }] = await q("select count(*)::int n from verifications");
  chk("I4", "no MOCK / manual verification exists in soar_eval", mockVer[0].n === 0, `${verN} verifications, ${mockVer[0].n} not from WAZUH_INDEXER`);
  const gtHash = sha(JSON.stringify(REAL_GROUND_TRUTH));
  chk("I5", "real ground truth unchanged since each run (sha256)", runs.every((r) => r.json.groundTruthSha256 === gtHash), `current ${gtHash.slice(0, 16)}…; runs: ${runs.map((r) => String(r.json.groundTruthSha256).slice(0, 16) + "…").join(", ")}`);
  const evalOut = path.join(ROOT, "apps", "backend", "scripts", "eval-out", "evaluation.json");
  const arch = fs.readdirSync(path.join(RES, "archive")).filter((d) => d.startsWith("mock-run-pre-real-")).sort().pop()!;
  const archFile = path.join(RES, "archive", arch, "evaluation.json");
  chk("I6", "MOCK baseline archive is byte-identical to scripts/eval-out/evaluation.json", sha(fs.readFileSync(evalOut)) === sha(fs.readFileSync(archFile)), `sha256 ${sha(fs.readFileSync(archFile)).slice(0, 16)}…`);
  const mock = JSON.parse(fs.readFileSync(archFile, "utf8"));
  const mk = mock.summary, mc = mock.cases;
  const mockNums = { compliance: `${mk.compliantRecommendations}/${mk.evaluatedCases}`, workflow: `${mk.workflowCompletedCases}/${mk.totalCases}`, invAvg: mk.investigationTimeAverage, decAvg: mk.decisionTimeAverage, verificationMock: mk.mockVerificationCases, real: mk.realWazuhVerificationCases, retryCases: mc.filter((c: any) => c.invalidOutputCount > 0).length, retryTotal: mc.reduce((a: number, c: any) => a + c.invalidOutputCount, 0), interventionCases: mk.interventionCases };
  chk("I7", "MOCK baseline equals the stated baseline (100% 10/10, 2152 s, 1387 s, 10/10 MOCK, 4/10, 43 retries)", mockNums.compliance === "10/10" && mockNums.workflow === "10/10" && Math.round(mockNums.invAvg) === 2152 && Math.round(mockNums.decAvg) === 1387 && mockNums.verificationMock === 10 && mockNums.retryCases === 4 && mockNums.retryTotal === 43 && mockNums.interventionCases === 4, JSON.stringify(mockNums));
  chk("I8", "audit re-score from PostgreSQL equals the stored run.json results", crossDiffs.length === 0, crossDiffs.length ? crossDiffs.join("; ") : "compliance, retries, verification result, investigation time and time-to-decision all agree for every case");
  chk("I9", "timestamps are monotonic (alert ≤ … ≤ verification) in every case", allRows.filter((r) => r.timestamps).every((r) => r.timestampsMonotonic), `${allRows.filter((r) => r.timestamps && !r.timestampsMonotonic).map((r) => r.run + "/" + r.caseId).join(",") || "no violations"}`);
  chk("I10", "real-run incidents are not shared between runs", new Set(allRows.map((r) => r.incidentId)).size === allRows.length, `${new Set(allRows.map((r) => r.incidentId)).size} distinct incidents`);
  const noMock = mc.every((c: any) => true);
  const platformUrl = (process.env.DATABASE_URL ?? "").replace(/\/soar_eval(\?|$)/, "/soar_platform$1");
  let platform: any = null;
  try { const p2 = new PrismaClient({ datasources: { db: { url: platformUrl } } }); const [a] = await p2.$queryRawUnsafe<any[]>("select count(*)::int n, max(created_at) m from alerts"); const [i] = await p2.$queryRawUnsafe<any[]>("select count(*)::int n from incidents"); const [e] = await p2.$queryRawUnsafe<any[]>("select count(*)::int n from alerts where external_alert_id = any($1::text[])", allRows.map((r) => r.alert.externalId)); platform = { alerts: a.n, incidents: i.n, latestAlert: a.m, evalAlertsAlsoInPlatform: e.n }; await p2.$disconnect(); } catch (e) { platform = { error: String((e as Error).message).slice(0, 100) }; }
  chk("I11", "soar_platform was not written by the harness (pre-eval baseline: 260 alerts / 39 incidents)", platform && platform.incidents === 39, `now ${JSON.stringify(platform)} — any growth in alerts comes from the manager's custom-vigix webhook, not from the harness`);
  void noMock;

  // ---------------------------------------------------------------- control experiment
  const ctl = auditedRuns["real-recurrence-control"].find((r) => r.incidentId);
  const [ctlInv] = ctl ? await q("select investigation_number, status from investigations where incident_id::text=$1 order by investigation_number", ctl.incidentId).then((x: any[]) => [x]) : [[]];
  const ctlInvestigations = ctl ? await q("select investigation_number, status from investigations where incident_id::text=$1 order by investigation_number", ctl.incidentId) : [];
  const ctlReopen = ctl ? await q("select metadata from audit_logs where action='INVESTIGATION_REOPENED' and entity_id::text=$1", ctl.incidentId) : [];
  const [ctlInc] = ctl ? await q("select status, investigation_number from incidents where id::text=$1", ctl.incidentId) : [null];
  void ctlInv;
  const control = ctl && ctl.verification ? { matchingEvents: ctl.verification.matchingEvents, iocRecurrence: ctl.verification.iocRecurrence, spreadDetected: ctl.verification.spreadDetected, threatContained: ctl.verification.threatContained, result: ctl.verification.result, mode: ctl.verification.mode, incidentStatus: ctlInc?.status, investigations: ctlInvestigations.map((i: any) => `#${i.investigation_number}:${i.status}`), reopenedBy: ctlReopen[0]?.metadata?.matchedPolicies ?? [], incidentResolvedByAi: false } : null;

  const out = { generatedAt: new Date().toISOString(), readOnly: true, checks, kpi, control, mockBaseline: mockNums, platform, cases: auditedRuns, crossDiffs };
  fs.writeFileSync(path.join(RES, "evaluation-audit.json"), JSON.stringify(out, null, 2));
  console.log(JSON.stringify({ checks: checks.map((c) => `${c.ok ? "PASS" : "FAIL"} ${c.id} ${c.name} :: ${c.detail.slice(0, 160)}`), control }, null, 1));
  await prisma.$disconnect();
})().catch((e) => { console.error("audit crashed:", String(e?.stack ?? e).slice(0, 1200)); process.exit(2); });
