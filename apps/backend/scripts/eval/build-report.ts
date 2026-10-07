/**
 * build-report.ts — aggregate evaluation runs into results/ (JSON + CSV + Markdown). READ-ONLY over run outputs.
 *
 *   npx ts-node --transpile-only scripts/eval/build-report.ts --clean <runLabel> [--intervention <runLabel>] [--post-fix <runLabel>]
 *
 * MOCK and REAL_WAZUH are kept in SEPARATE sections and are never averaged together. The MOCK section is the
 * archived original run (results/archive/mock-run-pre-real-*) plus its repeated single-pass timing file; its
 * per-case verification rows are read (SELECT only) from the database that produced them.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { execFileSync } from "node:child_process";

const arg = (n: string) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : undefined; };
const ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const RES = path.join(ROOT, "results");
const r2 = (x: number) => Math.round(x * 100) / 100;

// ---------------------------------------------------------------- stats
export function stats(xs: (number | null | undefined)[]) {
  const v = xs.filter((x): x is number => typeof x === "number" && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return { n: 0, average: null, median: null, min: null, max: null, stdDev: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const median = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
  const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : 0;
  return { n: v.length, average: r2(mean), median: r2(median), min: v[0], max: v[v.length - 1], stdDev: r2(sd) };
}

// ---------------------------------------------------------------- normalized case row
export interface Row {
  run: string; evaluationType: "MOCK" | "REAL_WAZUH"; mode: string; caseId: string; attack: string; severity: string | null;
  environmentStatus: string; telemetry: string; compliance: string; checks: Record<string, boolean> | null; failedChecks: string[];
  investigationSeconds: number | null; decisionSeconds: number | null; timingMode: string;
  retries: number; interventions: { type: string; detail: string }[]; verificationMode: string; verificationResult: string | null;
  verification: Record<string, unknown> | null; workflowCompleted: boolean; workflow: Record<string, boolean> | null; finalStatus: string | null;
  playbook: string | null; observations: string[]; findings: string[]; incidentId: string | null;
}

function classifyMockFinding(f: string): { type: string; detail: string }[] {
  const out: { type: string; detail: string }[] = [];
  if (/analyst manually|analyst/i.test(f)) out.push({ type: "ANALYST_IOC_CORRECTION", detail: f });
  if (/PB-[A-Z0-9-]+ was seeded/i.test(f)) out.push({ type: "PLAYBOOK_SEED_UPDATE", detail: f });
  if (/MITRE catalog/i.test(f)) out.push({ type: "MITRE_CATALOG_UPDATE", detail: f });
  return out;
}

function psql(sql: string): string[][] {
  const out = execFileSync("docker", ["exec", "soar-postgres", "sh", "-c", `psql -U "$POSTGRES_USER" -d soar_platform -At -F '|' -c "${sql}"`], { encoding: "utf8" });
  return out.split(/\r?\n/).filter(Boolean).map((l) => l.split("|"));
}

function loadMock(): { rows: Row[]; repeated: any; source: string } {
  const arch = fs.readdirSync(path.join(RES, "archive")).filter((d) => d.startsWith("mock-run-pre-real-")).sort().pop()!;
  const dir = path.join(RES, "archive", arch);
  const j = JSON.parse(fs.readFileSync(path.join(dir, "evaluation.json"), "utf8"));
  const ids = j.cases.map((c: any) => c.verificationId).filter(Boolean).map((i: string) => `'${i}'`).join(",");
  const ver: Record<string, any> = {};
  if (ids) for (const [id, me, spread, rec, cont, idx] of psql(`select id, matching_events, spread_detected, ioc_recurrence, threat_contained, wazuh_index from verifications where id in (${ids})`))
    ver[id] = { matchingEvents: Number(me), spreadDetected: spread === "t", iocRecurrence: rec === "t", threatContained: cont === "t", index: idx };
  const iids = j.cases.map((c: any) => c.incidentId).filter(Boolean).map((i: string) => `'${i}'`).join(",");
  const agentOf: Record<string, string> = {};
  if (iids) for (const [id, agent] of psql(`select i.id, a.raw_payload->'agent'->>'name' from incidents i join alerts a on a.id=i.alert_id where i.id in (${iids})`)) agentOf[id] = agent;
  const REAL_LAB_AGENTS = ["attack-endpoint", "vigix-lab-agent"];
  const rows: Row[] = j.cases.map((c: any): Row => ({
    run: "mock-original", evaluationType: "MOCK", mode: "MOCK (JSON alerts + CleanRehuntAdapter)", caseId: c.caseId, attack: c.attackName, severity: c.severity, environmentStatus: "AVAILABLE (mock)",
    telemetry: REAL_LAB_AGENTS.includes(agentOf[c.incidentId]) ? `HYBRID: alert came from REAL lab agent '${agentOf[c.incidentId]}' (run-evaluation.ts selects the latest alert by rule id only) + MOCK verification` : "MOCK_ALERT_JSON",
    compliance: c.recommendationCompliance, checks: c.compliance ? { attackAlignment: c.compliance.attackAlignment, evidenceSupport: c.compliance.evidenceSupport, knowledgeValidity: c.compliance.knowledgeValidity, policyCompliance: c.compliance.policyCompliance, playbookAlignment: c.compliance.playbookAlignment, approvalCorrectness: c.compliance.approvalCorrectness } : null, failedChecks: c.compliance?.failedChecks ?? [],
    investigationSeconds: c.investigationTimeSeconds, decisionSeconds: c.timeToDecisionSeconds, timingMode: "WITH_MANUAL_GAPS (stepwise, interrupted run; see repeated single-pass for clean latency)",
    retries: c.invalidOutputCount, interventions: c.findings.flatMap(classifyMockFinding), verificationMode: c.verificationMode, verificationResult: c.verificationResult,
    verification: c.verificationId ? { ...ver[c.verificationId], note: "NO_MATCH is SIMULATED by CleanRehuntAdapter — this is NOT real threat detection" } : null,
    workflowCompleted: c.workflowCompleted, workflow: c.workflow, finalStatus: c.finalStatus, playbook: c.playbookCode, observations: REAL_LAB_AGENTS.includes(agentOf[c.incidentId]) ? [`MOCK_RUN_CONTAMINATION: this row is NOT a pure mock alert - the incident was built from a real Wazuh alert of agent ${agentOf[c.incidentId]}; only its verification is mock`] : [], findings: c.findings, incidentId: c.incidentId,
  }));
  const repPath = path.join(dir, "repeated-evaluation-N2.json");
  return { rows, repeated: fs.existsSync(repPath) ? JSON.parse(fs.readFileSync(repPath, "utf8")) : null, source: path.relative(ROOT, dir).replace(/\\/g, "/") };
}

/** Supplementary, deterministic: an IP-blocking step aimed at the alerting endpoint's OWN address would block the victim.
 *  evidenceSupport (membership in the incident's IOCs) cannot see this, so it is reported next to - not inside - the KPI. */
function selfTargeting(c: any): string[] {
  const own = c.simulation?.facts?.endpointIp, m = c.actionMatch;
  if (!own || !m) return [];
  return m.actualActions.map((a: string, i: number) => (["ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP"].includes(a) && m.actualTargets[i] === own ? `SELF_TARGETING_STEP (not counted in the six criteria): ${a} targets ${own}, the monitored endpoint's own address; the compliance evaluator accepts it because that IP is an evidence-linked IOC` : "")).filter(Boolean);
}

function loadReal(label: string, runName: string): { rows: Row[]; meta: any } {
  const j = JSON.parse(fs.readFileSync(path.join(RES, "runs", label, "run.json"), "utf8"));
  const rows: Row[] = j.cases.map((c: any): Row => ({
    run: runName, evaluationType: "REAL_WAZUH", mode: j.mode, caseId: c.caseId, attack: c.attackName, severity: c.severity ?? c.groundTruth?.expectedSeverity ?? null, environmentStatus: c.environmentStatus ?? "AVAILABLE", telemetry: c.telemetry ?? c.mode,
    compliance: c.recommendationCompliance ?? "NOT_EVALUATED", checks: c.compliance ? { attackAlignment: c.compliance.attackAlignment, evidenceSupport: c.compliance.evidenceSupport, knowledgeValidity: c.compliance.knowledgeValidity, policyCompliance: c.compliance.policyCompliance, playbookAlignment: c.compliance.playbookAlignment, approvalCorrectness: c.compliance.approvalCorrectness } : null, failedChecks: c.compliance?.failedChecks ?? [],
    investigationSeconds: c.investigationTimeSeconds ?? null, decisionSeconds: c.timeToDecisionSeconds ?? null, timingMode: c.timingMode ?? "UNINTERRUPTED_SCRIPTED (no human gap; decision latency = scripted IR API call, not human deliberation)",
    retries: c.invalidOutputCount ?? 0, interventions: c.interventions ?? [], verificationMode: c.verificationMode ?? "NONE", verificationResult: c.verificationResult ?? null,
    verification: c.verificationDetail ?? (c.rehuntError ? { rehuntError: c.rehuntError } : null), workflowCompleted: !!c.workflowCompleted, workflow: c.workflow ?? null, finalStatus: c.finalStatus ?? null,
    playbook: c.playbookCode ?? null, observations: [...(c.observations ?? []), ...selfTargeting(c)], findings: c.findings ?? [], incidentId: c.incidentId ?? null,
  }));
  return { rows, meta: j };
}

// ---------------------------------------------------------------- summary
function summarize(rows: Row[]) {
  const attempted = rows.filter((r) => r.environmentStatus !== "ENVIRONMENT_UNAVAILABLE");
  const evaluated = attempted.filter((r) => r.compliance !== "NOT_EVALUATED");
  const compliant = evaluated.filter((r) => r.compliance === "COMPLIANT").length;
  const intervened = attempted.filter((r) => r.interventions.length);
  const byType: Record<string, number> = {};
  for (const r of intervened) for (const t of new Set(r.interventions.map((i) => i.type))) byType[t] = (byType[t] ?? 0) + 1;
  const retryCases = attempted.filter((r) => r.retries > 0);
  const ver = attempted.filter((r) => r.verificationResult);
  const criteria = ["attackAlignment", "evidenceSupport", "knowledgeValidity", "policyCompliance", "playbookAlignment", "approvalCorrectness"];
  return {
    totalCases: rows.length, attemptedCases: attempted.length, environmentUnavailableCases: rows.length - attempted.length,
    recommendationCompliance: { evaluated: evaluated.length, compliant, ratePercent: evaluated.length ? r2((compliant / evaluated.length) * 100) : null, formula: "compliant / evaluated recommendations × 100",
      perCriterionPassed: Object.fromEntries(criteria.map((k) => [k, evaluated.filter((r) => r.checks?.[k as keyof typeof r.checks]).length])),
      automaticCompliant: evaluated.filter((r) => r.compliance === "COMPLIANT" && !r.interventions.length).length },
    investigationTime: { unit: "seconds", ...stats(attempted.map((r) => r.investigationSeconds)) },
    timeToDecision: { unit: "seconds", ...stats(attempted.map((r) => r.decisionSeconds)) },
    workflowCompletion: { completed: attempted.filter((r) => r.workflowCompleted).length, ofAttempted: attempted.length, ofTotal: rows.length, ratePercentOfAttempted: attempted.length ? r2((attempted.filter((r) => r.workflowCompleted).length / attempted.length) * 100) : null, ratePercentOfTotal: rows.length ? r2((attempted.filter((r) => r.workflowCompleted).length / rows.length) * 100) : null },
    interventionRate: { cases: intervened.length, ofAttempted: attempted.length, ratePercentOfAttempted: attempted.length ? r2((intervened.length / attempted.length) * 100) : null, byTypeCases: byType, definition: "cases with ≥1 correction applied during the run / attempted cases × 100 (retries are reported separately)" },
    retry: { caseLevelRatePercent: attempted.length ? r2((retryCases.length / attempted.length) * 100) : null, casesWithRetry: retryCases.length, ofAttempted: attempted.length, totalRetryCount: attempted.reduce((a, r) => a + r.retries, 0), perCase: Object.fromEntries(attempted.map((r) => [r.caseId, r.retries])), note: "total retry count is a COUNT of RECOMMENDATION_GENERATION_FAILED events, not a percentage" },
    verification: { casesVerified: ver.length, resolved: ver.filter((r) => r.verificationResult === "RESOLVED").length, notResolved: ver.filter((r) => r.verificationResult === "NOT_RESOLVED").length, modes: Object.fromEntries(["MOCK", "REAL_WAZUH", "NONE"].map((m) => [m, attempted.filter((r) => r.verificationMode === m).length])) },
  };
}

// ---------------------------------------------------------------- outputs
const fmt = (n: number | null | undefined, u = "s") => (n === null || n === undefined ? "–" : `${n}${u}`);
function finalTable(rows: Row[]): string {
  const h = "| TC | Attack | Severity | Compliance | Investigation Time | Time-to-Decision | Retries | Intervention | Verification | Final Status |\n|---|---|---|---|---:|---:|---:|---|---|---|\n";
  return h + rows.map((r) => `| ${r.caseId} | ${r.attack} | ${r.severity ?? "–"} | ${r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "ENVIRONMENT_UNAVAILABLE" : r.compliance} | ${fmt(r.investigationSeconds)} | ${fmt(r.decisionSeconds)} | ${r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "–" : r.retries} | ${r.interventions.length ? [...new Set(r.interventions.map((i) => i.type))].join("; ") : "none"} | ${r.verificationResult ? `${r.verificationResult} (${r.verificationMode})` : r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "–" : "not reached"} | ${r.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "ENVIRONMENT_UNAVAILABLE" : (r.finalStatus ?? "no incident")} |`).join("\n");
}
function summaryBlock(s: ReturnType<typeof summarize>, mode: string): string {
  const c = s.recommendationCompliance;
  return [
    `- Recommendation Compliance: **${c.ratePercent ?? "n/a"}%** (${c.compliant}/${c.evaluated} evaluated; ${c.automaticCompliant} compliant with no intervention). Counting attempted cases that produced NO valid recommendation as non-compliant: ${s.attemptedCases ? r2((c.compliant / s.attemptedCases) * 100) : "n/a"}% (${c.compliant}/${s.attemptedCases} attempted)`,
    `- Workflow Completion: **${s.workflowCompletion.ratePercentOfAttempted ?? "n/a"}%** (${s.workflowCompletion.completed}/${s.workflowCompletion.ofAttempted} attempted; ${s.workflowCompletion.ratePercentOfTotal}% of all ${s.workflowCompletion.ofTotal})`,
    `- Investigation Time: avg **${fmt(s.investigationTime.average)}**, median ${fmt(s.investigationTime.median)}, min ${fmt(s.investigationTime.min)}, max ${fmt(s.investigationTime.max)}, SD ${fmt(s.investigationTime.stdDev)} (n=${s.investigationTime.n})`,
    `- Time-to-Decision: avg **${fmt(s.timeToDecision.average)}**, median ${fmt(s.timeToDecision.median)}, min ${fmt(s.timeToDecision.min)}, max ${fmt(s.timeToDecision.max)}, SD ${fmt(s.timeToDecision.stdDev)} (n=${s.timeToDecision.n})`,
    `- Intervention Rate: **${s.interventionRate.ratePercentOfAttempted ?? "n/a"}%** (${s.interventionRate.cases}/${s.interventionRate.ofAttempted}) ${Object.keys(s.interventionRate.byTypeCases).length ? "— " + Object.entries(s.interventionRate.byTypeCases).map(([k, v]) => `${k}: ${v}`).join(", ") : ""}`,
    `- Retry Case Rate: **${s.retry.caseLevelRatePercent ?? "n/a"}%** (${s.retry.casesWithRetry}/${s.retry.ofAttempted} cases with ≥1 retry)`,
    `- Total Retry Count: **${s.retry.totalRetryCount}** (${Object.entries(s.retry.perCase).filter(([, v]) => v > 0).map(([k, v]) => `${k}=${v}`).join(", ") || "none"})`,
    `- Verification Result: ${s.verification.resolved} RESOLVED / ${s.verification.notResolved} NOT_RESOLVED of ${s.verification.casesVerified} verified`,
    `- Verification Mode: ${mode} — MOCK cases ${s.verification.modes.MOCK}, REAL_WAZUH cases ${s.verification.modes.REAL_WAZUH}, no verification ${s.verification.modes.NONE}`,
  ].join("\n");
}

const esc = (v: unknown) => { const t = v === null || v === undefined ? "" : String(v); return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
const csv = (head: string[], rows: unknown[][]) => [head, ...rows].map((r) => r.map(esc).join(",")).join("\n");

(() => {
  const cleanLabel = arg("clean"), ivLabel = arg("intervention"), pfLabel = arg("post-fix"), ctlLabel = arg("control");
  const mock = loadMock();
  const runs: Record<string, { rows: Row[]; meta: any }> = {};
  if (cleanLabel) runs["real-clean"] = loadReal(cleanLabel, "real-clean");
  if (ivLabel) runs["real-intervention"] = loadReal(ivLabel, "real-intervention");
  if (pfLabel) runs["real-post-fix"] = loadReal(pfLabel, "real-post-fix");
  if (ctlLabel) runs["real-recurrence-control"] = loadReal(ctlLabel, "real-recurrence-control");

  const sections: Record<string, { evaluationType: string; source: string; summary: ReturnType<typeof summarize>; rows: Row[]; environment?: unknown; groundTruthSha256?: string; startedAt?: string }> = {
    "mock-original": { evaluationType: "MOCK", source: mock.source, summary: summarize(mock.rows), rows: mock.rows },
  };
  for (const [k, v] of Object.entries(runs)) sections[k] = { evaluationType: "REAL_WAZUH", source: `results/runs/${v.meta.runLabel}/run.json`, summary: summarize(v.rows), rows: v.rows, environment: v.meta.preflight?.env, groundTruthSha256: v.meta.groundTruthSha256, startedAt: v.meta.startedAt };

  fs.mkdirSync(RES, { recursive: true });
  const w = (f: string, o: unknown) => fs.writeFileSync(path.join(RES, f), typeof o === "string" ? o : JSON.stringify(o, null, 2));
  const all = Object.values(sections).flatMap((s) => s.rows);

  w("evaluation.json", { generatedAt: new Date().toISOString(), note: "MOCK and REAL_WAZUH are separate sections; never combine their numbers. MOCK verification uses CleanRehuntAdapter: NO_MATCH is simulated.", mockRepeatedSinglePass: mock.repeated, runs: Object.fromEntries(Object.entries(sections).map(([k, s]) => [k, { evaluationType: s.evaluationType, source: s.source, startedAt: s.startedAt, groundTruthSha256: s.groundTruthSha256, environment: s.environment, summary: s.summary }])) });
  w("evaluation.csv", csv(["run", "evaluationType", "metric", "value"], Object.entries(sections).flatMap(([k, s]) => [
    [k, s.evaluationType, "recommendationCompliancePercent", s.summary.recommendationCompliance.ratePercent], [k, s.evaluationType, "workflowCompletionPercentOfAttempted", s.summary.workflowCompletion.ratePercentOfAttempted],
    [k, s.evaluationType, "investigationTimeAvgSec", s.summary.investigationTime.average], [k, s.evaluationType, "investigationTimeMedianSec", s.summary.investigationTime.median], [k, s.evaluationType, "investigationTimeSdSec", s.summary.investigationTime.stdDev],
    [k, s.evaluationType, "timeToDecisionAvgSec", s.summary.timeToDecision.average], [k, s.evaluationType, "timeToDecisionMedianSec", s.summary.timeToDecision.median], [k, s.evaluationType, "timeToDecisionSdSec", s.summary.timeToDecision.stdDev],
    [k, s.evaluationType, "interventionRatePercent", s.summary.interventionRate.ratePercentOfAttempted], [k, s.evaluationType, "retryCaseRatePercent", s.summary.retry.caseLevelRatePercent], [k, s.evaluationType, "totalRetryCount", s.summary.retry.totalRetryCount],
    [k, s.evaluationType, "verificationResolved", s.summary.verification.resolved], [k, s.evaluationType, "verificationNotResolved", s.summary.verification.notResolved]])));
  w("case-results.json", all);
  w("case-results.csv", csv(["run", "evaluationType", "TC", "attack", "severity", "environmentStatus", "telemetry", "compliance", "investigationSec", "decisionSec", "timingMode", "retries", "interventionTypes", "verificationMode", "verificationResult", "workflowCompleted", "finalStatus", "playbook", "observations"],
    all.map((r) => [r.run, r.evaluationType, r.caseId, r.attack, r.severity, r.environmentStatus, r.telemetry, r.compliance, r.investigationSeconds, r.decisionSeconds, r.timingMode, r.retries, [...new Set(r.interventions.map((i) => i.type))].join(";"), r.verificationMode, r.verificationResult, r.workflowCompleted, r.finalStatus, r.playbook, r.observations.join(" || ")])));
  w("compliance-results.json", Object.fromEntries(Object.entries(sections).map(([k, s]) => [k, { evaluationType: s.evaluationType, summary: s.summary.recommendationCompliance, cases: s.rows.map((r) => ({ caseId: r.caseId, compliance: r.compliance, checks: r.checks, failedChecks: r.failedChecks, playbook: r.playbook })) }])));
  w("timing-results.json", { note: "Investigation Time = T_recommendation − T_investigation_start; Time-to-Decision = T_decision − T_recommendation (PostgreSQL timestamps). REAL runs are uninterrupted scripted passes: Time-to-Decision is the latency of a scripted IR decision, NOT human deliberation. The MOCK stepwise run contains manual gaps (hours between steps) — use mockRepeatedSinglePass for its clean latency.",
    runs: Object.fromEntries(Object.entries(sections).map(([k, s]) => [k, { evaluationType: s.evaluationType, investigationTime: s.summary.investigationTime, timeToDecision: s.summary.timeToDecision, timingMode: [...new Set(s.rows.map((r) => r.timingMode))], cases: s.rows.map((r) => ({ caseId: r.caseId, investigationSeconds: r.investigationSeconds, decisionSeconds: r.decisionSeconds })) }])), mockRepeatedSinglePass: mock.repeated });
  w("intervention-results.json", Object.fromEntries(Object.entries(sections).map(([k, s]) => [k, { evaluationType: s.evaluationType, summary: s.summary.interventionRate, retry: s.summary.retry, cases: s.rows.map((r) => ({ caseId: r.caseId, interventions: r.interventions, retries: r.retries, observations: r.observations })) }])));
  w("verification-results.json", Object.fromEntries(Object.entries(sections).map(([k, s]) => [k, { evaluationType: s.evaluationType, verificationModeStatement: s.evaluationType === "MOCK" ? "Verification Mode = MOCK. NO_MATCH is simulated (CleanRehuntAdapter). This proves the workflow can reach Verification and close an incident on a mock re-hunt — it does NOT prove any threat was eliminated." : "Verification Mode = REAL_WAZUH: re-hunt queries the live Wazuh Indexer after the (manually simulated) response.", summary: s.summary.verification, cases: s.rows.map((r) => ({ caseId: r.caseId, mode: r.verificationMode, result: r.verificationResult, finalIncidentStatus: r.finalStatus, detail: r.verification })) }])));

  const md: string[] = [`# VIGIX evaluation summary`, ``, `Generated ${new Date().toISOString()}. **MOCK and REAL_WAZUH results are reported separately and must not be combined.**`, ``];
  for (const [k, s] of Object.entries(sections)) {
    md.push(`## ${k} — ${s.evaluationType}${s.evaluationType === "MOCK" ? " (verification MOCK: NO_MATCH is simulated)" : ""}`, ``, `Source: \`${s.source}\`${s.startedAt ? ` · started ${s.startedAt}` : ""}`, ``, finalTable(s.rows), ``, summaryBlock(s.summary, s.evaluationType === "MOCK" ? "MOCK" : "REAL_WAZUH"), ``);
    const obsAll = s.rows.filter((r) => r.observations.length);
    if (obsAll.length) md.push(`### Observations / findings (${k})`, ``, ...obsAll.map((r) => `- **${r.caseId}**: ${r.observations.join(" · ")}`), ``);
  }
  if (mock.repeated) md.push(`## mock-repeated-single-pass — MOCK (N=${mock.repeated.runs})`, ``, `Clean uninterrupted latencies for the MOCK pipeline (fresh alerts each run, no manual gap). Overall: compliance ${mock.repeated.overall.overallCompliancePassRatePct}%, investigation ${mock.repeated.overall.investigationTimeMean}s ± ${mock.repeated.overall.investigationTimeSd}, decision ${mock.repeated.overall.decisionTimeMean}s ± ${mock.repeated.overall.decisionTimeSd}. Verification not exercised in this harness.`, ``);
  const extra = path.join(RES, "findings-and-limitations.md");
  if (fs.existsSync(extra)) md.push(fs.readFileSync(extra, "utf8"));
  w("evaluation-summary.md", md.join("\n"));
  console.log("wrote results/{evaluation,case-results,compliance-results,timing-results,intervention-results,verification-results}.json/.csv + evaluation-summary.md");
  for (const [k, s] of Object.entries(sections)) console.log(`\n## ${k}\n${finalTable(s.rows)}\n${summaryBlock(s.summary, s.evaluationType)}`);
})();
