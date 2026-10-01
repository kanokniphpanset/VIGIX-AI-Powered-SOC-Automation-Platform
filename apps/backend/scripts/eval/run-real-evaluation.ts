/**
 * run-real-evaluation.ts — REAL-WAZUH evaluation of TC-01..TC-10 against the isolated evaluation database.
 *
 *   cd apps/backend && . scripts/eval/eval-env.sh
 *   npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode clean [--cases TC-01,TC-06] [--label name]
 *   npx ts-node --transpile-only scripts/eval/run-real-evaluation.ts --mode intervention
 *
 * Per case: simulate on the endpoint -> read the REAL Wazuh alert from the indexer -> ingest -> (SOC triage) ->
 * investigation + AI analysis -> AI recommendation (bounded retries) -> SOC hands to IR -> IR decision ->
 * manual response simulation -> REAL Wazuh re-hunt -> verification -> deterministic scoring from PostgreSQL.
 *
 * Principles: no LLM judge (scoring = src/evaluation/EvaluationService.ts); ground truth is FROZEN before the run
 * (src/evaluation/groundTruthReal.ts) and hashed into the output; --mode clean applies NO correction of any kind;
 * --mode intervention applies analyst corrections and records each one. Nothing here approves or executes a
 * response on behalf of the AI: the scripted SOC/IR steps stand in for humans and are labelled as such.
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { REAL_GROUND_TRUTH, RealTcGroundTruth, resolveGroundTruth } from "../../src/evaluation/groundTruthReal";
import { collectEvaluationCase, knownActionCodes, verificationModeOf } from "../../src/evaluation/EvaluationService";
import { EvaluationCase } from "../../src/evaluation/types";
import { probeWazuhManagerApi, wazuhManagerConfigFromEnv } from "../../src/infrastructure/external-services/siem/WazuhManagerHealth";
import { ManualDecisionUseCase } from "../../src/application/approval/use-cases/ManualDecision.usecase";
import { AuditLogger } from "../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { buildEvalContext, TENANT, SOC, IR } from "./wiring";
import { waitForAlert } from "./indexerClient";
import { environmentFacts, prepareLab, simulate, cleanupCase, docker, dockerAll, ENDPOINT_AGENT, SimResult } from "./simulations";

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const MODE = (arg("mode", "clean") as "clean" | "intervention");
const DECISION = (arg("decision", "approve") as "approve" | "reject"); // reject: IR rejects, then Manual Decision -> Manual Response -> Re-hunt (FINAL evaluation)
const RECURRENCE = process.argv.includes("--recurrence"); // verification sensitivity control: the attack REPEATS after the response completes
const ONLY = arg("cases")?.split(",").map((s) => s.trim());
const ROOT = path.resolve(__dirname, "..", "..", "..", "..");
const RUN_LABEL = arg("label", `${MODE}-real-wazuh-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 13)}`)!;
const OUT_DIR = path.join(ROOT, "results", "runs", RUN_LABEL);
const MAX_RECOMMENDATION_ATTEMPTS = 5;
const MANAGER = process.env.WAZUH_MANAGER_CONTAINER ?? "single-node-wazuh.manager-1";
const MITRE_IOC_TYPE: Record<string, string> = { ip: "IPV4", domain: "DOMAIN", url: "URL", hash: "SHA256", user: "USERNAME", email: "EMAIL", process: "PROCESS_NAME", command: "COMMAND_LINE", file: "FILE_PATH" };

interface Intervention { type: "ANALYST_IOC_CORRECTION" | "KNOWLEDGE_BASE_UPDATE" | "MITRE_CATALOG_UPDATE" | "PLAYBOOK_SEED_UPDATE" | "ACTION_TARGET_CORRECTION" | "ENVIRONMENT_CORRECTION"; detail: string }
interface Check { name: string; ok: boolean; detail: string }

const iso = (d: Date | null | undefined) => (d ? d.toISOString() : null);
const secs = (a: Date | null | undefined, b: Date | null | undefined) => (a && b ? Math.round(((b.getTime() - a.getTime()) / 1000) * 100) / 100 : null);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));


// ------------------------------------------------------------------ infrastructure awareness (FINAL evaluation)
// An unreachable LLM endpoint (timeout / connection error) is an INFRASTRUCTURE failure. It is recorded separately,
// waited out, and NEVER counted as a model attempt, a retry caused by the model, or an inconsistency.
const LLM_WAIT_MS = Number(process.env.LLM_WAIT_MS ?? 15 * 60 * 1000);
const infraEvents: { case: string; stage: string; at: string; detail: string; waitedSeconds: number | null; recovered: boolean | null }[] = [];
function llmBaseUrl(): string | null {
  try { return [...fs.readFileSync(path.join(ROOT, "apps", "ai-orchestrator", ".env"), "utf8").matchAll(/^LLM_BASE_URL=(.*)$/gm)].map((x) => x[1].replace(/"/g, "").trim()).pop() ?? null; } catch { return null; }
}
async function llmHealthy(): Promise<boolean> {
  const b = llmBaseUrl(); if (!b) return true;
  try { return (await fetch(`${b.replace(/\/$/, "")}/models`, { signal: AbortSignal.timeout(8000) })).ok; } catch { return false; }
}
async function waitForLlm(caseId: string, stage: string): Promise<boolean> {
  if (await llmHealthy()) return true;
  const t0 = Date.now();
  console.log(`   ! INFRASTRUCTURE: LLM endpoint unreachable before ${stage} — waiting for recovery (not a model failure)`);
  while (Date.now() - t0 < LLM_WAIT_MS) {
    await sleep(15000);
    if (await llmHealthy()) { infraEvents.push({ case: caseId, stage, at: new Date().toISOString(), detail: "LLM endpoint unreachable, recovered", waitedSeconds: Math.round((Date.now() - t0) / 1000), recovered: true }); return true; }
  }
  infraEvents.push({ case: caseId, stage, at: new Date().toISOString(), detail: "LLM endpoint did not recover within the wait limit", waitedSeconds: Math.round((Date.now() - t0) / 1000), recovered: false });
  return false;
}

// ------------------------------------------------------------------ preflight
async function preflight(prisma: PrismaClient, ctx: ReturnType<typeof buildEvalContext>, gts: RealTcGroundTruth[]): Promise<{ checks: Check[]; env: Record<string, unknown>; kbGaps: string[] }> {
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });
  const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  add("evaluation database", dbName.endsWith("_eval"), `connected to '${dbName}' (must end with _eval; soar_platform is never touched)`);
  add("REHUNT_PROVIDER", process.env.REHUNT_PROVIDER === "wazuh", `REHUNT_PROVIDER=${process.env.REHUNT_PROVIDER ?? "(unset)"} — mock would make verification MOCK`);
  add("recommendation agent", process.env.RECOMMENDATION_AGENT === "llm", `RECOMMENDATION_AGENT=${process.env.RECOMMENDATION_AGENT ?? "(unset)"} (harness always builds LlmRecommendationAgent)`);
  let orch = "";
  try { orch = await (await fetch(`${process.env.AI_ORCHESTRATOR_URL}/health`)).text(); } catch (e) { orch = String((e as Error).message); }
  add("AI orchestrator (eval instance)", /"status":"ok"/.test(orch), `${process.env.AI_ORCHESTRATOR_URL} -> ${orch.slice(0, 80)}`);
  const idx = await ctx.rehuntProvider.health();
  add("Wazuh Indexer + re-hunt provider", idx.reachable, `WazuhRehuntAdapter health: reachable=${idx.reachable} cluster=${idx.clusterStatus} indices=${idx.alertIndices} pattern=${idx.indexPattern}${idx.error ? " error=" + idx.error : ""}`);
  const api = await probeWazuhManagerApi(wazuhManagerConfigFromEnv(process.env));
  add("Wazuh manager API", api.status === "UP", `${api.status}: ${api.detail}`);
  let agents = "", version = "";
  try { agents = docker(["exec", MANAGER, "/var/ossec/bin/agent_control", "-l"]); version = docker(["exec", MANAGER, "/var/ossec/bin/wazuh-control", "info"]).replace(/\r?\n/g, " "); } catch (e) { agents = String((e as Error).message); }
  add("Wazuh agent attack-endpoint", new RegExp(`Name: ${ENDPOINT_AGENT}, IP: any, Active`).test(agents), (agents.match(new RegExp(`.*Name: ${ENDPOINT_AGENT}.*`)) ?? ["not listed"])[0].trim());
  // custom rules: logtest each controlled-telemetry rule
  const lines: [string, string][] = [
    ["100310", '{"vigix":{"event_type":"phishing_url_delivered"},"srcip":"203.0.113.45"}'], ["100320", '{"vigix":{"event_type":"c2_beacon"},"srcip":"172.19.0.5"}'],
    ["100330", '{"vigix":{"event_type":"suspicious_process"},"process":"/tmp/x"}'], ["100340", '{"vigix":{"event_type":"data_exfiltration"},"srcip":"172.19.0.5"}'],
    ["100350", "Sep 30 10:48:10 host usermod[8419]: add 'evaluser' to group 'sudo'"],
  ];
  for (const [rule, line] of lines) {
    let out = "";
    out = dockerAll(["exec", "-i", MANAGER, "/var/ossec/bin/wazuh-logtest"], line + "\n");
    add(`custom rule ${rule} loaded`, new RegExp(`id: '${rule}'`).test(out), "wazuh-logtest on the manager");
  }
  // KB completeness — gaps are recorded as findings BEFORE the run, never silently fixed
  const kbGaps: string[] = [];
  const pbs = new Set((await prisma.playbook.findMany({ select: { code: true } })).map((p) => p.code));
  const mitre = new Set((await prisma.$queryRawUnsafe<{ technique_id: string }[]>("select technique_id from mitre_techniques")).map((r) => r.technique_id));
  const actions = await knownActionCodes(prisma);
  for (const g of gts.filter((x) => x.mode !== "ENVIRONMENT_UNAVAILABLE")) {
    if (!pbs.has(g.expectedPlaybook)) kbGaps.push(`${g.caseId}: playbook ${g.expectedPlaybook} missing from Knowledge Base`);
    for (const t of g.expectedMitre) if (!mitre.has(t)) kbGaps.push(`${g.caseId}: MITRE technique ${t} missing from catalog`);
    for (const a of g.allowedActions) if (!actions.has(a)) kbGaps.push(`${g.caseId}: action ${a} missing/disabled`);
  }
  add("Knowledge Base complete for ground truth", kbGaps.length === 0, kbGaps.length ? kbGaps.join("; ") : `${pbs.size} playbooks, ${mitre.size} MITRE techniques, ${actions.size} actions; all ground-truth references present`);
  // LLM (non-secret settings only)
  const aiEnv = fs.readFileSync(path.join(ROOT, "apps", "ai-orchestrator", ".env"), "utf8");
  const last = (k: string) => [...aiEnv.matchAll(new RegExp(`^${k}=(.*)$`, "gm"))].map((m) => m[1].replace(/"/g, "").trim()).pop() ?? "";
  const provider = last("LLM_PROVIDER");
  const llm = provider === "openrouter" ? { provider, model: last("OPENROUTER_MODEL"), note: "LLM_PROVIDER is defined twice in apps/ai-orchestrator/.env (openai-compatible, then openrouter); the last value is assumed to win" } : { provider, model: last("LLM_MODEL"), note: "" };
  return { checks, kbGaps, env: { wazuhVersion: version, wazuhAgent: agents.match(new RegExp(`.*Name: ${ENDPOINT_AGENT}.*`))?.[0]?.trim() ?? null, wazuhManagerApi: api, indexer: idx, aiOrchestrator: process.env.AI_ORCHESTRATOR_URL, llm, database: dbName, verificationModeConfigured: "REAL_WAZUH (REHUNT_PROVIDER=wazuh)", recommendationAgent: process.env.RECOMMENDATION_AGENT, node: process.version } };
}

// ------------------------------------------------------------------ analyst corrections (intervention mode only)
async function analystIocCorrection(prisma: PrismaClient, ctx: ReturnType<typeof buildEvalContext>, incidentId: string, gt: RealTcGroundTruth, rawAlert: unknown): Promise<Intervention[]> {
  const out: Intervention[] = [];
  const inv = await prisma.investigation.findFirst({ where: { incidentId, investigationNumber: 1 } });
  if (!inv) return out;
  const haystack = JSON.stringify(rawAlert);
  const existing = await prisma.threatIntelIoc.findMany({ where: { incidentId }, select: { iocValue: true, iocType: true, createdBy: true } });
  for (const e of gt.expectedIocs) {
    const type = MITRE_IOC_TYPE[e.type];
    if (!type || !haystack.includes(e.value)) continue; // only values the alert itself evidences
    const have = existing.find((x) => x.iocValue.toLowerCase() === e.value.toLowerCase());
    const manual = have && have.createdBy && have.createdBy !== "system";
    if (manual) continue;
    if (have) {
      await prisma.threatIntelIoc.updateMany({ where: { incidentId, iocValue: have.iocValue }, data: { createdBy: SOC } });
      out.push({ type: "ANALYST_IOC_CORRECTION", detail: `promoted existing ${have.iocType} IOC ${e.value} to analyst-confirmed/actionable` });
    } else {
      const r = await ctx.createIoc.execute({ tenantId: TENANT, investigationId: inv.id, createdBy: SOC, body: { iocType: type, iocValue: e.value, source: "analyst enrichment (from alert evidence)" } as never });
      out.push({ type: "ANALYST_IOC_CORRECTION", detail: `added ${type} IOC ${e.value} evidenced in the alert${(r as any).isFailure ? " (FAILED: " + JSON.stringify((r as any).error) + ")" : ""}` });
    }
  }
  return out;
}

// ------------------------------------------------------------------ one case
interface CaseOutcome extends EvaluationCase {
  mode: string; telemetry: string; simulation: SimResult | null; wazuh: Record<string, unknown> | null; groundTruth: unknown;
  interventions: Intervention[]; observations: string[]; timeline: Record<string, string | number | null>; iocRecall: { expected: number; found: number; missing: string[] } | null;
  actionMatch: { expectedActions: string[]; actualActions: string[]; expectedActionHit: boolean; expectedTargetHit: boolean; actualTargets: string[] } | null;
  verificationDetail: Record<string, unknown> | null; rehuntError: string | null; timingMode: string; environmentStatus: string;
}

async function runCase(prisma: PrismaClient, ctx: ReturnType<typeof buildEvalContext>, gt0: RealTcGroundTruth, facts: Record<string, string>, known: Set<string>): Promise<CaseOutcome> {
  const gt = resolveGroundTruth(gt0, facts);
  const base: CaseOutcome = {
    ...(await collectEvaluationCase(prisma, { ...gt, knownFindings: [] }, known, "00000000-0000-0000-0000-000000000000")),
    mode: gt.mode, telemetry: gt.mode, simulation: null, wazuh: null, groundTruth: gt, interventions: [], observations: [], timeline: {}, iocRecall: null, actionMatch: null,
    verificationDetail: null, rehuntError: null, timingMode: "UNINTERRUPTED_SCRIPTED", environmentStatus: "AVAILABLE",
  };
  base.caseId = gt.caseId; base.attackName = gt.attackName; base.attackType = gt.attackType;
  const obs = (m: string) => { base.observations.push(m); console.log(`   ! ${m}`); };
  const ivn = (i: Intervention) => { base.interventions.push(i); console.log(`   > INTERVENTION [${i.type}] ${i.detail}`); };
  if (gt.mode === "ENVIRONMENT_UNAVAILABLE") {
    base.environmentStatus = "ENVIRONMENT_UNAVAILABLE"; base.recommendationCompliance = "NOT_EVALUATED"; base.notes = gt.environmentNote ?? "";
    obs(`ENVIRONMENT_UNAVAILABLE: ${gt.simulation}`);
    return base;
  }

  // ---- 1. simulate (real action on the endpoint)
  console.log(`\n=== ${gt.caseId} ${gt.attackName} [${gt.mode}] ===`);
  const sim = await simulate(gt.caseId, facts);
  base.simulation = sim; base.telemetry = sim.telemetry;
  console.log(`   simulated ${sim.startedAt} -> ${sim.endedAt}`);
  const since = new Date(new Date(sim.startedAt).getTime() - 2000).toISOString();

  // ---- 2. the REAL Wazuh alert
  const found = await waitForAlert(ENDPOINT_AGENT, gt.expectedWazuh.ruleId, since);
  cleanupCase(gt.caseId);
  if (!found) { obs(`WAZUH_ALERT_MISSING: no alert of rule ${gt.expectedWazuh.ruleId} from ${ENDPOINT_AGENT} within 150s of the simulation`); base.recommendationCompliance = "NOT_EVALUATED"; return base; }
  const raw = { ...found.source } as Record<string, any>;
  const r = raw.rule ?? {};
  const wazuh = { indexerDocId: found.docId, alertId: raw.id, timestamp: raw.timestamp, ruleId: r.id, level: r.level, description: r.description, mitre: r.mitre?.id ?? [], agent: raw.agent?.name, srcip: raw.data?.srcip ?? null, stockRule: gt.expectedWazuh.stockRule,
    ruleMatch: String(r.id) === gt.expectedWazuh.ruleId, levelMatch: Number(r.level) === gt.expectedWazuh.level, mitreMatch: gt.expectedMitre.every((t: string) => (r.mitre?.id ?? []).includes(t)),
    detectionLatencySeconds: secs(new Date(sim.startedAt), new Date(String(raw.timestamp).replace(/([+-]\d\d)(\d\d)$/, "$1:$2"))) };
  base.wazuh = wazuh;
  console.log(`   REAL Wazuh alert ${raw.id} rule ${r.id} L${r.level} mitre=${JSON.stringify(wazuh.mitre)} srcip=${wazuh.srcip}`);
  if (!wazuh.levelMatch) obs(`WAZUH_LEVEL_MISMATCH: expected ${gt.expectedWazuh.level}, got ${r.level}`);
  if (!wazuh.mitreMatch) obs(`WAZUH_MITRE_MISMATCH: expected ${gt.expectedMitre.join(",")}, alert carries ${JSON.stringify(wazuh.mitre)}`);

  // ---- 3. ingest exactly as the webhook path does (WazuhAdapter.normalize -> IngestAlertFromSiem)
  const tIngestStart = new Date();
  const norm = ctx.wazuh.normalize(raw);
  const ing = await ctx.ingest.execute({ ...norm, tenantId: TENANT });
  if (ing.isFailure) { obs(`INGEST_FAILED: ${JSON.stringify(ing.error)}`); return base; }
  let incidentId = ing.value.incidentId as string | null;
  if (ing.value.alert.severity !== gt.expectedSeverity) obs(`SEVERITY_MISMATCH: expected ${gt.expectedSeverity}, VIGIX assigned ${ing.value.alert.severity}`);
  if (!incidentId) { // MEDIUM waits for SOC review (scripted SOC analyst)
    const t = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: ing.value.alert.id, actor: SOC, decision: "CREATE_INCIDENT", reason: "evaluation: SOC review opens incident" } as never);
    incidentId = (t as any).value?.incidentId ?? null;
  }
  if (!incidentId) { obs("NO_INCIDENT: triage did not open an incident"); return base; }
  base.incidentId = incidentId;

  // ---- 4. investigation + AI analysis
  let analysis: any = null;
  for (let k = 0; k < 3; k++) {
    await waitForLlm(gt.caseId, "ai-analysis");
    analysis = await ctx.runAnalysis.execute({ tenantId: TENANT, incidentId, actor: SOC });
    if (!analysis.isFailure) break;
    const msg = JSON.stringify(analysis.error);
    if (!/UNAVAILABLE|TIMEOUT|timeout|ECONN|fetch failed|50[34]/i.test(msg)) break; // not infrastructure: do not retry
    infraEvents.push({ case: gt.caseId, stage: "ai-analysis", at: new Date().toISOString(), detail: msg.slice(0, 200), waitedSeconds: null, recovered: null });
    console.log("   ! INFRASTRUCTURE: AI analysis failed because the LLM endpoint was unavailable — retrying");
    await sleep(20000);
  }
  if (analysis?.isFailure) obs(`AI_ANALYSIS_FAILED: ${JSON.stringify(analysis.error).slice(0, 200)}`);
  const ioc0 = await prisma.threatIntelIoc.findMany({ where: { incidentId }, select: { iocType: true, iocValue: true, createdBy: true } });
  const missing = gt.expectedIocs.filter((e) => !ioc0.some((i) => e.value.toLowerCase().split("|").includes(i.iocValue.toLowerCase()))).map((e) => `${e.type}:${e.value}`);
  base.iocRecall = { expected: gt.expectedIocs.length, found: gt.expectedIocs.length - missing.length, missing };
  if (missing.length) obs(`EXPECTED_IOC_MISSING (before any correction): ${missing.join(", ")}`);

  // ---- 5. recommendation, bounded retries (failures are counted from the audit log by the collector)
  const usable = async () => (await prisma.recommendation.findMany({ where: { incidentId, status: "VALIDATED" }, include: { steps: true } })).some((rr) => rr.steps.some((s) => s.actionId));
  let attempts = 0;
  let infraRetries = 0, infraBlocked = false;
  const attempt = async (upTo: number) => {
    while (attempts < upTo && !(await usable()) && !infraBlocked) {
      await waitForLlm(gt.caseId, "recommendation-generation");
      const res = await ctx.generate.execute({ incidentId, tenantId: TENANT });
      if (res.isFailure && String(res.error) === "AI_UNAVAILABLE") { // infrastructure, not a model attempt
        infraEvents.push({ case: gt.caseId, stage: "recommendation-generation", at: new Date().toISOString(), detail: "AI_UNAVAILABLE (LLM endpoint timeout / connection error)", waitedSeconds: null, recovered: null });
        console.log("   ! INFRASTRUCTURE: AI_UNAVAILABLE during recommendation generation — not counted as a model attempt");
        if (++infraRetries > 8) { infraBlocked = true; break; }
        await sleep(20000);
        continue;
      }
      attempts++;
    }
  };
  if (MODE === "intervention") {
    // Reactive analyst: let the system try twice; only when the recommendation is blocked does the analyst correct
    // the incident's IOCs (values the alert itself evidences), then the system retries. Nothing is pre-applied.
    await attempt(2);
    if (!(await usable())) for (const i of await analystIocCorrection(prisma, ctx, incidentId, gt, raw)) ivn(i);
  }
  await attempt(MAX_RECOMMENDATION_ATTEMPTS);
  const rec = await prisma.recommendation.findFirst({ where: { incidentId, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: { include: { action: true } }, snapshot: true } });
  if (!rec || !rec.steps.some((s) => s.actionId)) {
    if (infraBlocked) obs("INFRASTRUCTURE_FAILURE: no recommendation could be generated because the LLM endpoint stayed unavailable — this is NOT a model result");
    else obs(`NO_VALID_RECOMMENDATION after ${MAX_RECOMMENDATION_ATTEMPTS} model attempts`);
    const c = await collectEvaluationCase(prisma, { ...gt, knownFindings: [] }, known, incidentId);
    return finalize(prisma, base, c, gt, sim, wazuh);
  }
  if (rec.snapshot && rec.snapshot.playbookCode !== gt.expectedPlaybook) obs(`PLAYBOOK_MISMATCH: selector chose ${rec.snapshot.playbookCode}, ground truth expects ${gt.expectedPlaybook}`);

  // ---- 6. SOC hands the step to IR, IR decides (scripted stand-ins for the humans), manual response simulation
  const step = rec.steps.find((s) => s.actionId)!;
  const plan = await ctx.createPlan.execute({ recommendationId: rec.id, stepId: step.id, tenantId: TENANT });
  if (plan.isFailure) { obs(`RESPONSE_PLAN_FAILED: ${JSON.stringify(plan.error)}`); }
  else {
    let p = plan.value;
    if (DECISION === "reject") {
      // IR REJECTS the AI recommendation -> nothing executes, incident stays open, no AI regeneration,
      // PENDING_MANUAL_DECISION -> IR writes a Manual Decision -> Manual Response -> Re-hunt -> Verification.
      const checks: { id: string; scenario: string; expected: string; actual: string; pass: boolean }[] = [];
      const chk = (id: string, scenario: string, expected: string, actual: string, pass: boolean) => { checks.push({ id, scenario, expected, actual, pass }); console.log(`   ${pass ? "PASS" : "FAIL"} ${id} ${scenario}: expected ${expected}, actual ${actual}`); };
      const manual = new ManualDecisionUseCase(ctx.approvals as any, ctx.plans as any, new AuditLogger(prisma));
      const recCountBefore = await prisma.recommendation.count({ where: { incidentId } });
      const incBefore = await prisma.incident.findUnique({ where: { id: incidentId } });
      const a = (await ctx.approvals.findByResponse(p.id, TENANT)).find((x) => x.status === "pending")!;
      const err = (r: any) => (r.isFailure ? String(r.error) : "OK");
      for (const [id, role, exp] of [["IRR-01", "SOC", "ROLE_MISMATCH"], ["IRR-02", "AI_AGENT", "ROLE_MISMATCH"], ["IRR-03", "admin", "ADMIN_NOT_APPROVER"]] as const) {
        const d = await ctx.decide.execute({ approvalId: a.id, tenantId: TENANT, status: "approved", decidedBy: role, decidedByRole: role, comment: "attempt" });
        chk(id, `approval attempted by "${role}" instead of IR_TEAM`, `denied (${exp})`, err(d), d.isFailure && String(d.error) === exp);
      }
      const tReject = new Date();
      const rej = await ctx.decide.execute({ approvalId: a.id, tenantId: TENANT, status: "rejected", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "evaluation: IR rejects the AI-recommended response" });
      p = (await ctx.plans.findById(p.id, TENANT))!;
      chk("IRR-04", "IR rejects the recommendation", "ticket PENDING_MANUAL_DECISION", `${err(rej)}; ${p.status}`, rej.isSuccess && p.status === "PENDING_MANUAL_DECISION");
      const st = await ctx.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: IR });
      chk("IRR-05", "start the response after the reject", "blocked", err(st), st.isFailure);
      const exec0 = await prisma.stepExecution.count({ where: { planId: p.id } });
      chk("IRR-06", "rejected recommendation not executed", "0 step executions", `${exec0}`, exec0 === 0);
      const incAfter = await prisma.incident.findUnique({ where: { id: incidentId } });
      chk("IRR-07", "incident not closed/resolved by the reject", `status unchanged (${incBefore?.status})`, String(incAfter?.status), incAfter?.status === incBefore?.status && !["resolved", "dismissed"].includes(String(incAfter?.status)));
      await sleep(5000);
      const regenerated = await prisma.auditLog.count({ where: { action: { in: ["RECOMMENDATION_GENERATED", "RECOMMENDATION_GENERATION_FAILED"] }, createdAt: { gt: tReject } } });
      const recCountAfter = await prisma.recommendation.count({ where: { incidentId } });
      chk("IRR-08", "no automatic AI regeneration after the reject", "0 new recommendations / generation attempts", `${recCountAfter} recommendations (was ${recCountBefore}); ${regenerated} generation audit records after the reject`, regenerated === 0 && recCountAfter === recCountBefore);
      const rh = await ctx.rehunt.execute({ incidentId, responseId: p.id, tenantId: TENANT, verifiedBy: IR });
      chk("IRR-09", "re-hunt/verification requested before any response completed", "blocked", err(rh), rh.isFailure);
      const m0 = await manual.execute({ responseId: p.id, tenantId: TENANT, decidedBy: "SOC", decidedByRole: "SOC", note: "manual plan" });
      chk("IRR-10", "manual decision by SOC", "denied (ROLE_MISMATCH)", err(m0), m0.isFailure && String(m0.error) === "ROLE_MISMATCH");
      const m1 = await manual.execute({ responseId: p.id, tenantId: TENANT, decidedBy: IR, decidedByRole: "IR_TEAM", note: null });
      chk("IRR-11", "manual decision by IR without a note", "denied (NOTE_REQUIRED)", err(m1), m1.isFailure && String(m1.error) === "NOTE_REQUIRED");
      const m2 = await manual.execute({ responseId: p.id, tenantId: TENANT, decidedBy: IR, decidedByRole: "IR_TEAM", note: "Evaluation: IR writes its own manual response for this incident." });
      p = (await ctx.plans.findById(p.id, TENANT))!;
      chk("IRR-12", "IR records the Manual Decision", "ticket READY_FOR_EXECUTION (not executed)", `${err(m2)}; ${p.status}`, m2.isSuccess && p.status === "READY_FOR_EXECUTION");
      (base as any).irReject = { checks, passed: checks.filter((c) => c.pass).length, total: checks.length, planId: p.id, note: "continues below: start -> manual response -> REAL_WAZUH re-hunt -> verification" };
    } else
    while (p.status === "PENDING_IR_DECISION") {
      const a = (await ctx.approvals.findByResponse(p.id, TENANT)).find((x) => x.status === "pending");
      if (!a) break;
      await ctx.decide.execute({ approvalId: a.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: "evaluation: scripted IR approval" });
      p = (await ctx.plans.findById(p.id, TENANT))!;
    }
    const s = await ctx.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: IR });
    if (s.isFailure) obs(`RESPONSE_START_FAILED: ${JSON.stringify(s.error)}`);
    else {
      await sleep(3000); // let the response window close strictly before the re-hunt window opens
      const c = await ctx.complete.execute({ responseId: p.id, tenantId: TENANT, completedBy: IR, executionResult: { simulated: true, manual: true, by: IR, action: step.action?.code, target: step.target } });
      if (c.isFailure) obs(`RESPONSE_COMPLETE_FAILED: ${JSON.stringify(c.error)}`);
      else {
        // ---- 7. REAL Wazuh re-hunt -> verification
        if (RECURRENCE) {
          // CONTROL (not part of the 10-case KPIs): the same attack recurs AFTER containment. A verification that
          // cannot see this would be vacuous; REAL_WAZUH must answer NOT_RESOLVED with matchingEvents > 0.
          const after = new Date().toISOString();
          const again = await simulate(gt.caseId, facts);
          const seen = await waitForAlert(ENDPOINT_AGENT, gt.expectedWazuh.ruleId, after);
          cleanupCase(gt.caseId);
          base.observations.push(`RECURRENCE_CONTROL: attack repeated ${again.startedAt} after the response completed; recurrence alert ${seen ? "seen in the indexer (" + (seen.source as any).id + ")" : "NOT seen in the indexer"}`);
          console.log(`   > RECURRENCE CONTROL: attack repeated after containment; alert in indexer: ${!!seen}`);
        }
        await sleep(15000); // indexer refresh margin so the query window is not empty for the wrong reason
        const v = await ctx.rehunt.execute({ incidentId, responseId: p.id, tenantId: TENANT, verifiedBy: IR });
        if (v.isFailure) {
          base.rehuntError = String(v.error);
          const fail = await prisma.auditLog.findFirst({ where: { entityId: p.id, action: "REHUNT_FAILED" }, orderBy: { createdAt: "desc" } });
          obs(`REHUNT_FAILED: ${v.error} ${fail ? JSON.stringify((fail.metadata as any)?.message ?? "") : ""} — no verification, incident not resolved`);
        }
      }
    }
  }
  const c = await collectEvaluationCase(prisma, { ...gt, knownFindings: [] }, known, incidentId);
  return finalize(prisma, base, c, gt, sim, wazuh, tIngestStart);
}

async function finalize(prisma: PrismaClient, base: CaseOutcome, c: EvaluationCase, gt: RealTcGroundTruth, sim: SimResult, wazuh: Record<string, unknown>, tIngestStart?: Date): Promise<CaseOutcome> {
  const out: CaseOutcome = { ...base, ...c, mode: base.mode, telemetry: sim.telemetry, simulation: sim, wazuh, groundTruth: gt, interventions: base.interventions, observations: base.observations, iocRecall: base.iocRecall, rehuntError: base.rehuntError, irReject: (base as any).irReject ?? null, timingMode: "UNINTERRUPTED_SCRIPTED", environmentStatus: "AVAILABLE" } as CaseOutcome;
  out.findings = [...c.findings, ...gt.knownFindings.map((f) => `(ground-truth note) ${f}`)];
  const iid = c.incidentId;
  if (iid) {
    const inc = await prisma.incident.findUnique({ where: { id: iid } });
    const alert = c.alertId ? await prisma.alert.findUnique({ where: { id: c.alertId } }) : null;
    const plan = c.responseTicketId ? await prisma.responsePlan.findUnique({ where: { id: c.responseTicketId } }) : null;
    const ver = c.verificationId ? await prisma.verification.findUnique({ where: { id: c.verificationId } }) : null;
    const rec = c.recommendationId ? await prisma.recommendation.findUnique({ where: { id: c.recommendationId }, include: { steps: { include: { action: true } } } }) : null;
    out.timeline = { simulationStart: sim.startedAt, wazuhAlertTimestamp: String((wazuh as any).timestamp), alertReceivedByVigix: iso(alert?.createdAt), incidentOpened: iso((inc as any)?.openedAt), investigationStart: c.investigationStartAt, recommendationCreated: c.recommendationAt, irDecision: c.decisionAt, responseCompleted: iso((plan as any)?.completedAt), verificationAt: iso((ver as any)?.verifiedAt),
      detectionLatencySeconds: (wazuh as any).detectionLatencySeconds, ingestToRecommendationSeconds: secs(tIngestStart ?? null, rec?.createdAt ?? null) };
    if (rec) {
      const steps = rec.steps.filter((s) => s.actionId);
      const actual = steps.map((s) => s.action?.code ?? "");
      const targets = steps.map((s) => s.target ?? "");
      out.actionMatch = { expectedActions: gt.expectedActions, actualActions: actual, expectedActionHit: actual.some((a) => gt.expectedActions.includes(a)), actualTargets: targets, expectedTargetHit: targets.some((t) => gt.expectedTargets.some((e) => e.toLowerCase() === t.toLowerCase())) };
      if (!out.actionMatch.expectedActionHit) out.observations.push(`ACTION_DIFFERS_FROM_PREFERRED: actual [${actual.join(",")}] vs preferred [${gt.expectedActions.join(",")}] (allowed set still governs compliance)`);
    }
    if (ver) {
      const b = (ver.beforeState ?? {}) as any, a = (ver.afterState ?? {}) as any;
      out.verificationDetail = { result: ver.result, matchingEvents: ver.matchingEvents, spreadDetected: ver.spreadDetected, iocRecurrence: ver.iocRecurrence, threatContained: ver.threatContained, affectedHosts: ver.affectedHosts, index: ver.wazuhIndex, evidenceSource: a.evidenceSource, searchedIocs: a.searchedIocs ?? b.criteria?.iocs, skippedIocs: a.skippedIocs, excludedIocs: a.excludedIocs, window: { start: iso(ver.timeRangeStart), end: iso(ver.timeRangeEnd) } };
      out.verificationMode = verificationModeOf(ver.wazuhIndex ?? "", a.evidenceSource ?? "");
    }
  }
  // the collector's interventionType mixes retries in; here intervention = corrections actually applied by the harness
  out.interventionType = [...new Set(out.interventions.map((i) => i.type))];
  out.interventionRequired = out.interventions.length > 0;
  return out;
}

// ------------------------------------------------------------------ main
(async () => {
  const prisma = new PrismaClient();
  const ctx = buildEvalContext(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001");
  const gtAll = REAL_GROUND_TRUTH.filter((g) => !ONLY || ONLY.includes(g.caseId));
  const frozen = createHash("sha256").update(JSON.stringify(REAL_GROUND_TRUTH)).digest("hex");
  const groundTruthFrozenAt = new Date().toISOString();
  console.log(`RUN ${RUN_LABEL}  mode=${MODE}  ground-truth sha256=${frozen.slice(0, 16)}…`);

  const pre = await preflight(prisma, ctx, gtAll);
  for (const c of pre.checks) console.log(`  [${c.ok ? "PASS" : "FAIL"}] ${c.name}: ${c.detail}`);
  const critical = pre.checks.filter((c) => !c.ok && !/Knowledge Base/.test(c.name));
  if (critical.length) { console.error(`\nREAL_WAZUH = NOT_AVAILABLE — preflight failed: ${critical.map((c) => c.name).join(", ")}`); fs.mkdirSync(OUT_DIR, { recursive: true }); fs.writeFileSync(path.join(OUT_DIR, "preflight-failed.json"), JSON.stringify({ RUN_LABEL, pre }, null, 2)); process.exit(3); }
  if (pre.kbGaps.length) console.log(`  ! Knowledge gaps recorded (NOT fixed in-run): ${pre.kbGaps.join("; ")}`);

  const labLog = prepareLab();
  const facts = environmentFacts();
  const known = await knownActionCodes(prisma);
  const runStart = new Date();
  const cases: CaseOutcome[] = [];
  console.log(`decision mode: ${DECISION}`);
  for (const gt of gtAll) {
    try { cases.push(await runCase(prisma, ctx, gt, facts, known)); }
    catch (e) { console.log(`   CASE CRASHED: ${String((e as Error).stack ?? e).slice(0, 500)}`); cases.push({ caseId: gt.caseId, attackName: gt.attackName, observations: [`CASE_CRASHED: ${String((e as Error).message).slice(0, 300)}`], interventions: [] } as unknown as CaseOutcome); }
    const last = cases[cases.length - 1];
    console.log(`   => ${last.caseId}: compliance=${last.recommendationCompliance} workflow=${last.workflowCompleted} verification=${last.verificationResult}(${last.verificationMode}) final=${last.finalStatus} retries=${last.invalidOutputCount}`);
  }

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, "run.json"), JSON.stringify({ runLabel: RUN_LABEL, mode: MODE, evaluationType: "REAL_WAZUH", startedAt: runStart.toISOString(), finishedAt: new Date().toISOString(), groundTruthFrozenAt, groundTruthSha256: frozen, groundTruthSource: "apps/backend/src/evaluation/groundTruthReal.ts", decisionMode: DECISION, infrastructureEvents: infraEvents, scoring: "deterministic (EvaluationService.evaluateCompliance) — no LLM judge", preflight: pre, labSetup: labLog, cases }, null, 2));
  console.log(`\nWrote ${path.join(OUT_DIR, "run.json")}`);
  await prisma.$disconnect();
})().catch((e) => { console.error("real evaluation crashed:", String(e?.stack ?? e).slice(0, 900)); process.exit(2); });
