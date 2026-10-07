/**
 * run-low-fp.ts — EXTENDED evaluation, part A: LOW severity and False Positive handling, on the REAL Wazuh stack.
 *
 * For each case of groundTruthExtended.ts: a benign lab action -> the REAL Wazuh alert from the Wazuh Indexer ->
 * ingestion exactly as the webhook path does it (WazuhAdapter.normalize -> IngestAlertFromSiem) -> the SOC / IR step the
 * workflow requires (scripted stand-ins for the humans) -> database checks. Nothing is graded on AI "false positive
 * detection": VIGIX has none. What is checked is that benign alerts never reach an executed response and that the human
 * gates (SOC triage, IR reject) work.
 *
 * Usage (repo root, Git-Bash):  EVAL_DB=soar_ext_eval . apps/backend/scripts/eval/eval-env.sh
 *   npx ts-node --transpile-only scripts/eval/extended/run-low-fp.ts --label ext-low-fp-20261001 [--cases LOW-01,FP-03]
 * Guards: DATABASE_URL must end in `_eval` and not be soar_eval; REHUNT_PROVIDER must be wazuh.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { buildEvalContext, TENANT, SOC, IR } from "../wiring";
import { docker, ENDPOINT, ATTACKER, ENDPOINT_AGENT, prepareLab } from "../simulations";
import { waitForAlert } from "../indexerClient";
import { EXTENDED_GROUND_TRUTH, ExtCase } from "./groundTruthExtended";
import { PrismaIncidentRepository } from "../../../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { AuditLogger } from "../../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { UpdateIncidentStatusUseCase } from "../../../src/application/incident/use-cases/UpdateIncidentStatus.usecase";

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i > -1 ? process.argv[i + 1] : d; };
const LABEL = arg("label", `ext-low-fp-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 13)}`)!;
const ONLY = arg("cases")?.split(",").map((s) => s.trim());
const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
const OUT = path.join(ROOT, "results", "extended-evaluation", "runs");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const secs = (a: Date, b: Date) => Math.round((b.getTime() - a.getTime()) / 10) / 100;
const sh = (c: string, s: string, t = 120000) => docker(["exec", c, "sh", "-c", s], undefined, t);
const sshTry = (u: string, p: string, cmd = "exit") => `sshpass -p '${p}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4 -o PreferredAuthentications=password -o PubkeyAuthentication=no ${u}@${ENDPOINT} ${cmd} >/dev/null 2>&1 || true`;
const web = (q: string, ua = "curl/8") => `curl -s -o /dev/null -A '${ua}' 'http://${ENDPOINT}${q}'`;

interface Check { id: string; check: string; expected: string; actual: string; pass: boolean }

function simulate(id: string): { startedAt: string; endedAt: string; telemetry: string } {
  const startedAt = new Date();
  let telemetry = "REAL_EVENTS_STOCK_RULE";
  switch (id) {
    case "LOW-01": sh(ATTACKER, sshTry("victim", "VictimPass123!", "id")); break;
    case "LOW-02": sh(ATTACKER, sshTry("victim", "definitely-wrong")); break;
    case "LOW-03": sh(ATTACKER, web("/does-not-exist.html")); break;
    case "LOW-04": sh(ATTACKER, web("/app/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E")); break;
    case "FP-01": sh(ATTACKER, web("/app/search.php?id=1%20union%20select%20username,password%20from%20users", "Mozilla/5.0 (compatible; Nessus)")); break;
    case "FP-02": sh(ATTACKER, Array.from({ length: 25 }, (_, i) => web(`/missing-${i}.php`, "SiteCrawler/2.1")).join("; ")); break;
    case "FP-03":
      telemetry = "REAL_ACTION_CUSTOM_RULE";
      sh(ENDPOINT, "userdel -r opsadmin 2>/dev/null; useradd -m -s /bin/bash opsadmin; sleep 2; usermod -aG sudo opsadmin; sleep 1");
      break;
    default: throw new Error(`unknown case ${id}`);
  }
  return { startedAt: startedAt.toISOString(), endedAt: new Date().toISOString(), telemetry };
}
const cleanup = (id: string) => { if (id === "FP-03") { try { sh(ENDPOINT, "userdel -r opsadmin 2>/dev/null; true"); } catch { /* best effort */ } } };

async function counts(prisma: PrismaClient) {
  const q = async (t: string) => Number((await prisma.$queryRawUnsafe<{ c: bigint }[]>(`select count(*) c from ${t}`))[0].c);
  return { incidents: await q("incidents"), investigations: await q("investigations"), agent_executions: await q("agent_executions"), recommendations: await q("recommendations"), response_plans: await q("response_plans"), approvals: await q("approvals"), step_executions: await q("step_executions") };
}
const delta = (a: Record<string, number>, b: Record<string, number>) => Object.fromEntries(Object.keys(a).map((k) => [k, b[k] - a[k]]));

async function llmUp(): Promise<boolean> {
  try { return (await fetch(`${process.env.AI_ORCHESTRATOR_URL}/health`)).ok; } catch { return false; }
}

async function runCase(prisma: PrismaClient, ctx: ReturnType<typeof buildEvalContext>, gt: ExtCase) {
  console.log(`\n=== ${gt.id} [${gt.kind}] ${gt.title} ===`);
  const checks: Check[] = [];
  const chk = (id: string, check: string, expected: string, actual: string, pass: boolean) => { checks.push({ id, check, expected, actual, pass }); console.log(`   ${pass ? "PASS" : "FAIL"} ${id} ${check}: expected ${expected}; actual ${actual}`); };
  const observations: string[] = [];
  const rec: Record<string, any> = { caseId: gt.id, kind: gt.kind, title: gt.title, benignReason: gt.benignReason, trigger: gt.trigger, groundTruth: gt, checks, observations, environmentStatus: "AVAILABLE" };

  const sim = simulate(gt.id);
  rec.simulation = sim;
  const found = await waitForAlert(ENDPOINT_AGENT, gt.expected.ruleId, new Date(new Date(sim.startedAt).getTime() - 2000).toISOString());
  cleanup(gt.id);
  if (!found) { observations.push(`WAZUH_ALERT_MISSING: rule ${gt.expected.ruleId} not seen within 150 s`); rec.result = "FAIL"; return rec; }
  const raw = { ...found.source } as Record<string, any>;
  rec.wazuh = { indexerDocId: found.docId, alertId: raw.id, ruleId: raw.rule?.id, level: raw.rule?.level, description: raw.rule?.description, mitre: raw.rule?.mitre?.id ?? [], srcip: raw.data?.srcip ?? null, timestamp: raw.timestamp };
  chk("A1", "the REAL Wazuh alert has the calibrated rule and level", `rule ${gt.expected.ruleId} level ${gt.expected.level}`, `rule ${raw.rule?.id} level ${raw.rule?.level}`, String(raw.rule?.id) === gt.expected.ruleId && Number(raw.rule?.level) === gt.expected.level);

  const before = await counts(prisma);
  const tIngest = new Date();
  const ing = await ctx.ingest.execute({ ...ctx.wazuh.normalize(raw), tenantId: TENANT });
  if (ing.isFailure) { observations.push(`INGEST_FAILED ${JSON.stringify(ing.error)}`); rec.result = "FAIL"; return rec; }
  const alert = ing.value.alert;
  rec.alertId = alert.id;
  chk("A2", "severity is the deterministic Wazuh-level mapping (never AI)", gt.expected.severity, alert.severity, alert.severity === gt.expected.severity);
  const auditOf = async (entityId: string) => (await prisma.auditLog.findMany({ where: { entityId }, orderBy: { createdAt: "asc" }, select: { action: true, actor: true, metadata: true } }));
  let incidentId: string | null = ing.value.incidentId ?? null;
  const audits = (await auditOf(alert.id)).map((a) => a.action);

  if (gt.kind === "LOW") {
    chk("L1", "audit ALERT_OUTSIDE_SOC_WORKFLOW recorded", "present", audits.includes("ALERT_OUTSIDE_SOC_WORKFLOW") ? "present" : `absent (${audits.join(",")})`, audits.includes("ALERT_OUTSIDE_SOC_WORKFLOW"));
    chk("L2", "no incident opened", "null", String(incidentId), incidentId === null);
    chk("L3", "no triage required (not in the SOC workflow)", "triageRequired=false", `triageRequired=${ing.value.triageRequired}`, ing.value.triageRequired === false);
    const t = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: alert.id, actor: SOC, decision: "CREATE_INCIDENT", reason: "attempt to escalate a LOW alert" } as never);
    chk("L4", "SOC cannot escalate a LOW alert", "refused NOT_IN_SOC_WORKFLOW", t.isFailure ? String((t as any).error) : "accepted", t.isFailure && String((t as any).error) === "NOT_IN_SOC_WORKFLOW");
    const t2 = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: alert.id, actor: SOC, decision: "FALSE_POSITIVE", reason: "attempt to close a LOW alert" } as never);
    chk("L5", "a LOW alert is not part of triage at all", "refused NOT_IN_SOC_WORKFLOW", t2.isFailure ? String((t2 as any).error) : "accepted", t2.isFailure && String((t2 as any).error) === "NOT_IN_SOC_WORKFLOW");
    await sleep(1500);
    const d = delta(before, await counts(prisma));
    chk("L6", "no incident / investigation / AI execution / recommendation / ticket / approval was created", "all deltas 0", JSON.stringify(d), Object.values(d).every((v) => v === 0));
    rec.dbDelta = d;
  } else if (gt.kind === "FP_MEDIUM") {
    chk("M1", "audit ALERT_ROUTED_TO_TRIAGE recorded (medium waits for SOC)", "present", audits.includes("ALERT_ROUTED_TO_TRIAGE") ? "present" : `absent (${audits.join(",")})`, audits.includes("ALERT_ROUTED_TO_TRIAGE"));
    chk("M2", "NO automatic incident for a MEDIUM alert", "null", String(incidentId), incidentId === null);
    chk("M3", "triage is required", "triageRequired=true", `triageRequired=${ing.value.triageRequired}`, ing.value.triageRequired === true);
    const tTriage = new Date();
    const t = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: alert.id, actor: SOC, decision: "FALSE_POSITIVE", reason: `${gt.benignReason} — false positive` } as never);
    rec.timeToTriageSeconds = secs(tIngest, new Date());
    chk("M4", "SOC closes the alert as FALSE_POSITIVE", "accepted, no incident", t.isFailure ? String((t as any).error) : `accepted, incident=${(t as any).value?.incidentId ?? null}`, t.isSuccess && !(t as any).value?.incidentId);
    const row = await prisma.alert.findUnique({ where: { id: alert.id } });
    chk("M5", "alert stored as TRIAGED / FALSE_POSITIVE with closed_at, actor and reason", "TRIAGED, FALSE_POSITIVE, closed_at set", `${row?.workflowState}, ${row?.triageDisposition}, closed_at=${row?.closedAt ? "set" : "null"}, by ${row?.triagedBy}`, row?.workflowState === "TRIAGED" && row?.triageDisposition === "FALSE_POSITIVE" && !!row?.closedAt && row?.triagedBy === SOC && !!row?.triageNote);
    const a2 = (await auditOf(alert.id)).map((a) => a.action);
    chk("M6", "audit ALERT_TRIAGED recorded", "present", a2.includes("ALERT_TRIAGED") ? "present" : `absent (${a2.join(",")})`, a2.includes("ALERT_TRIAGED"));
    const again = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: alert.id, actor: "eval-soc-2", decision: "CREATE_INCIDENT", reason: "second analyst tries to reopen" } as never);
    chk("M7", "a closed alert cannot be decided twice", "refused ALERT_ALREADY_DECIDED", again.isFailure ? String((again as any).error) : "accepted", again.isFailure && String((again as any).error) === "ALERT_ALREADY_DECIDED");
    await sleep(1500);
    const d = delta(before, await counts(prisma));
    chk("M8", "no incident / investigation / AI execution / recommendation / ticket / approval was created", "all deltas 0", JSON.stringify(d), Object.values(d).every((v) => v === 0));
    rec.dbDelta = d;
  } else {
    // FP_HIGH: automatic incident -> AI -> recommendation -> IR reject -> human dismisses
    incidentId = incidentId ?? null;
    chk("H1", "CRITICAL alert opens an incident AUTOMATICALLY", "incident opened (trigger AUTOMATIC)", `incident=${incidentId}`, !!incidentId && audits.includes("ALERT_ESCALATED_TO_INCIDENT"));
    if (!incidentId) { rec.result = "FAIL"; return rec; }
    rec.incidentId = incidentId;
    const fp = await ctx.alertWorkflow().triage.execute({ tenantId: TENANT, alertId: alert.id, actor: SOC, decision: "FALSE_POSITIVE", reason: "approved change — attempt to close from the inbox" } as never);
    chk("H2", "a HIGH/CRITICAL alert cannot be closed as false positive from the inbox", "refused (ALERT_IN_INCIDENT / CLOSE_NOT_ALLOWED)", fp.isFailure ? String((fp as any).error) : "accepted", fp.isFailure && ["ALERT_IN_INCIDENT", "CLOSE_NOT_ALLOWED"].includes(String((fp as any).error)));
    // AI analysis + recommendation (cost of the false positive; the AI is NOT graded on recognising it)
    const tAi = new Date();
    let analysis: any = null;
    for (let k = 0; k < 3; k++) {
      if (!(await llmUp())) { observations.push("INFRASTRUCTURE: AI orchestrator not healthy — waiting"); await sleep(20000); }
      analysis = await ctx.runAnalysis.execute({ tenantId: TENANT, incidentId, actor: SOC });
      if (!analysis.isFailure) break;
      if (!/UNAVAILABLE|TIMEOUT|timeout|ECONN|fetch failed|50[34]/i.test(JSON.stringify(analysis.error))) break;
      observations.push("INFRASTRUCTURE: AI analysis failed because the LLM endpoint was unavailable — retrying");
      await sleep(20000);
    }
    if (analysis?.isFailure) observations.push(`AI_ANALYSIS_FAILED ${JSON.stringify(analysis.error).slice(0, 200)}`);
    let attempts = 0, infra = 0;
    const usable = async () => (await prisma.recommendation.findMany({ where: { incidentId: incidentId!, status: "VALIDATED" }, include: { steps: true } })).some((r) => r.steps.some((s) => s.actionId));
    while (attempts < 5 && !(await usable()) && infra <= 8) {
      const res = await ctx.generate.execute({ incidentId, tenantId: TENANT });
      if (res.isFailure && String(res.error) === "AI_UNAVAILABLE") { infra++; observations.push("INFRASTRUCTURE: AI_UNAVAILABLE during recommendation generation (not counted as a model attempt)"); await sleep(20000); continue; }
      attempts++;
    }
    rec.aiSeconds = secs(tAi, new Date()); rec.modelAttempts = attempts; rec.infrastructureRetries = infra;
    const r = await prisma.recommendation.findFirst({ where: { incidentId, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: { include: { action: true } }, snapshot: true } });
    const aiRow = await prisma.agentResult.findFirst({ where: { agentName: "llm_analyst", agentExecution: { incidentId } }, orderBy: { createdAt: "desc" } }).catch(() => null);
    const text = JSON.stringify(aiRow?.output ?? {}).toLowerCase();
    rec.aiMentionsBenignContext = /authori[sz]ed|approved change|legitimate|benign|change window|maintenance/.test(text); // keyword observation only, NOT a metric
    rec.recommendation = r ? { playbook: r.snapshot?.playbookCode, steps: r.steps.map((s) => ({ action: s.action?.code, target: s.target })) } : null;
    chk("H3", "the system produced a recommendation for the benign event (cost of the false positive — recorded, not graded)", "recorded", r ? `${r.snapshot?.playbookCode}: ${r.steps.map((s) => `${s.action?.code}→${s.target}`).join(", ")}` : "none", true);
    if (!r) { observations.push("NO_VALID_RECOMMENDATION — nothing for IR to reject; the benign incident still needs a human dismissal"); }
    let planId: string | null = null;
    if (r) {
      const step = r.steps.find((s) => s.actionId)!;
      const plan = await ctx.createPlan.execute({ recommendationId: r.id, stepId: step.id, tenantId: TENANT });
      if (plan.isFailure) observations.push(`RESPONSE_PLAN_FAILED ${JSON.stringify(plan.error)}`);
      else {
        planId = plan.value.id;
        const incBefore = await prisma.incident.findUnique({ where: { id: incidentId } });
        const recBefore = await prisma.recommendation.count({ where: { incidentId } });
        const a = (await ctx.approvals.findByResponse(planId, TENANT)).find((x) => x.status === "pending");
        const tRej = new Date();
        const rej = a ? await ctx.decide.execute({ approvalId: a.id, tenantId: TENANT, status: "rejected", decidedBy: IR, decidedByRole: "IR_TEAM", comment: `${gt.benignReason} — IR rejects the containment recommendation` }) : null;
        const p = await ctx.plans.findById(planId, TENANT);
        chk("H4", "IR_TEAM rejects the recommendation for the benign event", "ticket PENDING_MANUAL_DECISION", `${rej ? (rej.isFailure ? String(rej.error) : "OK") : "no pending approval"}; ${p?.status}`, !!rej && rej.isSuccess && p?.status === "PENDING_MANUAL_DECISION");
        const st = await ctx.start.execute({ responseId: planId, tenantId: TENANT, startedBy: IR });
        chk("H5", "the rejected response cannot be started", "blocked", st.isFailure ? String(st.error) : "started", st.isFailure);
        const ex = await prisma.stepExecution.count({ where: { planId } });
        chk("H6", "nothing executed", "0 step executions", String(ex), ex === 0);
        await sleep(5000);
        const regen = await prisma.auditLog.count({ where: { action: { in: ["RECOMMENDATION_GENERATED", "RECOMMENDATION_GENERATION_FAILED"] }, createdAt: { gt: tRej } } });
        const recAfter = await prisma.recommendation.count({ where: { incidentId } });
        chk("H7", "no automatic regeneration after the reject", "0 new recommendations / attempts", `${recAfter} recs (was ${recBefore}); ${regen} generation audit records`, regen === 0 && recAfter === recBefore);
        const incAfter = await prisma.incident.findUnique({ where: { id: incidentId } });
        chk("H8", "the reject does not close the incident", `status unchanged (${incBefore?.status})`, String(incAfter?.status), incAfter?.status === incBefore?.status && !["resolved", "dismissed"].includes(String(incAfter?.status)));
        rec.planId = planId; rec.planStatusAfterReject = p?.status;
      }
    }
    const upd = new UpdateIncidentStatusUseCase(new PrismaIncidentRepository(prisma), new AuditLogger(prisma));
    const res = await upd.execute({ id: incidentId, tenantId: TENANT, status: "resolved", actor: SOC });
    chk("H9", "an incident cannot be set to resolved by hand (verification only)", "refused RESOLVE_REQUIRES_VERIFICATION", res.isFailure ? String(res.error) : "accepted", res.isFailure && String(res.error) === "RESOLVE_REQUIRES_VERIFICATION");
    const dis = await upd.execute({ id: incidentId, tenantId: TENANT, status: "dismissed", actor: IR });
    const incEnd = await prisma.incident.findUnique({ where: { id: incidentId } });
    chk("H10", "a human dismisses the benign incident (IR_TEAM, audited)", "status dismissed, audit INCIDENT_STATUS_CHANGED by the human", `${incEnd?.status}`, dis.isSuccess && incEnd?.status === "dismissed" && (await auditOf(incidentId)).some((x) => x.action === "INCIDENT_STATUS_CHANGED" && x.actor === IR));
    const execAll = Number((await prisma.$queryRawUnsafe<{ c: bigint }[]>(`select count(*) c from step_executions se join response_plans rp on rp.id = se.plan_id where rp.incident_id::text = '${incidentId}'`))[0].c);
    chk("H11", "no response was executed for the benign incident", "0 step executions", String(execAll), execAll === 0);
    const d = delta(before, await counts(prisma));
    rec.dbDelta = d;
    observations.push("After the IR reject the ticket stays PENDING_MANUAL_DECISION: the use cases expose no explicit cancel/close for it (observation).");
  }
  rec.result = checks.every((c) => c.pass) ? "PASS" : "FAIL";
  rec.checksPassed = checks.filter((c) => c.pass).length; rec.checksTotal = checks.length;
  return rec;
}

(async () => {
  const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  if (dbName !== "soar_ext_eval") throw new Error(`refusing to run: connected to '${dbName}', expected soar_ext_eval`);
  if (process.env.REHUNT_PROVIDER !== "wazuh") throw new Error("REHUNT_PROVIDER must be wazuh");
  const gtHash = createHash("sha256").update(JSON.stringify(EXTENDED_GROUND_TRUTH)).digest("hex");
  const pinFile = path.join(ROOT, "results", "extended-evaluation", "ground-truth.sha256");
  const pin = fs.existsSync(pinFile) ? JSON.parse(fs.readFileSync(pinFile, "utf8")) : {};
  if (pin.lowFp && pin.lowFp !== gtHash) throw new Error(`ground truth changed (${gtHash} != pinned ${pin.lowFp}); refusing to run`);
  if (!pin.lowFp) { fs.mkdirSync(path.dirname(pinFile), { recursive: true }); fs.writeFileSync(pinFile, JSON.stringify({ ...pin, lowFp: gtHash, pinnedAt: new Date().toISOString() }, null, 1)); }
  const prisma = new PrismaClient();
  const ctx = buildEvalContext(prisma, process.env.AI_ORCHESTRATOR_URL!);
  prepareLab();
  const startedAt = new Date().toISOString();
  const cases = EXTENDED_GROUND_TRUTH.filter((c) => !ONLY || ONLY.includes(c.id));
  const results: any[] = [];
  for (const gt of cases) {
    try { results.push(await runCase(prisma, ctx, gt)); } catch (e) { console.error(`   CASE CRASHED: ${(e as Error).message}`); results.push({ caseId: gt.id, kind: gt.kind, result: "FAIL", crashed: String((e as Error).stack ?? e).slice(0, 800), checks: [], observations: ["CRASHED"] }); }
  }
  fs.mkdirSync(OUT, { recursive: true });
  const out = { label: LABEL, startedAt, finishedAt: new Date().toISOString(), database: dbName, groundTruthSha256: gtHash, results };
  fs.writeFileSync(path.join(OUT, `${LABEL}.json`), JSON.stringify(out, null, 2));
  console.log(`\nWrote results/extended-evaluation/runs/${LABEL}.json`);
  for (const r of results) console.log(` ${r.caseId} ${r.result} (${r.checksPassed ?? 0}/${r.checksTotal ?? 0})`);
  await prisma.$disconnect();
})().catch((e) => { console.error(e); process.exit(1); });
