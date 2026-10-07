/**
 * run-escalation.ts — EXTENDED evaluation, part C: the ESCALATED path (three re-hunt rounds, then escalation).
 *
 * ESC-01 reuses the TC-07 Command & Control telemetry (searchable IP / domain / URL IOCs). After EVERY completed response
 * the same beacon is repeated (the threat "comes back"), so the REAL_WAZUH re-hunt must answer NOT_RESOLVED three times:
 *   round 1 NOT_RESOLVED -> investigation #2 reopened, new AI recommendation (IR decision still required)
 *   round 2 NOT_RESOLVED -> investigation #3 reopened, new AI recommendation
 *   round 3 NOT_RESOLVED -> no new round, no new recommendation, incident 'escalated' (never closed)
 * The runner only plays the human roles (SOC hands a step to IR, IR approves, the response is "carried out" manually);
 * the outcome (NOT_RESOLVED / reopen / ESCALATED) is decided by the product code from real Wazuh evidence.
 * ESCALATED is recorded ONLY if the third round was actually reached.
 *
 * Usage: EVAL_DB=soar_ext_eval . scripts/eval/eval-env.sh && npx ts-node --transpile-only scripts/eval/extended/run-escalation.ts --label ext-esc-20261001
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { buildEvalContext, TENANT, SOC, IR } from "../wiring";
import { simulate, cleanupCase, environmentFacts, prepareLab, ENDPOINT_AGENT } from "../simulations";
import { waitForAlert } from "../indexerClient";
import { ESCALATION_GROUND_TRUTH } from "./groundTruthExtended";
import { UpdateIncidentStatusUseCase } from "../../../src/application/incident/use-cases/UpdateIncidentStatus.usecase";
import { PrismaIncidentRepository } from "../../../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { AuditLogger } from "../../../src/infrastructure/database/postgres/repositories/AuditLogger";

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i > -1 ? process.argv[i + 1] : d; };
const LABEL = arg("label", `ext-esc-${new Date().toISOString().replace(/[-:]/g, "").slice(0, 13)}`)!;
const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
const OUT = path.join(ROOT, "results", "extended-evaluation", "runs");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const CASE = "TC-07"; // telemetry of the base case

interface Check { id: string; check: string; expected: string; actual: string; pass: boolean }

async function llmUp(): Promise<boolean> { try { return (await fetch(`${process.env.AI_ORCHESTRATOR_URL}/health`)).ok; } catch { return false; } }

(async () => {
  const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  if (dbName !== "soar_ext_eval") throw new Error(`refusing to run: connected to '${dbName}', expected soar_ext_eval`);
  if (process.env.REHUNT_PROVIDER !== "wazuh") throw new Error("REHUNT_PROVIDER must be wazuh");
  const gtHash = createHash("sha256").update(JSON.stringify(ESCALATION_GROUND_TRUTH)).digest("hex");
  const pinFile = path.join(ROOT, "results", "extended-evaluation", "ground-truth.sha256");
  const pin = fs.existsSync(pinFile) ? JSON.parse(fs.readFileSync(pinFile, "utf8")) : {};
  if (pin.escalation && pin.escalation !== gtHash) throw new Error(`ground truth changed (${gtHash} != pinned ${pin.escalation}); refusing to run`);
  if (!pin.escalation) fs.writeFileSync(pinFile, JSON.stringify({ ...pin, escalation: gtHash, escalationPinnedAt: new Date().toISOString() }, null, 1));

  const prisma = new PrismaClient();
  const ctx = buildEvalContext(prisma, process.env.AI_ORCHESTRATOR_URL!);
  prepareLab();
  const facts = environmentFacts();
  const checks: Check[] = [];
  const observations: string[] = [];
  const chk = (id: string, check: string, expected: string, actual: string, pass: boolean) => { checks.push({ id, check, expected, actual, pass }); console.log(`   ${pass ? "PASS" : "FAIL"} ${id} ${check}: expected ${expected}; actual ${actual}`); };
  const startedAt = new Date().toISOString();
  const rounds: any[] = [];
  let incidentId: string | null = null;
  let fatal: string | null = null;

  const generateUntilValid = async (invNo: number, label: string) => {
    let attempts = 0, infra = 0;
    const usable = async () => (await prisma.recommendation.findMany({ where: { incidentId: incidentId!, status: "VALIDATED", investigationNumber: invNo }, include: { steps: true } })).some((r) => r.steps.some((s) => s.actionId));
    while (attempts < 5 && !(await usable()) && infra <= 8) {
      if (!(await llmUp())) { observations.push(`INFRASTRUCTURE (${label}): orchestrator not healthy — waiting`); await sleep(20000); }
      const res = await ctx.generate.execute({ incidentId: incidentId!, tenantId: TENANT });
      if (res.isFailure && String(res.error) === "AI_UNAVAILABLE") { infra++; observations.push(`INFRASTRUCTURE (${label}): AI_UNAVAILABLE — not counted as a model attempt`); await sleep(20000); continue; }
      attempts++;
    }
    return { attempts, infra, ok: await usable() };
  };

  const used = new Set<string>();
  try {
    // ---- round 0: the first attack, ingestion, AI analysis
    console.log("\n=== ESC-01 (TC-07 telemetry) ===");
    const sim1 = await simulate(CASE, facts);
    const found = await waitForAlert(ENDPOINT_AGENT, "100320", new Date(new Date(sim1.startedAt).getTime() - 2000).toISOString());
    cleanupCase(CASE);
    if (!found) throw new Error("Wazuh alert 100320 missing after the first simulation");
    const ing = await ctx.ingest.execute({ ...ctx.wazuh.normalize({ ...found.source }), tenantId: TENANT });
    if (ing.isFailure) throw new Error(`ingest failed ${JSON.stringify(ing.error)}`);
    incidentId = ing.value.incidentId as string | null;
    if (!incidentId) throw new Error("no incident (HIGH alert should open one automatically)");
    console.log(`   incident ${incidentId} severity ${ing.value.alert.severity}`);
    for (let k = 0; k < 3; k++) {
      if (!(await llmUp())) { observations.push("INFRASTRUCTURE: orchestrator not healthy before analysis — waiting"); await sleep(20000); }
      const a = await ctx.runAnalysis.execute({ tenantId: TENANT, incidentId, actor: SOC });
      if (!a.isFailure) break;
      if (!/UNAVAILABLE|TIMEOUT|timeout|ECONN|fetch failed|50[34]/i.test(JSON.stringify(a.error))) { observations.push(`AI_ANALYSIS_FAILED ${JSON.stringify(a.error).slice(0, 200)}`); break; }
      observations.push("INFRASTRUCTURE: AI analysis failed (LLM endpoint) — retrying"); await sleep(20000);
    }

    for (let round = 1; round <= ESCALATION_GROUND_TRUTH.maxInvestigationRounds; round++) {
      const rd: Record<string, any> = { round };
      const inc = await prisma.incident.findUnique({ where: { id: incidentId } });
      rd.investigationNumber = inc?.investigationNumber;
      console.log(`\n--- round ${round} (investigation #${inc?.investigationNumber}) ---`);
      // recommendation of this round
      let g = await generateUntilValid(inc!.investigationNumber, `round ${round}`);
      rd.recommendationGeneration = g;
      let rec = await prisma.recommendation.findFirst({ where: { incidentId, status: "VALIDATED", investigationNumber: inc!.investigationNumber }, orderBy: { recommendationNumber: "desc" }, include: { steps: { include: { action: true } } } });
      let fallback = false;
      if (!rec && round > 1) { // new round produced no VALIDATED recommendation: SOC picks an unexecuted step of the earlier recommendation (recorded)
        rec = await prisma.recommendation.findFirst({ where: { incidentId, status: "VALIDATED" }, orderBy: { recommendationNumber: "desc" }, include: { steps: { include: { action: true } } } });
        fallback = !!rec;
        observations.push(`ROUND ${round}: no VALIDATED recommendation for investigation #${inc!.investigationNumber} after ${g.attempts} model attempts — the SOC hands an unexecuted step of the earlier recommendation to IR (harness fallback, recorded)`);
      }
      rd.fallbackToEarlierRecommendation = fallback;
      if (!rec) { fatal = `round ${round}: no recommendation available`; rounds.push(rd); break; }
      const step = rec.steps.find((s) => s.actionId && !used.has(s.id)) ?? rec.steps.find((s) => s.actionId);
      if (!step) { fatal = `round ${round}: no step available`; rounds.push(rd); break; }
      used.add(step.id);
      rd.recommendation = { number: rec.recommendationNumber, investigationNumber: rec.investigationNumber, steps: rec.steps.map((s) => `${s.action?.code}→${s.target}`), chosenStep: `${step.action?.code}→${step.target}` };
      const plan = await ctx.createPlan.execute({ recommendationId: rec.id, stepId: step.id, tenantId: TENANT });
      if (plan.isFailure) { fatal = `round ${round}: create plan failed ${JSON.stringify(plan.error)}`; rounds.push(rd); break; }
      let p = plan.value;
      while (p.status === "PENDING_IR_DECISION") {
        const a = (await ctx.approvals.findByResponse(p.id, TENANT)).find((x) => x.status === "pending");
        if (!a) break;
        await ctx.decide.execute({ approvalId: a.id, tenantId: TENANT, status: "approved", decidedBy: IR, decidedByRole: "IR_TEAM", comment: `evaluation: scripted IR approval (round ${round})` });
        p = (await ctx.plans.findById(p.id, TENANT))!;
      }
      const s = await ctx.start.execute({ responseId: p.id, tenantId: TENANT, startedBy: IR });
      if (s.isFailure) { fatal = `round ${round}: start failed ${JSON.stringify(s.error)}`; rounds.push(rd); break; }
      await sleep(3000);
      const c = await ctx.complete.execute({ responseId: p.id, tenantId: TENANT, completedBy: IR, executionResult: { simulated: true, manual: true, by: IR, action: step.action?.code, target: step.target } });
      if (c.isFailure) { fatal = `round ${round}: complete failed ${JSON.stringify(c.error)}`; rounds.push(rd); break; }
      rd.responseId = p.id; rd.responseCompletedAt = new Date().toISOString();
      // the threat comes back AFTER the response completed
      const after = new Date().toISOString();
      const again = await simulate(CASE, facts);
      const seen = await waitForAlert(ENDPOINT_AGENT, "100320", after);
      cleanupCase(CASE);
      rd.recurrence = { simulatedAt: again.startedAt, alertSeenInIndexer: !!seen, alertId: (seen?.source as any)?.id ?? null };
      console.log(`   > recurrence simulated after the response; alert in indexer: ${!!seen}`);
      await sleep(15000);
      const recBefore = await prisma.recommendation.count({ where: { incidentId } });
      const v = await ctx.rehunt.execute({ incidentId, responseId: p.id, tenantId: TENANT, verifiedBy: IR });
      if (v.isFailure) { rd.rehuntError = String(v.error); fatal = `round ${round}: re-hunt failed ${v.error}`; rounds.push(rd); break; }
      const ver = await prisma.verification.findFirst({ where: { responseId: p.id } });
      const incAfter = await prisma.incident.findUnique({ where: { id: incidentId } });
      const recAfter = await prisma.recommendation.count({ where: { incidentId } });
      rd.verification = { result: ver?.result, matchingEvents: ver?.matchingEvents, iocRecurrence: ver?.iocRecurrence, mode: (ver?.afterState as any)?.evidenceSource ?? null, verificationId: ver?.id };
      rd.incidentAfter = { status: incAfter?.status, investigationNumber: incAfter?.investigationNumber };
      rd.recommendationsCreatedByVerification = recAfter - recBefore;
      console.log(`   verification ${ver?.result} (${ver?.matchingEvents} matching events); incident ${incAfter?.status}, investigation #${incAfter?.investigationNumber}; new recommendations: ${recAfter - recBefore}`);
      rounds.push(rd);
      chk(`R${round}a`, `round ${round}: the REAL_WAZUH re-hunt sees the recurrence`, "NOT_RESOLVED, matching events > 0", `${ver?.result}, ${ver?.matchingEvents}`, ver?.result === "NOT_RESOLVED" && (ver?.matchingEvents ?? 0) > 0);
      if (round < ESCALATION_GROUND_TRUTH.maxInvestigationRounds) {
        chk(`R${round}b`, `round ${round}: investigation reopened, incident not closed`, `investigation #${round + 1}, status not resolved/escalated`, `#${incAfter?.investigationNumber}, ${incAfter?.status}`, incAfter?.investigationNumber === round + 1 && !["resolved", "escalated", "dismissed"].includes(String(incAfter?.status)));
      }
    }

    // ---- escalation checks
    const final = await prisma.incident.findUnique({ where: { id: incidentId } });
    const reached = rounds.length === 3 && rounds.every((r) => r.verification?.result === "NOT_RESOLVED");
    const audits = await prisma.auditLog.findMany({ where: { OR: [{ entityId: incidentId }] }, orderBy: { createdAt: "asc" }, select: { action: true, actor: true, metadata: true } });
    const act = (n: string) => audits.filter((a) => a.action === n);
    const vers = await prisma.verification.findMany({ where: { incidentId }, orderBy: { verifiedAt: "asc" } });
    chk("E1", "three REAL_WAZUH verifications, all NOT_RESOLVED", "3 × NOT_RESOLVED", vers.map((v) => v.result).join(", "), vers.length === 3 && vers.every((v) => v.result === "NOT_RESOLVED"));
    chk("E2", "the third NOT_RESOLVED escalates the incident (not resolved, not closed)", "status escalated, investigation #3", `${final?.status}, #${final?.investigationNumber}`, final?.status === "escalated" && final?.investigationNumber === 3);
    chk("E3", "INVESTIGATION_ESCALATED audited with MAX_INVESTIGATION_ROUNDS_REACHED", "present", JSON.stringify(act("INVESTIGATION_ESCALATED").map((a) => (a.metadata as any)?.escalationReasons ?? (a.metadata as any)?.reasons ?? null)), act("INVESTIGATION_ESCALATED").length === 1 && JSON.stringify(act("INVESTIGATION_ESCALATED")[0].metadata).includes("MAX_INVESTIGATION_ROUNDS_REACHED"));
    chk("E4", "INCIDENT_ESCALATED audited, INVESTIGATION_REOPENED exactly twice", `INCIDENT_ESCALATED=1, INVESTIGATION_REOPENED=2`, `INCIDENT_ESCALATED=${act("INCIDENT_ESCALATED").length}, INVESTIGATION_REOPENED=${act("INVESTIGATION_REOPENED").length}`, act("INCIDENT_ESCALATED").length === 1 && act("INVESTIGATION_REOPENED").length === 2);
    await sleep(3000);
    const recNow = await prisma.recommendation.count({ where: { incidentId } });
    const lastVerifAt = vers[vers.length - 1]?.verifiedAt;
    const recAfterEsc = await prisma.recommendation.count({ where: { incidentId, createdAt: { gt: lastVerifAt } } });
    chk("E5", "no new recommendation / investigation after the escalation", "0 recommendations after the 3rd verification; investigation stays #3", `${recAfterEsc} new recommendations; #${final?.investigationNumber}`, recAfterEsc === 0 && final?.investigationNumber === 3);
    const plansAll = await prisma.responsePlan.findMany({ where: { incidentId }, select: { id: true, status: true, createdAt: true } });
    const plansAfter = plansAll.filter((x) => lastVerifAt && x.createdAt > lastVerifAt);
    chk("E6", "no response was created or executed automatically after the escalation", "0 new tickets", `${plansAfter.length} new tickets`, plansAfter.length === 0);
    const upd = new UpdateIncidentStatusUseCase(new PrismaIncidentRepository(prisma), new AuditLogger(prisma));
    const res = await upd.execute({ id: incidentId, tenantId: TENANT, status: "resolved", actor: SOC });
    chk("E7", "an escalated incident cannot be resolved by hand", "refused RESOLVE_REQUIRES_VERIFICATION", res.isFailure ? String(res.error) : "accepted", res.isFailure && String(res.error) === "RESOLVE_REQUIRES_VERIFICATION");
    const again = await ctx.rehunt.execute({ incidentId, responseId: rounds[2]?.responseId, tenantId: TENANT, verifiedBy: IR });
    chk("E8", "a ticket cannot be verified twice (no silent fourth round)", "refused", again.isFailure ? String(again.error) : "accepted", again.isFailure);
    const chRes = await prisma.incident.findUnique({ where: { id: incidentId } });
    chk("E9", "the escalated incident is still not closed after all attempts", "status escalated", String(chRes?.status), chRes?.status === "escalated");
    const aiClosers = audits.filter((a) => /^INCIDENT_(RESOLVED|STATUS_CHANGED)$/.test(a.action) && /agent|ai|llm|system/i.test(a.actor ?? ""));
    chk("E10", "no AI/system actor changed the incident status", "0", String(aiClosers.length), aiClosers.length === 0);
    rounds.forEach((r) => { if (r.fallbackToEarlierRecommendation) observations.push(`round ${r.round} used an earlier recommendation`); });
    var escalatedObserved = reached && final?.status === "escalated";
  } catch (e) { fatal = fatal ?? (e as Error).message; console.error("   FATAL:", fatal); var escalatedObserved = false; }

  const out = {
    label: LABEL, startedAt, finishedAt: new Date().toISOString(), database: dbName, groundTruthSha256: gtHash, groundTruth: ESCALATION_GROUND_TRUTH, incidentId,
    escalatedObserved, verificationMode: "REAL_WAZUH", roundsReached: rounds.filter((r) => r.verification).length, rounds, checks, observations, fatal,
    result: escalatedObserved && checks.every((c) => c.pass) ? "PASS" : fatal ? "INCOMPLETE" : "FAIL",
    note: "ESCALATED is recorded only because the third round was reached." ,
  };
  fs.mkdirSync(OUT, { recursive: true });
  fs.writeFileSync(path.join(OUT, `${LABEL}.json`), JSON.stringify(out, null, 2));
  console.log(`\nWrote results/extended-evaluation/runs/${LABEL}.json — ${out.result}; escalatedObserved=${escalatedObserved}`);
  await prisma.$disconnect();
})().catch((e) => { console.error(e); process.exit(1); });
