/**
 * consistency.ts — Evaluation B: Recommendation Consistency.
 *
 * Same evidence snapshot, N repetitions: for each selected case the recommendation pipeline (context builder ->
 * LLM agent -> bounded correction -> deterministic validator; the REAL GenerateRecommendationUseCase) is run N times
 * against the SAME incident of the frozen Clean Run (cloned database). No new attack is generated and nothing is
 * persisted (in-memory recommendation store, capturing audit logger): only the AI's output varies.
 *
 *   cd apps/backend && EVAL_DB=soar_addl_eval . scripts/eval/eval-env.sh
 *   npx ts-node --transpile-only scripts/eval/additional/consistency.ts [--reps 5] [--cases TC-01,TC-02,...]
 *
 * Consistency (per case) = runs whose validated primary recommendation equals the modal validated primary
 * recommendation / total runs, where "identical primary recommendation" = same playbook + same primary action +
 * same target type + same target value. Runs that fail validation count as not consistent. It is NOT accuracy.
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { iocKind } from "../../../src/domain/knowledge/knowledgeTypes";
import { TENANT, DATA, CLEAN_LABEL, frozenRun, buildPipeline, preflightAdditional, sha, r2, stats } from "./common";

const arg = (n: string, d?: string) => { const i = process.argv.indexOf(`--${n}`); return i >= 0 ? process.argv[i + 1] : d; };
const REPS = Math.max(1, Number(arg("reps", "5")));
const TAG = arg("tag", "") as string; // file suffix: consistency${TAG}.json (used to keep a re-run of some cases separate)
const RETRY_INFRA = process.argv.includes("--retry-infra"); // an AI_UNAVAILABLE call is infrastructure: wait for the LLM endpoint, repeat the SAME repetition, keep the failed attempt
const LLM_WAIT_MS = Number(process.env.LLM_WAIT_MS ?? 15 * 60 * 1000);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
function llmBaseUrl(): string | null { try { return [...fs.readFileSync(path.join(process.cwd(), "..", "ai-orchestrator", ".env"), "utf8").matchAll(/^LLM_BASE_URL=(.*)$/gm)].map((x) => x[1].replace(/"/g, "").trim()).pop() ?? null; } catch { return null; } }
async function llmHealthy(): Promise<boolean> { const b = llmBaseUrl(); if (!b) return true; try { return (await fetch(`${b.replace(/\/$/, "")}/models`, { signal: AbortSignal.timeout(8000) })).ok; } catch { return false; } }
async function waitForLlm(): Promise<{ recovered: boolean; waitedSeconds: number }> { const t0 = Date.now(); while (Date.now() - t0 < LLM_WAIT_MS) { if (await llmHealthy()) return { recovered: true, waitedSeconds: Math.round((Date.now() - t0) / 1000) }; await sleep(15000); } return { recovered: false, waitedSeconds: Math.round((Date.now() - t0) / 1000) }; }
const infrastructureFailures: any[] = [];
const CASES = (arg("cases", "TC-01,TC-02,TC-04,TC-06,TC-07,TC-09") as string).split(",").map((s) => s.trim());

(async () => {
  const prisma = new PrismaClient();
  const pre = await preflightAdditional();
  const clean = frozenRun(CLEAN_LABEL);
  const P = buildPipeline(prisma, process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8001", { firstRound: true });
  const actionById = new Map((await prisma.action.findMany({ select: { id: true, code: true } })).map((a) => [a.id, a.code]));
  const startedAt = new Date().toISOString();
  const runs: any[] = [];
  const snapshots: Record<string, any> = {};
  const rawByRun: any[] = [];

  for (const caseId of CASES) {
    const c = clean.cases.find((x: any) => x.caseId === caseId);
    if (!c?.incidentId) { console.log(`${caseId}: no incident in the frozen clean run — skipped`); continue; }
    const incidentId = c.incidentId as string;
    for (let rep = 1; rep <= REPS; rep++) {
      let infraAttempt = 0;
      const priorInfra: any[] = [];
      for (;;) { // one repetition; repeated ONLY after an infrastructure failure (never after a model result)
      P.created.length = 0; P.audits.length = 0; P.raw.length = 0;
      const ctxRes = await P.builder.build(incidentId, TENANT);
      if (ctxRes.isFailure) { console.log(`${caseId} #${rep}: context build failed`); continue; }
      const ctx = ctxRes.value;
      const ctxHash = sha(JSON.stringify(ctx));
      snapshots[caseId] ??= { incidentId, evidenceSnapshotHashes: [], iocCount: ctx.iocs.length, evidenceRows: ctx.evidence.length, affectedHosts: ctx.affectedHosts, playbook: ctx.playbook?.code ?? null, matchedTechniques: ctx.playbook?.matchedTechniques ?? [], mitreMappings: ctx.mitreMappings.map((m) => m.techniqueId), recommendableActions: (ctx.actionProcedures ?? []).filter((p) => p.applicable !== false && p.evidence?.satisfied !== false).map((p) => p.actionCode) };
      snapshots[caseId].evidenceSnapshotHashes.push(ctxHash);
      const t0 = Date.now();
      const res = await P.generate.execute({ incidentId, tenantId: TENANT });
      const seconds = r2((Date.now() - t0) / 1000);
      const audit = P.audits.find((a) => a.action === "RECOMMENDATION_GENERATION_FAILED");
      const base: any = { case_id: caseId, repetition: rep, incident_id: incidentId, evidence_snapshot_hash: ctxHash.slice(0, 16), generation_seconds: seconds, attempts: audit?.metadata?.attempts ?? (P.raw.length || 1), mitre_technique: [...new Set([...(ctx.playbook?.matchedTechniques ?? [])])].join(",") || null };
      if (res.isSuccess) {
        const data = P.created[0];
        const steps = (data.steps as any[]).map((s) => ({ order: s.stepOrder, action: actionById.get(s.actionId) ?? s.actionId, target: s.target, requiresApproval: s.requiresApproval }));
        const primary = steps[0];
        const kind = ctx.affectedHosts.includes(primary.target) ? "host" : iocKind(ctx.iocs.find((i) => i.iocValue === primary.target)?.iocType ?? "");
        const pol = data.snapshot?.policyResult?.[primary.action] ?? null;
        Object.assign(base, { playbook_id: data.snapshot?.playbookCode ?? null, primary_action: primary.action, target_type: kind, target_value: primary.target, recommendation_status: "VALIDATED", validation_status: "VALIDATED", policy_status: pol ? `approvalRequired=${pol.approvalRequired}; approvalRole=${pol.approvalRole}; responsibleRole=${pol.responsibleRole}; rules=${(pol.matchedRules ?? []).join("+")}` : "no policy result", all_steps: steps, failure_reason: null, violations: [] });
      } else {
        Object.assign(base, { playbook_id: ctx.playbook?.code ?? null, primary_action: null, target_type: null, target_value: null, recommendation_status: "NOT_GENERATED", validation_status: `INVALID (${res.error})`, policy_status: "not reached", all_steps: [], failure_reason: res.error, violations: audit?.metadata?.violations ?? audit?.violations ?? [] });
      }
      const rawSet = [...P.raw];
      if (RETRY_INFRA && !res.isSuccess && String(res.error) === "AI_UNAVAILABLE" && infraAttempt < 4) {
        // INFRASTRUCTURE failure (LLM endpoint timeout / connection error): recorded, NOT a recommendation, NOT counted as inconsistency.
        const f: any = { case_id: caseId, repetition: rep, attempt: infraAttempt + 1, at: new Date().toISOString(), classification: "INFRASTRUCTURE", detail: String((base.violations ?? [])[0] ?? res.error).slice(0, 240), generation_seconds: seconds };
        infrastructureFailures.push(f); priorInfra.push(f); infraAttempt++;
        console.log(`${caseId} #${rep}: INFRASTRUCTURE failure (attempt ${infraAttempt}) — waiting for the LLM endpoint, then repeating this repetition`);
        const w = await waitForLlm(); f.recovered = w.recovered; f.waitedSeconds = w.waitedSeconds;
        if (!w.recovered) { console.log("LLM endpoint did not recover — recording the failure and stopping this repetition"); runs.push({ ...base, classification: "INFRASTRUCTURE_FAILURE_UNRECOVERED", rerun_after_infrastructure_failure: false, previous_infrastructure_failures: priorInfra }); break; }
        continue;
      }
      base.rerun_after_infrastructure_failure = priorInfra.length > 0;
      base.previous_infrastructure_failures = priorInfra;
      rawByRun.push({ case_id: caseId, repetition: rep, candidates: rawSet });
      runs.push(base);
      console.log(`${caseId} #${rep}: ${base.recommendation_status} ${base.primary_action ?? "-"} → ${base.target_value ?? "-"} (${seconds}s${base.attempts > 1 ? ", " + base.attempts + " agent calls" : ""})${priorInfra.length ? " [RERUN after infrastructure failure]" : ""}`);
      break;
      }
    }
  }

  // ---- consistency (definition in the header)
  const key = (r: any) => `${r.playbook_id}|${r.primary_action}|${r.target_type}|${r.target_value}`;
  const setKey = (r: any) => JSON.stringify((r.all_steps ?? []).map((s: any) => `${s.action}|${s.target}`).sort());
  const perCase = CASES.filter((c) => runs.some((r) => r.case_id === c)).map((caseId) => {
    const rs = runs.filter((r) => r.case_id === caseId && r.classification !== "INFRASTRUCTURE_FAILURE_UNRECOVERED");
    const validated = rs.filter((r) => r.recommendation_status === "VALIDATED");
    const tally = new Map<string, number>();
    for (const r of validated) tally.set(key(r), (tally.get(key(r)) ?? 0) + 1);
    const [modal, modalN] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0] ?? [null, 0];
    const setTally = new Map<string, number>();
    for (const r of validated) setTally.set(setKey(r), (setTally.get(setKey(r)) ?? 0) + 1);
    const snapshotIdentical = new Set(snapshots[caseId].evidenceSnapshotHashes).size === 1;
    return { case_id: caseId, runs: rs.length, validated_runs: validated.length, consistent_runs: modalN, consistency_pct: r2((modalN / rs.length) * 100), modal_primary: modal, distinct_primary_recommendations: tally.size, distribution: Object.fromEntries(tally), step_set_agreement_runs: Math.max(0, ...setTally.values()), step_set_agreement_pct: r2((Math.max(0, ...setTally.values()) / rs.length) * 100), failed_runs: rs.filter((r) => r.recommendation_status !== "VALIDATED").map((r) => ({ repetition: r.repetition, reason: r.failure_reason })), evidence_snapshot_identical_across_runs: snapshotIdentical, generation_seconds: stats(rs.map((r) => r.generation_seconds)) };
  });
  const total = perCase.reduce((a, c) => a + c.runs, 0), consistent = perCase.reduce((a, c) => a + c.consistent_runs, 0);
  const pcts = perCase.map((c) => c.consistency_pct);
  const m = pcts.reduce((a, b) => a + b, 0) / (pcts.length || 1);
  const overall = { runs: total, consistent_runs: consistent, consistency_pct: total ? r2((consistent / total) * 100) : null, per_case_mean_pct: r2(m), per_case_sd_pct: pcts.length > 1 ? r2(Math.sqrt(pcts.reduce((a, b) => a + (b - m) ** 2, 0) / (pcts.length - 1))) : 0, validated_runs: runs.filter((r) => r.recommendation_status === "VALIDATED").length, all_evidence_snapshots_identical: perCase.every((c) => c.evidence_snapshot_identical_across_runs) };

  fs.mkdirSync(DATA, { recursive: true });
  fs.writeFileSync(path.join(DATA, `consistency${TAG}.json`), JSON.stringify({ evaluation: "B_recommendation_consistency", startedAt, finishedAt: new Date().toISOString(), database: pre.db, orchestrator: pre.orchestrator, source_run: CLEAN_LABEL, repetitions: REPS, cases: CASES, definition: "identical validated primary recommendation = same playbook + primary action + target type + target value; consistency = modal validated primary / total runs", firstRoundContext: "the incident's earlier recommendations are hidden from the context (previousSteps=[]) — the condition of the original first-round generation; otherwise the NO_NEW_STEP validator rule would reject any repeat by design", nothingPersisted: true, infrastructure_failures: infrastructureFailures, infrastructure_failure_count: infrastructureFailures.length, evidenceSnapshots: snapshots, overall, perCase, runs }, null, 2));
  fs.writeFileSync(path.join(DATA, `consistency${TAG}-raw-candidates.json`), JSON.stringify(rawByRun, null, 2));
  console.log("\nOVERALL", JSON.stringify(overall));
  for (const c of perCase) console.log(`${c.case_id}: ${c.consistent_runs}/${c.runs} = ${c.consistency_pct}% (validated ${c.validated_runs}, distinct ${c.distinct_primary_recommendations})`);
  await prisma.$disconnect();
})().catch((e) => { console.error("consistency crashed:", String(e?.stack ?? e).slice(0, 1200)); process.exit(2); });
