/**
 * merge-consistency.ts — assembles the FINAL consistency.json from the recorded attempts, keeping every attempt file.
 *
 *   attempt 1            consistency-attempt1.json       6 cases x 5 runs; TC-09's 5 calls failed with AI_UNAVAILABLE
 *   outage re-run        consistency-rerun-tc09-outage.json   TC-09 again while the LLM endpoint was still down (5 failures)
 *   successful re-run    consistency-rerun-tc09.json     TC-09 once the LLM endpoint was reachable again (5 runs)
 *
 * Calls that failed with AI_UNAVAILABLE (LLM endpoint timeout / ConnectError) are AVAILABILITY failures of the model
 * server, independent of the evidence and of the recommendation content; they are excluded from the consistency
 * denominator but listed in `excluded_infrastructure_failures`. Nothing else is excluded or altered. The consistency
 * formula is the one defined in consistency.ts.
 *
 *   cd apps/backend && npx ts-node --transpile-only scripts/eval/additional/merge-consistency.ts
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { DATA, r2, stats } from "./common";

const J = (f: string) => JSON.parse(fs.readFileSync(path.join(DATA, f), "utf8"));
const a1 = J("consistency-attempt1.json"), outage = J("consistency-rerun-tc09-outage.json"), rerun = J("consistency-rerun-tc09.json");
const infra = (r: any) => r.recommendation_status !== "VALIDATED" && r.failure_reason === "AI_UNAVAILABLE";
const tag = (rs: any[], attempt: string) => rs.map((r) => ({ ...r, attempt }));
const all = [...tag(a1.runs, "attempt1"), ...tag(outage.runs, "rerun-tc09-outage"), ...tag(rerun.runs, "rerun-tc09")];
const excluded = all.filter(infra).map((r) => ({ case_id: r.case_id, repetition: r.repetition, attempt: r.attempt, reason: r.failure_reason, detail: String((r.violations ?? [])[0] ?? "").slice(0, 200), generation_seconds: r.generation_seconds }));
const runs = all.filter((r) => !infra(r));
const CASES: string[] = a1.cases;
const snapshots: Record<string, any> = { ...a1.evidenceSnapshots, ...rerun.evidenceSnapshots };

const key = (r: any) => `${r.playbook_id}|${r.primary_action}|${r.target_type}|${r.target_value}`;
const setKey = (r: any) => JSON.stringify((r.all_steps ?? []).map((s: any) => `${s.action}|${s.target}`).sort());
const perCase = CASES.map((caseId) => {
  const rs = runs.filter((r) => r.case_id === caseId);
  const validated = rs.filter((r) => r.recommendation_status === "VALIDATED");
  const tally = new Map<string, number>();
  for (const r of validated) tally.set(key(r), (tally.get(key(r)) ?? 0) + 1);
  const [modal, modalN] = [...tally.entries()].sort((a, b) => b[1] - a[1])[0] ?? [null, 0];
  const setTally = new Map<string, number>();
  for (const r of validated) setTally.set(setKey(r), (setTally.get(setKey(r)) ?? 0) + 1);
  const hashes = new Set(snapshots[caseId].evidenceSnapshotHashes);
  return { case_id: caseId, runs: rs.length, validated_runs: validated.length, consistent_runs: modalN, consistency_pct: rs.length ? r2((modalN / rs.length) * 100) : null, modal_primary: modal, distinct_primary_recommendations: tally.size, distribution: Object.fromEntries(tally), step_set_agreement_runs: Math.max(0, ...setTally.values()), step_set_agreement_pct: rs.length ? r2((Math.max(0, ...setTally.values()) / rs.length) * 100) : null, failed_runs: rs.filter((r) => r.recommendation_status !== "VALIDATED").map((r) => ({ repetition: r.repetition, reason: r.failure_reason })), evidence_snapshot_identical_across_runs: hashes.size === 1, generation_seconds: stats(rs.map((r) => r.generation_seconds)), source_attempt: [...new Set(rs.map((r) => r.attempt))].join("+") };
});
const total = perCase.reduce((a, c) => a + c.runs, 0), consistent = perCase.reduce((a, c) => a + c.consistent_runs, 0);
const pcts = perCase.map((c) => c.consistency_pct as number);
const mean = pcts.reduce((a, b) => a + b, 0) / pcts.length;
const overall = { runs: total, consistent_runs: consistent, consistency_pct: r2((consistent / total) * 100), per_case_mean_pct: r2(mean), per_case_sd_pct: pcts.length > 1 ? r2(Math.sqrt(pcts.reduce((a, b) => a + (b - mean) ** 2, 0) / (pcts.length - 1))) : 0, validated_runs: runs.filter((r) => r.recommendation_status === "VALIDATED").length, all_evidence_snapshots_identical: perCase.every((c) => c.evidence_snapshot_identical_across_runs), step_set_agreement_pct_pooled: r2((perCase.reduce((a, c) => a + c.step_set_agreement_runs, 0) / total) * 100) };

const out = {
  evaluation: "B_recommendation_consistency", merged: true, startedAt: a1.startedAt, finishedAt: rerun.finishedAt, database: a1.database, orchestrator: a1.orchestrator, source_run: a1.source_run, repetitions: a1.repetitions, cases: CASES,
  llm_actually_used: "vllm-spark-01/gemma4-26b-uncensored (self-hosted vLLM, OpenAI-compatible endpoint) — read from the model recorded in the analysis results of the same database; NOT OpenRouter",
  definition: a1.definition, firstRoundContext: a1.firstRoundContext, nothingPersisted: true,
  provenance: { attempt1: "consistency-attempt1.json (TC-01, TC-02, TC-04, TC-06, TC-07 used; TC-09's 5 calls failed: LLM endpoint timeout/ConnectError)", outage_rerun: "consistency-rerun-tc09-outage.json (TC-09 attempted again while the endpoint was still down: 5 failures)", successful_rerun: "consistency-rerun-tc09.json (TC-09 after the endpoint came back: 5 runs used)" },
  excluded_infrastructure_failures: excluded, excluded_infrastructure_failure_count: excluded.length,
  evidenceSnapshots: snapshots, overall, perCase, runs,
};
fs.writeFileSync(path.join(DATA, "consistency.json"), JSON.stringify(out, null, 2));
console.log(JSON.stringify({ overall, excluded: excluded.length }));
for (const c of perCase) console.log(`${c.case_id}: ${c.consistent_runs}/${c.runs} = ${c.consistency_pct}% (validated ${c.validated_runs}, distinct ${c.distinct_primary_recommendations}, step-set agreement ${c.step_set_agreement_pct}%) [${c.source_attempt}]`);
