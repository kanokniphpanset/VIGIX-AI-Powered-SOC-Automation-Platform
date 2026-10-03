/**
 * correct-recommendation-metrics.ts - Correct Recommendation Rate from a run.json (read-only over the run; writes one metrics file).
 *
 *   CR = N_correct / N_evaluated x 100
 *
 * N_evaluated = cases whose run.json entry has a `correctRecommendation` result (Ground Truth v3 present AND a final
 * recommendation exists). ENVIRONMENT_UNAVAILABLE / NOT_EVALUATED cases (TC-05) have none and leave the denominator.
 * It never re-scores with a different rule and never touches run.json. Separate from Recommendation Compliance,
 * Core Recommendation Consistency and First-pass Rate.
 *
 * Usage: npx ts-node --transpile-only scripts/eval/final/correct-recommendation-metrics.ts <runDir>
 *   (writes <runDir>/metrics/final-correct-recommendation.json)
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { aggregateCorrectness, CorrectnessResult } from "../../../src/evaluation/correctRecommendation";

const runDir = process.argv[2];
if (!runDir) { console.error("usage: correct-recommendation-metrics.ts <runDir>"); process.exit(2); }
const run = JSON.parse(fs.readFileSync(path.join(runDir, "run.json"), "utf8"));
if (!run.correctnessGroundTruth) { console.error("run.json has no correctnessGroundTruth metadata: this run was not scored with Ground Truth v3"); process.exit(3); }

const rows = (run.cases as any[]).map((c) => ({ caseId: c.caseId as string, result: (c.correctRecommendation ?? null) as CorrectnessResult | null, c }));
const agg = aggregateCorrectness(rows.map((r) => ({ caseId: r.caseId, result: r.result })));

const out = {
  kpi: "Correct Recommendation Rate",
  formula: "N_correct / N_evaluated x 100",
  definition: run.correctnessGroundTruth.rule,
  groundTruth: run.correctnessGroundTruth,
  sourceRun: run.runLabel,
  result: { numerator: agg.nCorrect, denominator: agg.nEvaluated, pct: agg.ratePct },
  correctCases: agg.correctCases,
  incorrectCases: agg.incorrectCases,
  notEvaluable: agg.notEvaluable.map((id) => ({ caseId: id, reason: rows.find((r) => r.caseId === id)?.c.environmentStatus === "ENVIRONMENT_UNAVAILABLE" ? "ENVIRONMENT_UNAVAILABLE" : "no Ground Truth recommendation or no final recommendation" })),
  perCase: rows.map((r) => ({
    caseId: r.caseId,
    groundTruth: r.c.correctnessGroundTruth?.expectedRecommendations?.map((e: any) => `${e.action} -> ${e.targets.map((t: any) => t.value).join(" | ")}`) ?? null,
    aiRecommendation: r.c.actionMatch ? (r.c.actionMatch.actualActions as string[]).map((a, i) => `${a} -> ${r.c.actionMatch.actualTargets[i]}`) : null,
    playbookMatch: r.result?.playbookMatch ?? null,
    actionTargetMatches: r.result?.actionTargetMatches ?? null,
    correct: r.result?.correct ?? null,
    reason: r.result?.reason ?? null,
    missingRecommendations: r.result?.missingRecommendations ?? null,
    unexpectedRecommendations: r.result?.unexpectedRecommendations ?? null,
    mismatchedTargets: r.result?.mismatchedTargets ?? null,
    recommendationCompliance: r.c.recommendationCompliance,
  })),
  note: "Compliance (system/policy validity) and Core Consistency (repeatability) are separate metrics; neither is evidence of correctness.",
};
fs.mkdirSync(path.join(runDir, "metrics"), { recursive: true });
fs.writeFileSync(path.join(runDir, "metrics", "final-correct-recommendation.json"), JSON.stringify(out, null, 2));
console.log(`Correct Recommendation Rate = ${agg.nCorrect}/${agg.nEvaluated} = ${agg.ratePct}%  incorrect: ${agg.incorrectCases.join(",") || "-"}  not evaluable: ${agg.notEvaluable.join(",") || "-"}`);
