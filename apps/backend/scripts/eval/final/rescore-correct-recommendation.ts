/**
 * rescore-correct-recommendation.ts - scores the OBSERVED final recommendations stored in existing run.json files against the
 * Correct Recommendation Ground Truth (groundTruthCorrectness.ts, the version in the working tree). Read-only over the runs.
 *
 * It never calls an LLM, never runs a simulation and never creates a recommendation: a case without an observed
 * recommendation is reported as N/A (not as a failure). The runs are NOT merged: each source is scored on its own and the
 * report states the run each row comes from.
 *
 * Usage: npx ts-node --transpile-only scripts/eval/final/rescore-correct-recommendation.ts <outDir> <label>=<run.json> [<label>=<run.json> ...]
 */
import * as fs from "node:fs";
import * as path from "node:path";
import { createHash } from "node:crypto";
import { aggregateCorrectness, evaluateCorrectRecommendation, CorrectnessResult } from "../../../src/evaluation/correctRecommendation";
import { CORRECTNESS_GROUND_TRUTH, correctnessGroundTruthMetadata, resolveCorrectnessGroundTruth } from "../../../src/evaluation/groundTruthCorrectness";
import { findActionKnowledge } from "../../../src/domain/knowledge/actionKnowledge";

const [outDir, ...sources] = process.argv.slice(2);
if (!outDir || sources.length === 0) { console.error("usage: rescore-correct-recommendation.ts <outDir> <label>=<run.json> ..."); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

const sha = (p: string) => createHash("sha256").update(fs.readFileSync(p)).digest("hex");
const meta = correctnessGroundTruthMetadata();

interface Row {
  source: string; caseId: string; gtDefined: boolean; expectedPairs: string[]; observedAvailable: boolean; observedPairs: string[] | null;
  correct: boolean | "N/A"; reason: string; playbookMatch: boolean | null; unexpected: string[]; missing: string[];
  compliance: string | null; workflow: string; verification: string; iocRecall: string; notes: string;
}
const rows: Row[] = [];
const perSource: Record<string, { file: string; sha256: string; runLabel: string; startedAt: string; aggregate: ReturnType<typeof aggregateCorrectness> }> = {};

for (const s of sources) {
  const [label, file] = s.split("=");
  const run = JSON.parse(fs.readFileSync(file, "utf8"));
  const results: { caseId: string; result: CorrectnessResult | null }[] = [];
  for (const c of run.cases as any[]) {
    const gt = CORRECTNESS_GROUND_TRUTH.find((g) => g.caseId === c.caseId);
    const facts = c.simulation?.facts ?? {};
    // placeholders are resolved from facts recorded BEFORE the attack in the same run (never from an AI output)
    const ctx: Record<string, string> = { ATTACKER_IP: String(facts.attackerIp ?? ""), TESTSERVER_IP: String(facts.testServerIp ?? ""), KWORKERD_SHA256: String(c.groundTruth?.expectedEvidence?.fileSha256 ?? "") };
    const resolved = gt ? resolveCorrectnessGroundTruth(gt, ctx) : null;
    const expectedPairs = resolved ? resolved.expectedRecommendations.map((r) => `${r.action} -> ${r.targets.map((t) => t.value).join(" | ")}`) : [];
    const am = c.actionMatch;
    const observed = am && Array.isArray(am.actualActions) && am.actualActions.length > 0;
    let result: CorrectnessResult | null = null;
    if (resolved && observed && resolved.expectedRecommendations.length > 0) {
      result = evaluateCorrectRecommendation(resolved, {
        playbook: c.playbookCode ?? null,
        steps: (am.actualActions as string[]).map((a, i) => ({ action: a, target: (am.actualTargets as string[])[i] ?? "", targetType: findActionKnowledge(a)?.targetKind ?? null })),
      });
    }
    results.push({ caseId: c.caseId, result });
    const env = c.environmentStatus === "ENVIRONMENT_UNAVAILABLE";
    rows.push({
      source: label, caseId: c.caseId, gtDefined: !!resolved && resolved.expectedRecommendations.length > 0, expectedPairs,
      observedAvailable: !!observed, observedPairs: observed ? (am.actualActions as string[]).map((a, i) => `${a} -> ${am.actualTargets[i]}`) : null,
      correct: result ? result.correct : "N/A", reason: result ? result.reason : env ? "ENVIRONMENT_UNAVAILABLE in this run: not evaluated" : "no observed recommendation",
      playbookMatch: result ? result.playbookMatch : null,
      unexpected: result ? result.unexpectedRecommendations.map((u) => `${u.action} -> ${u.target}`) : [],
      missing: result ? result.missingRecommendations.map((m) => `${m.action} -> ${m.acceptableTargets.join(" | ")}`) : [],
      compliance: c.recommendationCompliance ?? null,
      workflow: env ? "N/A" : `${c.workflowCompleted ? "complete" : "incomplete"} (${c.finalStatus ?? "no final status"})`,
      verification: env ? "N/A" : c.verificationResult ? `${c.verificationResult} (${c.verificationMode ?? "?"})` : `none${c.rehuntError ? " - " + c.rehuntError : ""}`,
      iocRecall: c.iocRecall ? `${c.iocRecall.found}/${c.iocRecall.expected}` : "N/A",
      notes: [c.attemptCount ? "" : "", c.recommendationAttemptCount ? `use-case calls ${c.recommendationAttemptCount}` : "", c.invalidOutputCount ? `failed calls ${c.invalidOutputCount}` : ""].filter(Boolean).join("; "),
    });
  }
  perSource[label] = { file, sha256: sha(file), runLabel: run.runLabel, startedAt: run.startedAt, aggregate: aggregateCorrectness(results) };
}

const out = { generatedFor: "correctness GT " + meta.version, groundTruth: { version: meta.version, sha256: meta.sha256 }, rule: meta.rule, sources: perSource, rows };
fs.writeFileSync(path.join(outDir, "correct-recommendation-v3.3-matrix.json"), JSON.stringify(out, null, 2));
const md = ["| Source | Case | GT pairs | Observed (final recommendation) | Correct | Reason |", "|---|---|---|---|---|---|",
  ...rows.map((r) => `| ${r.source} | ${r.caseId} | ${r.expectedPairs.join("; ") || "-"} | ${r.observedPairs ? r.observedPairs.join("; ") : "N/A"} | ${r.correct} | ${r.reason} |`)].join("\n");
fs.writeFileSync(path.join(outDir, "correct-recommendation-v3.3-matrix.md"), md + "\n");
for (const [k, v] of Object.entries(perSource)) console.log(`${k}: ${v.aggregate.nCorrect}/${v.aggregate.nEvaluated} = ${v.aggregate.ratePct}% | correct ${v.aggregate.correctCases.join(",") || "-"} | incorrect ${v.aggregate.incorrectCases.join(",") || "-"} | not evaluable ${v.aggregate.notEvaluable.join(",") || "-"} | ${v.runLabel} sha ${v.sha256.slice(0, 12)}`);
