/**
 * run-evaluation.ts — execute the deterministic 10-case evaluation against the REAL workflow data and
 * export the result (§12,§13,§18). Backend/DB/export only — no UI. Prints the per-case table, the KPI
 * summary, findings and verification mode, then writes JSON + CSV to scripts/eval-out/.
 *
 *   npx ts-node --transpile-only scripts/run-evaluation.ts
 */
import "dotenv/config";
import * as fs from "node:fs";
import * as path from "node:path";
import { PrismaClient } from "@prisma/client";
import { TC_GROUND_TRUTH } from "../src/evaluation/groundTruth";
import { collectEvaluationCase, summarize, knownActionCodes } from "../src/evaluation/EvaluationService";
import { EvaluationCase } from "../src/evaluation/types";

const OUT_DIR = path.join(__dirname, "eval-out");
const s = (n: number | null) => (n === null ? "-" : `${n}s`);

function toCsv(cases: EvaluationCase[]): string {
  const head = ["TC", "Attack", "Severity", "Risk", "RecommendationCompliance", "InvestigationTimeSec", "DecisionTimeSec", "Playbook", "PolicyEvaluated", "Decision", "ResponseCompleted", "Verification", "VerificationMode", "RehuntRound", "FinalStatus", "Intervention", "Finding"];
  const full = cases.map((c) => [
    c.caseId, c.attackName, c.severity ?? "", c.risk ?? "", c.recommendationCompliance,
    c.investigationTimeSeconds ?? "", c.timeToDecisionSeconds ?? "",
    c.playbookCode ?? "", String(c.workflow.policyEvaluated),
    c.workflow.decisionCompleted ? "decided" : "none",
    String(c.workflow.responseCompleted), c.verificationResult ?? "", c.verificationMode,
    c.rehuntRound ?? "", c.finalStatus ?? "", c.interventionType.join(";"),
    c.findings.join(" || "),
  ]);
  const esc = (v: unknown) => { const t = String(v); return /[",\n]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t; };
  return [head, ...full].map((r) => r.map(esc).join(",")).join("\n");
}

(async () => {
  const prisma = new PrismaClient();
  const known = await knownActionCodes(prisma);
  const cases: EvaluationCase[] = [];
  for (const gt of TC_GROUND_TRUTH) cases.push(await collectEvaluationCase(prisma, gt, known));
  const summary = summarize(cases);

  // ---- per-case table (§18)
  console.log("\n================= PER-CASE EVALUATION =================");
  console.log("TC     | Attack               | Sev    | Compliance     | InvTime | DecTime | Workflow  | Verify(mode)     | Retry");
  for (const c of cases) {
    console.log(
      `${c.caseId.padEnd(6)} | ${c.attackName.padEnd(20)} | ${(c.severity ?? "-").padEnd(6)} | ${c.recommendationCompliance.padEnd(14)} | ${s(c.investigationTimeSeconds).padEnd(7)} | ${s(c.timeToDecisionSeconds).padEnd(7)} | ${(c.workflowCompleted ? "COMPLETED" : "PARTIAL").padEnd(9)} | ${((c.verificationResult ?? "-") + "(" + c.verificationMode + ")").padEnd(16)} | ${c.invalidOutputCount}`
    );
    if (c.compliance && !c.compliance.compliant) console.log(`       └─ NON_COMPLIANT: ${c.compliance.failedChecks.join(" | ")}`);
  }

  // ---- compliance detail
  console.log("\n================= COMPLIANCE CHECKS =================");
  console.log("TC     | attack | evid | know | policy | pbook | appr | => COMPLIANT");
  for (const c of cases) {
    const k = c.compliance;
    const b = (x?: boolean) => (x ? " ✓ " : " ✗ ");
    console.log(`${c.caseId.padEnd(6)} |${b(k?.attackAlignment)}   |${b(k?.evidenceSupport)}  |${b(k?.knowledgeValidity)}  |${b(k?.policyCompliance)}    |${b(k?.playbookAlignment)}   |${b(k?.approvalCorrectness)}  | ${c.recommendationCompliance}`);
  }

  // ---- KPI summary (§12)
  console.log("\n================= KPI SUMMARY =================");
  console.log(`Total cases:                 ${summary.totalCases}`);
  console.log(`Evaluated cases:             ${summary.evaluatedCases}`);
  console.log(`COMPLIANT / NON_COMPLIANT:   ${summary.compliantRecommendations} / ${summary.nonCompliantRecommendations}`);
  console.log(`Recommendation Compliance:   ${summary.recommendationComplianceRate}% (as-is, after intervention)`);
  console.log(`  └ automatic (no interv.):  ${summary.complianceRateAutomatic}% (${summary.automaticCompliant}/${summary.evaluatedCases})`);
  console.log(`Investigation Time (s):      min ${summary.investigationTimeMin} | max ${summary.investigationTimeMax} | avg ${summary.investigationTimeAverage}`);
  console.log(`Time-to-Decision (s):        min ${summary.decisionTimeMin} | max ${summary.decisionTimeMax} | avg ${summary.decisionTimeAverage}`);
  console.log(`Workflow completed cases:    ${summary.workflowCompletedCases}/${summary.totalCases}`);
  console.log(`Intervention cases:          ${summary.interventionCases}`);
  console.log(`Verification MOCK / REAL:    ${summary.mockVerificationCases} / ${summary.realWazuhVerificationCases}`);

  // ---- findings (§9)
  console.log("\n================= FINDINGS / INTERVENTIONS =================");
  for (const c of cases) if (c.interventionRequired) console.log(`${c.caseId}: [${c.interventionType.join(",")}] ${c.findings.join(" || ") || "(retry only)"}`);

  // ---- export (§13)
  fs.mkdirSync(OUT_DIR, { recursive: true });
  const jsonPath = path.join(OUT_DIR, "evaluation.json");
  const csvPath = path.join(OUT_DIR, "evaluation.csv");
  fs.writeFileSync(jsonPath, JSON.stringify({ generatedAt: new Date().toISOString(), summary, cases }, null, 2));
  fs.writeFileSync(csvPath, toCsv(cases));
  console.log(`\nExported:\n  ${jsonPath}\n  ${csvPath}`);

  await prisma.$disconnect();
})().catch((e) => { console.error("evaluation crashed:", String(e?.stack ?? e).slice(0, 700)); process.exit(2); });
