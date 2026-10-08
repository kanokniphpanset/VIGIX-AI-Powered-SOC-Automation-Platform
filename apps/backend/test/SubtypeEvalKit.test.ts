import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { DEFAULT_SUBTYPE_KNOWLEDGE_DIR } from "../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { EVAL_INPUTS } from "./eval/evalCases";
import { runCase } from "./eval/evalRunner";
import { Aggregate, CaseScore, GtCase, Observed, aggregate, scoreCase } from "./eval/evalScoring";
import { loader as realLoader } from "./helpers/subtypeFixtures";

/**
 * EVALUATION KIT (offline). Scores the REAL GenerateRecommendationUseCase against a DRAFT Ground Truth, for round 1 and after a Re-hunt, for the
 * subtype path and for the legacy path (deterministic stand-in agent - NOT the production LLM agent). Recorded alerts + isolated fixtures only;
 * no live database, no service, no attack, no LLM. The Ground Truth file is hashed before and after the run and is never written by the kit.
 * Run only the kit:  npx jest test/SubtypeEvalKit      (the report is written to validation/eval/results/)
 */
const EVAL_DIR = path.join(DEFAULT_SUBTYPE_KNOWLEDGE_DIR, "validation", "eval");
const GT_FILE = path.join(EVAL_DIR, "ground-truth.draft.json");
const sha = (f: string) => crypto.createHash("sha256").update(fs.readFileSync(f)).digest("hex");
const gtRaw = () => JSON.parse(fs.readFileSync(GT_FILE, "utf8")) as { _meta: { status: string; ir_reviewed: boolean }; common: Record<string, string[]>; cases: GtCase[] };
const kb = realLoader.load();
const canonFor = (system: string) => (a: string) => (system === "legacy" ? kb.legacyActionMap.get(a) ?? [] : []);
const emptyObs = (over: Partial<Observed> = {}): Observed => ({ system: "subtype", ready: [], text: "", numberedLines: [], missingText: "", approvalText: "", statusValidated: true, onlyActionStepsHaveActionId: true, rehunt: {}, error: null, ...over });
const gtCase = (over: Partial<GtCase> = {}): GtCase => ({ case_id: "X", round: 1, title: "x", basis: [], expected_actions: [], prohibited_actions: [], process: {}, ...over });
const exp = (action: string, parts: string[], req: string[] = [], forb: string[] = []) => ({ action, target_parts: parts, scope_required: req, scope_forbidden: forb });
const obs = (action: string, target: string, text = "") => ({ action, target, text });

describe("scoring functions (hand-made data, independent of the runtime)", () => {
  it("precision / recall: TP, FP and FN are counted one-to-one on (action, target identity)", () => {
    const gt = gtCase({ expected_actions: [exp("A", ["t1"]), exp("B", ["t2"])] });
    const s = scoreCase(gt, emptyObs({ ready: [obs("A", "t1"), obs("C", "t3"), obs("A", "t9")] }), canonFor("subtype"), {});
    expect([s.tp, s.fp, s.fn]).toEqual([1, 2, 1]);
    expect(s.wrongTarget).toBe(1);                                                          // A at the wrong target
    const a = aggregate([s], { processApplicable: true });
    expect(a.precision).toBe("33.3% (1/3)"); expect(a.recall).toBe("50.0% (1/2)");
  });
  it("0/0 is reported as n/a, never as 100%", () => {
    const a = aggregate([scoreCase(gtCase(), emptyObs(), canonFor("subtype"), {})], { processApplicable: true });
    expect(a.precision).toBe("n/a (0/0)"); expect(a.recall).toBe("n/a (0/0)");
  });
  it("target & scope: required substrings present and forbidden ones absent; an unmatched expected action counts as wrong", () => {
    const gt = gtCase({ expected_actions: [exp("A", ["t1"], ["SSH"], ["/24"]), exp("B", ["t2"], ["x"])] });
    const ok = scoreCase(gt, emptyObs({ ready: [obs("A", "t1", "SSH only")] }), canonFor("subtype"), {});
    expect([ok.scopeCorrect, ok.scopeTotal]).toEqual([1, 2]);
    const widened = scoreCase(gt, emptyObs({ ready: [obs("A", "t1", "SSH /24")] }), canonFor("subtype"), {});
    expect(widened.scopeCorrect).toBe(0);
  });
  it("prohibited actions: a ready action in the (group-expanded) prohibited set is a violation even when its target matches", () => {
    const gt = gtCase({ prohibited_actions: ["@G", "Z"], expected_actions: [exp("P", ["t"])] });
    const s = scoreCase(gt, emptyObs({ ready: [obs("P", "t"), obs("Z", "t"), obs("Q", "t")] }), canonFor("subtype"), { G: ["P"] });
    expect(s.prohibited).toBe(2);                                                           // P (in group) and Z
    expect(aggregate([s], { processApplicable: true }).prohibitedRate).toContain("(2/3)");
  });
  it("process checks: ordering, not-ready, information-needed, approval separation, and the two structural guarantees", () => {
    const gt = gtCase({ process: { ordered_pairs: [["a", "b"]], must_not_be_ready: ["BAD"], must_be_in_missing: ["need"] }, expected_approval: [{ action: "A", authority_label: "owner" }] });
    const good = scoreCase(gt, emptyObs({ text: "a then b", numberedLines: ["1. **a**"], missingText: "need this", approvalText: "owner approves" }), canonFor("subtype"), {});
    expect([good.processPassed, good.processTotal]).toEqual([7, 7]);
    const bad = scoreCase(gt, emptyObs({ text: "b then a", numberedLines: ["1. **BAD**"], missingText: "", approvalText: "", ready: [obs("A", "t")], statusValidated: false, onlyActionStepsHaveActionId: false }), canonFor("subtype"), {});
    expect(bad.processPassed).toBe(0);
    expect(bad.processFailures.length).toBe(7);
  });
  it("re-hunt correctness: exact for the subtype path; coarse (propose vs hold) for any system", () => {
    const gt = gtCase({ round: 2, expected_rehunt: { t1: "INVESTIGATE", t2: "REPEAT" } });
    const s = scoreCase(gt, emptyObs({ rehunt: { t1: "ADJUST", t2: "REPEAT" } }), canonFor("subtype"), {});
    expect([s.rehuntExact, s.rehuntCoarse, s.rehuntTotal]).toEqual([1, 2, 2]);
    const legacy = scoreCase(gt, emptyObs({ system: "legacy", ready: [obs("ACT-X", "t2")] }), canonFor("legacy"), {});
    expect([legacy.rehuntExact, legacy.rehuntCoarse]).toEqual([0, 2]);                      // legacy: t1 HOLD ok, t2 PROPOSE ok
  });
  it("a legacy action is matched through the migration map", () => {
    const gt = gtCase({ expected_actions: [exp("ACT-AUTH-SOURCE-RESTRICT", ["172.19.0.3"])] });
    const s = scoreCase(gt, emptyObs({ system: "legacy", ready: [obs("ACT-BLOCK-SOURCE-IP", "172.19.0.3")] }), canonFor("legacy"), {});
    expect(s.tp).toBe(1);
  });
});

describe("Ground Truth file", () => {
  const gt = gtRaw();
  it("is DRAFT, not IR-reviewed, and says it was not derived from system output", () => {
    expect(gt._meta.status).toBe("DRAFT"); expect(gt._meta.ir_reviewed).toBe(false);
    expect((gt._meta as any).authored_from).toMatch(/NOT derived by running the system/);
  });
  it("every case has a runtime input and vice versa; ids are unique", () => {
    const ids = gt.cases.map((c) => c.case_id);
    expect(new Set(ids).size).toBe(ids.length);
    expect([...ids].sort()).toEqual(EVAL_INPUTS.map((i) => i.caseId).sort());
  });
  it("only names actions that exist in the knowledge", () => {
    const groups = gt.common;
    for (const c of gt.cases) {
      const named = [...c.expected_actions.map((e) => e.action), ...(c.expected_approval ?? []).map((a) => a.action), ...c.prohibited_actions.flatMap((p) => (p.startsWith("@") ? groups[p.slice(1)] : [p]))];
      for (const a of named) expect(kb.actions.has(a)).toBe(true);
    }
  });
});

describe("run the kit through the real runtime and write the report", () => {
  it("scores every case; the Ground Truth file is untouched; no run errors", async () => {
    const before = sha(GT_FILE);
    const gt = gtRaw();
    const scores: CaseScore[] = [];
    const errors: string[] = [];
    for (const input of EVAL_INPUTS) {
      const g = gt.cases.find((c) => c.case_id === input.caseId)!;
      for (const system of ["subtype", ...(input.legacy ? ["legacy"] : [])] as ("subtype" | "legacy")[]) {
        const o = await runCase(input, system);
        if (o.error) errors.push(`${input.caseId}/${system}: ${o.error}`);
        scores.push(scoreCase(g, o, canonFor(system), gt.common));
      }
    }
    expect(errors).toEqual([]);
    expect(sha(GT_FILE)).toBe(before);

    const pick = (system: string, round?: number, only?: Set<string>) => scores.filter((s) => s.system === system && (round === undefined || s.round === round) && (!only || only.has(s.caseId)));
    const legacyIds = new Set(scores.filter((s) => s.system === "legacy").map((s) => s.caseId));
    const table: Record<string, Aggregate> = {
      "subtype / first response": aggregate(pick("subtype", 1), { processApplicable: true }),
      "subtype / after Re-hunt": aggregate(pick("subtype", 2), { processApplicable: true }),
      "subtype / ALL": aggregate(pick("subtype"), { processApplicable: true }),
      "subtype / legacy-comparable subset, first response": aggregate(pick("subtype", 1, legacyIds), { processApplicable: true }),
      "subtype / legacy-comparable subset, after Re-hunt": aggregate(pick("subtype", 2, legacyIds), { processApplicable: true }),
      "legacy stand-in / first response": aggregate(pick("legacy", 1), { processApplicable: false }),
      "legacy stand-in / after Re-hunt": aggregate(pick("legacy", 2), { processApplicable: false }),
    };
    const classOf = (id: string) => EVAL_INPUTS.find((i) => i.caseId === id)!.dataClass;
    const dataClasses: Record<string, number> = {};
    for (const i of EVAL_INPUTS) dataClasses[i.dataClass] = (dataClasses[i.dataClass] ?? 0) + 1;
    const report = {
      generatedAt: new Date().toISOString(), knowledgeVersion: kb.version, groundTruth: { file: "validation/eval/ground-truth.draft.json", sha256: before, status: gt._meta.status, irReviewed: gt._meta.ir_reviewed, cases: gt.cases.length },
      runtime: "GenerateRecommendationUseCase over in-memory repositories (subtype: SUBTYPE mode enforce with the review override; legacy: mode off with FakeRecommendationAgent)",
      llm: "none - deterministic; this is NOT an actual-LLM evaluation", live: "none - no live alert, no database, no service touched", dataClasses, aggregates: table,
      cases: scores.map((s) => ({ ...s, dataClass: classOf(s.caseId) })),
    };
    const outDir = path.join(EVAL_DIR, "results");
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, "latest.json"), JSON.stringify(report, null, 1), "utf8");
    fs.writeFileSync(path.join(outDir, "latest.md"), toMarkdown(report, gt), "utf8");
    expect(Object.keys(table)).toHaveLength(7);
  });
});

function toMarkdown(r: any, gt: { cases: GtCase[] }): string {
  const rows = (k: string, a: Aggregate) =>
    `| ${k} | ${a.cases} | ${a.precision} | ${a.recall} | ${a.scopeAccuracy} | ${a.processCorrectness} | ${a.prohibitedRate} | ${a.rehuntExactRate} | ${a.rehuntCoarseRate} |`;
  const L: string[] = [
    "# Evaluation results (offline, DRAFT Ground Truth)", "",
    `- generated: ${r.generatedAt} | knowledge: ${r.knowledgeVersion}`,
    `- Ground Truth: ${r.groundTruth.file} (${r.groundTruth.cases} cases) status **${r.groundTruth.status}**, IR reviewed: **${r.groundTruth.irReviewed}**, sha256 ${r.groundTruth.sha256.slice(0, 16)}...`,
    `- runtime: ${r.runtime}`, `- LLM: ${r.llm}`, `- live: ${r.live}`,
    `- data classes: ${Object.entries(r.dataClasses).map(([k, v]) => `${k} x${v}`).join(", ")}`, "",
    "A score is a score against a DRAFT reference authored by the engineering team; it is not an acceptance result and not a production-quality claim.", "",
    "| system / round | cases | action precision | action recall | target & scope accuracy | response process correctness | prohibited actions | re-hunt correctness (exact) | re-hunt correctness (propose vs hold) |",
    "|---|---|---|---|---|---|---|---|---|", ...Object.entries(r.aggregates).map(([k, a]) => rows(k, a as Aggregate)), "",
    "Denominators: precision = TP/(TP+FP) over ready ACTION steps; recall = TP/(TP+FN) over expected actions; scope = expected actions whose matched step has every required and no forbidden scope string; process = checks passed / checks defined (including 2 structural checks per case); prohibited = ready actions the reference forbids / all ready actions; re-hunt = (case, target) expectations.", "",
    "## Per case", "", "| case | system | data | TP/FP/FN | scope | scope failures | prohibited | process failures | re-hunt (expected -> actual) |", "|---|---|---|---|---|---|---|---|---|",
  ];
  for (const c of r.cases as (CaseScore & { dataClass: string })[]) {
    L.push(`| ${c.caseId} | ${c.system} | ${c.dataClass} | ${c.tp}/${c.fp}/${c.fn} | ${c.scopeCorrect}/${c.scopeTotal} | ${c.scopeFailures.join("; ") || "-"} | ${c.prohibited} | ${c.processFailures.join("; ") || "-"} | ${c.rehuntDetail.map((d) => `${d.target}: ${d.expected} -> ${d.actual}`).join("; ") || "-"} |`);
  }
  L.push("", "## Ground Truth titles", "", ...gt.cases.map((c) => `- ${c.case_id}: ${c.title}`));
  return L.join("\n") + "\n";
}
