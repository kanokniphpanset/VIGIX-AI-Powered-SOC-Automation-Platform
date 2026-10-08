import { presentRecommendation } from "../../src/presentation/http/controllers/RecommendationController";
import { allowUnreviewed, harness, orgLoader } from "../helpers/subtypeFlowHarness";
import { EvalInput } from "./evalCases";
import { Observed, ObservedAction } from "./evalScoring";

/** Run one case through the REAL GenerateRecommendationUseCase (in-memory repositories, no DB, no network, no LLM) and extract what the user would see. */
const codeOf = (actionId: string | null | undefined) => (actionId ?? "").replace(/^action-/, "");
const stepText = (s: any) => [s.title, ...(s.instructions ?? []).flatMap((i: any) => [i.title, i.method, ...(i.preconditions ?? []), i.impact, i.verify, i.rollback, i.note, i.instruction])].filter(Boolean).join("\n");
const sectionOf = (text: string, heading: string): string => {
  const ls = text.split("\n"); const i = ls.findIndex((l) => l.startsWith(`**${heading}`));
  if (i < 0) return "";
  const out: string[] = [];
  for (let k = i + 1; k < ls.length && !ls[k].startsWith("**"); k++) out.push(ls[k]);
  return out.join("\n");
};

export async function runCase(input: EvalInput, system: "subtype" | "legacy"): Promise<Observed> {
  const base: Observed = { system, ready: [], text: "", numberedLines: [], missingText: "", approvalText: "", statusValidated: null, onlyActionStepsHaveActionId: null, rehunt: {}, error: null };
  const legacyPrev = input.tickets?.length ? [{ recommendationNumber: 1, investigationNumber: 1, actionCode: "ACT-BLOCK-SOURCE-IP", target: "172.19.0.3" }] : [];
  const run = async () => {
    const h = harness({
      rows: input.rows(), mode: system === "subtype" ? "enforce" : "off", loader: orgLoader(input.orgYaml), tickets: input.tickets ?? [], rehunt: input.rehunt ?? null,
      investigationNumber: input.investigationNumber ?? 1, nextNumber: input.investigationNumber ?? 1, criticality: input.criticality, previousSteps: system === "legacy" ? legacyPrev : [],
    });
    const r = await h.run();
    if (!r.isSuccess) return { ...base, error: String((r as any).error ?? "FAILED") };
    const rec = h.created[0];
    const ready: ObservedAction[] = rec.steps.filter((s) => s.stepType === "ACTION" && s.actionId).map((s) => ({ action: codeOf(s.actionId), target: s.target, text: stepText(s) }));
    if (system === "legacy") return { ...base, ready };
    const text: string = presentRecommendation(JSON.parse(JSON.stringify({ steps: rec.steps.map((s) => ({ stepType: s.stepType, title: s.title, actionId: s.actionId, instructions: s.instructions })) }))).recommendationText ?? "";
    const audit = (h.audits[0]?.audit ?? {}) as any;
    const rehunt: Record<string, string> = {};
    for (const d of audit.policyDecisions ?? []) if (d.target && d.rehuntDecision && d.decision === "ELIGIBLE") rehunt[d.target] = d.rehuntDecision;
    return {
      ...base, ready, text, numberedLines: text.split("\n").filter((l) => /^\d+\. \*\*/.test(l)),
      missingText: sectionOf(text, "ข้อมูลที่ต้องตรวจเพิ่ม"), approvalText: sectionOf(text, "ต้องขออนุมัติก่อนดำเนินการ"),
      statusValidated: rec.status === "VALIDATED" && h.audits[0]?.mode === "ENFORCE",
      onlyActionStepsHaveActionId: rec.steps.every((s) => !s.actionId || s.stepType === "ACTION"), rehunt,
    };
  };
  return system === "subtype" ? allowUnreviewed(run) : run();
}
