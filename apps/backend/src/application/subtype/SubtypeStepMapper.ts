import { IActionRepository } from "../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../domain/runbook/repositories/IRunbookRepository";
import { CreateRecommendationStepData, RecommendationSnapshotData } from "../../domain/recommendation/repositories/IRecommendationRepository";
import { reviewCandidate } from "../../domain/subtype/outputValidator";
import { RecommendationContextDto } from "../recommendation/dto/RecommendationContextDto";
import { SubtypeEvaluation } from "./SubtypeRecommendationService";

/** An AI narrator may only phrase the summary. It receives the approved plan and its answer is REVIEWED, never trusted. */
export interface ISubtypeNarrator {
  narrate(context: RecommendationContextDto, brief: SubtypeBrief): Promise<unknown | null>;
}
export interface SubtypeBrief { steps: { action: string; target: string | null; title: string }[]; missingInfo: string[] }

export type MapResult =
  | { ok: true; summary: string; steps: CreateRecommendationStepData[]; snapshot: RecommendationSnapshotData | null; llm: { used: boolean; accepted: boolean; deviations: string[] } }
  | { ok: false; reason: string };

/**
 * Maps the approved SubtypeEvaluation onto persistable RecommendationSteps:
 *  - ACTION steps carry a real Action row (catalog) + the Runbook row; they are the ONLY ticketable steps;
 *  - MANUAL / CHECK steps have no action (approval requests, missing information, investigation) and are never ticketed.
 * If the catalog lacks a row for an approved action the whole subtype recommendation is refused (KNOWLEDGE_NOT_SEEDED) - the caller falls
 * back to the legacy path; nothing is persisted half-way and no action is invented to fill the gap.
 */
export async function mapEvaluationToRecommendation(
  ev: SubtypeEvaluation, context: RecommendationContextDto, deps: { actions: IActionRepository; runbooks: IRunbookRepository; tenantId: string; narrator?: ISubtypeNarrator }
): Promise<MapResult> {
  if (!ev.plan || !ev.composition) return { ok: false, reason: "NO_PLAN" };
  const comp = ev.composition;
  const actionCodes = [...new Set(comp.steps.filter((s) => s.stepType === "ACTION").map((s) => s.actionCode!))];
  const runbookCodes = [...new Set(comp.steps.map((s) => s.runbookCode).filter((c): c is string => !!c))];
  const actionRows = actionCodes.length ? await deps.actions.findByCodes(actionCodes, deps.tenantId) : [];
  const runbookRows = runbookCodes.length ? await deps.runbooks.findByCodes(runbookCodes, deps.tenantId) : [];
  const actionByCode = new Map(actionRows.map((a) => [a.code, a]));
  const runbookByCode = new Map(runbookRows.map((r) => [r.code, r]));
  const missing = actionCodes.filter((c) => !actionByCode.get(c)?.enabled);
  if (missing.length) return { ok: false, reason: `KNOWLEDGE_NOT_SEEDED: catalog has no enabled Action row for ${missing.join(", ")}` };

  const steps: CreateRecommendationStepData[] = comp.steps.map((s, i) => ({
    stepOrder: i + 1,
    stepType: s.stepType,
    title: s.title,
    objective: s.objective,
    actionId: s.stepType === "ACTION" ? actionByCode.get(s.actionCode!)!.id : null,
    target: s.target,
    reason: s.reason || "ตามผลการประเมินหลักฐานและ policy",
    evidence: s.evidenceRefs,
    sourceRunbookId: s.runbookCode ? runbookByCode.get(s.runbookCode)?.id ?? null : null,
    precondition: s.precondition,
    expectedResult: s.expectedResult,
    requiresApproval: s.requiresApproval,
    instructions: s.instructions.map((x) => ({ order: x.order, instruction: x.instruction, target: x.target, expectedResult: x.expectedResult, title: x.title, impact: x.impact, verify: x.verify, kind: x.kind, manualOwner: x.manualOwner, method: x.method ?? null, methodKind: x.methodKind, preconditions: x.preconditions ?? [], rollback: x.rollback ?? null, note: x.note ?? null })),
    verificationCriteria: s.verificationCriteria,
  }));

  // Optional AI narration: the answer is reviewed against the approved plan; any deviation rejects it and the deterministic summary stays.
  let summary = comp.summary;
  const llm = { used: false, accepted: false, deviations: [] as string[] };
  if (deps.narrator && comp.steps.some((s) => s.stepType === "ACTION")) {
    llm.used = true;
    try {
      const brief: SubtypeBrief = { steps: comp.steps.filter((s) => s.stepType === "ACTION").map((s) => ({ action: s.actionCode!, target: s.target, title: s.title })), missingInfo: comp.missingInfo };
      const candidate = await deps.narrator.narrate(context, brief);
      const allowed = new Set<string>([...context.affectedHosts]);
      const review = reviewCandidate(ev.kb, ev.plan, candidate, allowed);
      llm.deviations = review.deviations;
      if (review.accepted && review.summary) { summary = review.summary; llm.accepted = true; }
    } catch (err) {
      llm.deviations = [`NARRATOR_ERROR: ${err instanceof Error ? err.message : String(err)}`];
    }
  }

  const snapshot: RecommendationSnapshotData | null = context.playbook
    ? {
        playbookCode: context.playbook.code, playbookVersion: context.playbook.version, procedureCode: "SUBTYPE_KNOWLEDGE", procedureVersion: ev.kb.version,
        procedureContent: { knowledgeVersion: ev.kb.version, knowledgeHash: ev.kb.hash, subtypes: ev.plan.active, openedBranches: ev.plan.opened, ordering: ev.plan.ordered.map((n) => ({ action: n.action_id, target: n.primary?.display ?? null, reason: n.orderReason })) },
        policyResult: ev.plan.instances.map((n) => ({ action: n.action_id, target: n.primary?.display ?? null, decision: n.decision.decision, flags: n.decision.flags })),
      }
    : null;
  return { ok: true, summary, steps, snapshot, llm };
}
