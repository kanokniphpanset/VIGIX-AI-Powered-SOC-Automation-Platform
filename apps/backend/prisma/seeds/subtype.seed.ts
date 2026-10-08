import { Prisma, PrismaClient } from "@prisma/client";
import { SubtypeKnowledgeLoader } from "../../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { KnowledgeBase } from "../../src/domain/subtype/types";

/**
 * subtype.seed.ts - the Action Catalog / Runbook rows behind the subtype knowledge (apps/knowledge/subtype-playbooks).
 * RecommendationStep.actionId is a foreign key to `actions`, so every approved subtype action needs a catalog row; the rows are DERIVED
 * from the knowledge (one source of truth, version-stamped) and added next to - never replacing - the legacy ACT-* / RB-* rows.
 *
 * Idempotent upserts by unique code. NOT part of the default `prisma db seed`: run it explicitly against the intended database
 * (`npm run subtype:seed`), because it writes rows. Nothing here executes anything.
 */
export interface SubtypeSeedAction { code: string; name: string; description: string; category: "CONTAINMENT" | "INVESTIGATION"; impactLevel: "LOW" | "MEDIUM" | "HIGH"; defaultApprovalRequired: boolean; runbookCode: string }
export interface SubtypeSeedRunbook {
  code: string; name: string; version: string; description: string; trigger: string; objective: string; preconditions: string[]; procedure: string[];
  decisionPoints: string[]; expectedResult: string; escalation: string; verificationCriteria: string[];
}

export function subtypeCatalog(kb: KnowledgeBase): { actions: SubtypeSeedAction[]; runbooks: SubtypeSeedRunbook[] } {
  if (kb.status !== "VALID") throw new Error(`subtype knowledge is INVALID: ${kb.errors.slice(0, 3).join(" | ")}`);
  const actions = [...kb.actions.values()].map((a): SubtypeSeedAction => {
    const impact = a.impact_level === "CRITICAL" ? "HIGH" : a.impact_level ?? "MEDIUM";
    return {
      code: a.action_id, name: a.action_name,
      description: `${a.objective} | constraints: ${a.execution_constraints.join("; ")} | subtype knowledge ${kb.version}; origin ${a.origin ?? "REFERENCE"}; review ${a.review_status ?? "IR_REVIEW_PENDING"}`,
      category: a.phase === "CONTAINMENT" ? "CONTAINMENT" : "INVESTIGATION", impactLevel: impact, defaultApprovalRequired: impact === "HIGH", runbookCode: a.runbook_refs[0],
    };
  });
  const runbooks = [...kb.runbooks.values()].map((r): SubtypeSeedRunbook => ({
    code: r.runbook_id, name: r.objective.slice(0, 120), version: kb.version, description: r.objective,
    trigger: `Required evidence: ${r.required_evidence.join(", ") || "-"}`, objective: r.objective, preconditions: r.prerequisites,
    procedure: r.ordered_steps.filter((s) => !s.fold).map((s) => `${s.step_id}${s.variant ? ` [${s.variant}]` : ""}: ${s.title ?? s.instruction}`),
    decisionPoints: r.failure_handling, expectedResult: r.ordered_steps.filter((s) => !s.fold && s.kind !== "verify").map((s) => s.expected_result).slice(-1)[0] ?? "", escalation: r.failure_handling[0] ?? "",
    verificationCriteria: r.verification,
  }));
  return { actions, runbooks };
}

export async function seedSubtypeKnowledge(prisma: PrismaClient, tenantId: string, loader: SubtypeKnowledgeLoader = new SubtypeKnowledgeLoader()): Promise<{ actions: number; runbooks: number; version: string }> {
  const kb = loader.load();
  const cat = subtypeCatalog(kb);
  for (const rb of cat.runbooks) {
    const data = {
      name: rb.name, version: rb.version, description: rb.description, trigger: rb.trigger, objective: rb.objective,
      preconditions: rb.preconditions as Prisma.InputJsonValue, procedure: rb.procedure as Prisma.InputJsonValue, decisionPoints: rb.decisionPoints as Prisma.InputJsonValue,
      expectedResult: rb.expectedResult, escalation: rb.escalation, verificationCriteria: rb.verificationCriteria as Prisma.InputJsonValue,
    };
    await prisma.runbook.upsert({ where: { code: rb.code }, update: data, create: { tenantId, code: rb.code, ...data } });
  }
  for (const a of cat.actions) {
    const runbook = await prisma.runbook.findUnique({ where: { code: a.runbookCode } });
    if (!runbook) throw new Error(`seedSubtypeKnowledge: runbook ${a.runbookCode} for ${a.code} not seeded`);
    const data = { name: a.name, description: a.description, category: a.category, impactLevel: a.impactLevel, defaultApprovalRequired: a.defaultApprovalRequired, runbookId: runbook.id };
    await prisma.action.upsert({ where: { code: a.code }, update: data, create: { tenantId, code: a.code, ...data } });
  }
  return { actions: cat.actions.length, runbooks: cat.runbooks.length, version: kb.version };
}
