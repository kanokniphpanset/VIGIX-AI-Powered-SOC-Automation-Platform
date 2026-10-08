import { Recommendation as PrismaRecommendation, RecommendationStep as PrismaRecommendationStep } from "@prisma/client";
import {
  Recommendation,
  RecommendationInstruction,
  RecommendationStatus,
  RecommendationStepStatus,
  RecommendationStepType,
} from "../../../../domain/recommendation/entities/Recommendation.entity";

type PrismaRecommendationWithSteps = PrismaRecommendation & { steps: PrismaRecommendationStep[] };

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function asInstructions(value: unknown): RecommendationInstruction[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((v): v is Record<string, unknown> => !!v && typeof v === "object")
    .map((v) => ({
      order: typeof v.order === "number" ? v.order : 0,
      instruction: typeof v.instruction === "string" ? v.instruction : "",
      target: typeof v.target === "string" ? v.target : null,
      expectedResult: typeof v.expectedResult === "string" ? v.expectedResult : null,
    }))
    .sort((a, b) => a.order - b.order);
}

/** recommendation_steps.phase carries the step type; rows written before step types existed are ACTION (with an action) or CHECK. */
function stepTypeOf(phase: string | null, actionId: string | null): RecommendationStepType {
  if (phase === "CHECK" || phase === "MANUAL") return phase;
  return actionId ? "ACTION" : "CHECK";
}

export class RecommendationMapper {
  static toDomain(raw: PrismaRecommendationWithSteps): Recommendation {
    return Recommendation.create({
      id: raw.id,
      tenantId: raw.tenantId,
      incidentId: raw.incidentId,
      investigationNumber: raw.investigationNumber,
      recommendationNumber: raw.recommendationNumber,
      status: raw.status as RecommendationStatus,
      summary: raw.summary,
      createdBy: raw.createdBy,
      snapshotId: raw.snapshotId,
      steps: raw.steps.map((s) => ({
        id: s.id,
        stepOrder: s.stepOrder,
        stepType: stepTypeOf(s.phase, s.actionId),
        title: s.title,
        objective: s.objective,
        actionId: s.actionId,
        target: s.target,
        reason: s.reason,
        evidence: asStringArray(s.evidence),
        sourceRunbookId: s.sourceRunbookId,
        precondition: s.precondition,
        expectedResult: s.expectedResult,
        requiresApproval: s.requiresApproval,
        status: s.status as RecommendationStepStatus,
        instructions: asInstructions(s.instructions),
        verificationCriteria: s.verificationCriteria,
      })),
    });
  }
}
