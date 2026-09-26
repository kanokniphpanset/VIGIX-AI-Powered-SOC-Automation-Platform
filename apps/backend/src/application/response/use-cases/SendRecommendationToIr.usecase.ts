import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";
import { CreateResponsePlanUseCase } from "./CreateResponsePlan.usecase";

export type SendToIrError = "RECOMMENDATION_NOT_FOUND" | "RECOMMENDATION_NOT_VALIDATED" | "NOTHING_TO_SEND";

/** Statuses of a ticket that ended without executing: its step may be sent to IR again. */
const REPLACEABLE_TICKET_STATUSES = new Set(["REJECTED", "FAILED", "CANCELLED", "MORE_EVIDENCE_REQUESTED"]);

/**
 * SOC "Send to IR" — the end of the SOC part of the workflow (Investigation -> AI Analysis -> Recommendation -> SOC
 * review -> Send to IR). The SOC has reviewed a VALIDATED recommendation (deterministically validated against the
 * incident's evidence; a recommendation that failed validation can never be sent). For every action step that has no
 * live ticket yet, CreateResponsePlanUseCase creates the Response Ticket FIRST (PENDING_IR_DECISION, IR_TEAM), opens the
 * IR decision and only then sends the notification carrying the ticket link. Investigation-only steps (no action) get
 * no ticket. The SOC never executes anything; audited as RECOMMENDATION_SENT_TO_IR with the SOC note.
 */
export class SendRecommendationToIrUseCase {
  constructor(
    private readonly recommendations: IRecommendationRepository,
    private readonly responsePlans: IResponsePlanRepository,
    private readonly createResponsePlan: Pick<CreateResponsePlanUseCase, "execute">,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; recommendationId: string; actor: string; note: string | null }): Promise<Result<{ tickets: ResponsePlan[] }, SendToIrError>> {
    const recommendation = await this.recommendations.findById(input.recommendationId, input.tenantId);
    if (!recommendation) return Result.fail("RECOMMENDATION_NOT_FOUND");
    if (recommendation.status !== "VALIDATED") return Result.fail("RECOMMENDATION_NOT_VALIDATED");

    const existing = await this.responsePlans.findByRecommendation(recommendation.id, input.tenantId);
    const pending = recommendation.steps.filter(
      (s) => !!s.actionId && !existing.some((p) => p.recommendationStepId === s.id && !REPLACEABLE_TICKET_STATUSES.has(p.status))
    );
    if (!pending.length) return Result.fail("NOTHING_TO_SEND");

    const tickets: ResponsePlan[] = [];
    for (const step of pending) {
      const created = await this.createResponsePlan.execute({ recommendationId: recommendation.id, stepId: step.id, tenantId: input.tenantId });
      if (created.isSuccess) tickets.push(created.value);
    }
    if (!tickets.length) return Result.fail("NOTHING_TO_SEND");

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "RECOMMENDATION_SENT_TO_IR",
      entity: "Recommendation",
      entityId: recommendation.id,
      metadata: {
        incidentId: recommendation.incidentId,
        recommendationNumber: recommendation.recommendationNumber,
        ticketIds: tickets.map((t) => t.id),
        stepIds: tickets.map((t) => t.recommendationStepId),
        note: input.note?.trim() || null,
        decisionRole: "IR_TEAM",
      },
    });
    return Result.ok({ tickets });
  }
}
