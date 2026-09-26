import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { Approval } from "../../../domain/approval/entities/Approval.entity";
import { Result } from "../../../shared/result/Result";
import { ApprovalService } from "../services/ApprovalService";

export type RequestApprovalError = "RECOMMENDATION_NOT_FOUND" | "RESPONSE_NOT_FOUND" | "APPROVAL_ALREADY_EXISTS" | "RESPONSE_NOT_AWAITING_DECISION";

/** Tickets that are still waiting for the IR decision (PENDING_APPROVAL: created before the two-role change). */
const AWAITING_DECISION = new Set(["PENDING_IR_DECISION", "PENDING_APPROVAL"]);

/**
 * RequestApprovalUseCase — fallback that (re)opens the IR decision for ONE Response Ticket whose approval could not be
 * opened when the ticket was created (CreateResponsePlan normally opens it). The ticket must still be waiting for the
 * IR decision and must not already have an open one. Nothing is chosen by the caller: the approval is always the single
 * IR_TEAM step, with Policy's reason tags (ApprovalService.evaluate, the same path CreateResponsePlan uses).
 */
export class RequestApprovalUseCase {
  constructor(
    private readonly recommendationRepository: IRecommendationRepository,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly approvalRepository: IApprovalRepository,
    private readonly actionRepository: IActionRepository,
    private readonly runbookRepository: IRunbookRepository,
    private readonly approvalService: ApprovalService
  ) {}

  async execute(input: { recommendationId: string; responseId: string; tenantId: string }): Promise<Result<Approval, RequestApprovalError>> {
    const recommendation = await this.recommendationRepository.findById(input.recommendationId, input.tenantId);
    if (!recommendation) return Result.fail("RECOMMENDATION_NOT_FOUND");

    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response || response.recommendationId !== recommendation.id) return Result.fail("RESPONSE_NOT_FOUND");
    if (!AWAITING_DECISION.has(response.status)) return Result.fail("RESPONSE_NOT_AWAITING_DECISION");
    const existing = await this.approvalRepository.findByResponse(response.id, input.tenantId);
    if (existing.some((a) => a.isOpen)) return Result.fail("APPROVAL_ALREADY_EXISTS");

    const decision = await this.approvalService.evaluate({ tenantId: input.tenantId, incidentId: recommendation.incidentId, actionId: response.actionId });
    if (!decision.incidentContext) return Result.fail("RECOMMENDATION_NOT_FOUND");

    // ResponsePlan.recommendationStepId is the source of truth for which step a plan came from.
    // Legacy plans created before that column existed (null) fall back to action+target matching.
    const stepRows = response.recommendationStepId
      ? recommendation.steps.filter((s) => s.id === response.recommendationStepId)
      : recommendation.steps.filter((s) => s.actionId === response.actionId && (s.target ?? null) === (response.target ?? null));
    const steps = await Promise.all(
      stepRows.map(async (step) => ({
        step,
        action: step.actionId ? await this.actionRepository.findById(step.actionId, input.tenantId) : null,
        runbook: step.sourceRunbookId ? await this.runbookRepository.findById(step.sourceRunbookId, input.tenantId) : null,
      }))
    );

    const approval = await this.approvalService.open({ tenantId: input.tenantId, recommendation, responseId: response.id, decision, steps });
    if (response.status !== "PENDING_IR_DECISION") {
      await this.responsePlanRepository.updateStatus(response.id, input.tenantId, { approvalStatus: "PENDING", status: "PENDING_IR_DECISION" });
    }
    return Result.ok(approval);
  }
}
