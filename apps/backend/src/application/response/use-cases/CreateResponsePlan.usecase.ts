import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IRecommendationRepository } from "../../../domain/recommendation/repositories/IRecommendationRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { ApprovalService } from "../../approval/services/ApprovalService";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";
import { INotificationDispatcherPort } from "../../notification/ports/INotificationDispatcherPort";
import { buildResponseAssignedEvent } from "../../notification/services/NotificationEventBuilder";

export type CreateResponsePlanError = "RECOMMENDATION_NOT_FOUND" | "STEP_NOT_FOUND" | "STEP_HAS_NO_ACTION" | "TICKET_ALREADY_EXISTS";

/** A step may get a new ticket only when every earlier ticket for it ended without executing. */
const REPLACEABLE_TICKET_STATUSES = new Set(["REJECTED", "FAILED", "CANCELLED", "MORE_EVIDENCE_REQUESTED"]);

/**
 * CreateResponsePlanUseCase — SOC "Send to IR" for ONE validated RecommendationStep (already resolved to a real
 * Action by RecommendationValidator). Order is fixed so no email ever points at a ticket that does not exist:
 *   1. create the Response Ticket: status PENDING_IR_DECISION, approval PENDING, assignedRole IR_TEAM
 *   2. open the IR decision (one IR_TEAM approval step, no notification of its own)
 *   3. emit ONE RESPONSE_ASSIGNED notification (email / in-app) carrying the ticket URL
 * Every ticket waits for IR APPROVE / REJECT — Policy is evaluated for the audit trail and the reason tags IR sees
 * (never to skip the decision). The step's own `requiresApproval` (the AI's advisory hint, RULE-006) is not an input.
 * A step with no resolved actionId (investigation-only) cannot become a ticket — there is nothing for IR to execute.
 *
 * This is the ONE place in the pipeline where a concrete Action is
 * already known, so it's the only call site that can supply
 * `actionImpactLevel` to Policy — RequestApproval (Recommendation-level,
 * before any action is chosen) cannot. `assetCriticality` is resolved by
 * ApprovalService from the shared asset catalog for the incident's hosts.
 */
export class CreateResponsePlanUseCase {
  constructor(
    private readonly recommendationRepository: IRecommendationRepository,
    private readonly actionRepository: IActionRepository,
    private readonly runbookRepository: IRunbookRepository,
    private readonly approvalService: ApprovalService,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly auditLogger: AuditLogger,
    private readonly notificationDispatcher: INotificationDispatcherPort,
    private readonly vigixBaseUrl: string
  ) {}

  async execute(input: { recommendationId: string; stepId: string; tenantId: string }): Promise<Result<ResponsePlan, CreateResponsePlanError>> {
    const recommendation = await this.recommendationRepository.findById(input.recommendationId, input.tenantId);
    if (!recommendation) return Result.fail("RECOMMENDATION_NOT_FOUND");

    const step = recommendation.steps.find((s) => s.id === input.stepId);
    if (!step) return Result.fail("STEP_NOT_FOUND");
    if (!step.actionId) return Result.fail("STEP_HAS_NO_ACTION");

    // One live Response Ticket per recommendation step (the UI hides the button, the API enforces it too).
    const existing = await this.responsePlanRepository.findByRecommendation(recommendation.id, input.tenantId);
    if (existing.some((p) => p.recommendationStepId === step.id && !REPLACEABLE_TICKET_STATUSES.has(p.status))) return Result.fail("TICKET_ALREADY_EXISTS");

    // Same Policy path RequestApproval uses (ApprovalService.evaluate) — never a second, divergent evaluation.
    const decision = await this.approvalService.evaluate({ tenantId: input.tenantId, incidentId: recommendation.incidentId, actionId: step.actionId });
    const { policy: policyResult, incidentContext } = decision;
    const action = await this.actionRepository.findById(step.actionId, input.tenantId);

    const responsePlan = await this.responsePlanRepository.create({
      tenantId: input.tenantId,
      incidentId: recommendation.incidentId,
      recommendationId: recommendation.id,
      recommendationStepId: step.id,
      actionId: step.actionId,
      target: step.target,
      reason: step.reason,
      expectedResult: step.expectedResult,
      approvalStatus: "PENDING",
      // IR_TEAM decides and executes every ticket; SOC (the investigation owner) never executes a response.
      assignedRole: "IR_TEAM",
      status: "PENDING_IR_DECISION",
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: "system",
      action: "RESPONSE_PLAN_CREATED",
      entity: "ResponsePlan",
      entityId: responsePlan.id,
      metadata: {
        recommendationId: recommendation.id,
        // The ticket cites the exact recommendation version it came from (createdBy carries the subtype knowledge version when used).
        recommendationNumber: recommendation.recommendationNumber,
        recommendationCreatedBy: recommendation.createdBy,
        recommendationStatus: recommendation.status,
        stepId: step.id,
        decisionRole: "IR_TEAM",
        policyApprovalRequired: policyResult.approvalRequired,
        responsibleRole: policyResult.responsibleRole,
        approvalReason: policyResult.approvalReason,
        assetCriticality: decision.assets?.criticality ?? null,
        matchedRules: policyResult.matchedRules,
        status: responsePlan.status,
      },
    });

    const runbook = step.sourceRunbookId ? await this.runbookRepository.findById(step.sourceRunbookId, input.tenantId) : null;

    // The IR decision, tied to THIS ticket. If opening fails the ticket stays PENDING_IR_DECISION and
    // RequestApproval (with responseId) can retry; IR cannot execute it until an approval exists and is approved.
    try {
      await this.approvalService.open({
        tenantId: input.tenantId,
        recommendation,
        responseId: responsePlan.id,
        decision,
        steps: [{ step, action, runbook }],
        notify: false,
      });
    } catch (err) {
      console.error("Failed to open the IR decision for response ticket", responsePlan.id, err);
    }

    try {
      await this.notificationDispatcher.emit(
        buildResponseAssignedEvent({
          recommendation,
          tenantId: input.tenantId,
          baseUrl: this.vigixBaseUrl,
          incident: {
            id: recommendation.incidentId,
            title: incidentContext?.title ?? "",
            priority: incidentContext?.priority ?? "medium",
            investigationNumber: incidentContext?.investigationNumber ?? recommendation.investigationNumber,
          },
          response: responsePlan,
          action,
          runbook,
        })
      );
    } catch (err) {
      console.error("Failed to emit RESPONSE_ASSIGNED notification for response plan", responsePlan.id, err);
    }

    return Result.ok(responsePlan);
  }
}
