import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";

export type ManualDecisionError = "NOT_FOUND" | "INVALID_STATE" | "ROLE_MISMATCH" | "ADMIN_NOT_APPROVER" | "NOTE_REQUIRED";

/**
 * ManualDecisionUseCase — the "Manual Decision" box of the main flow:
 *   IR Decision --REJECT--> Manual Decision --APPROVE--> IR Execution (Manual Response)
 * IR rejected the AI-recommended response on this ticket (status PENDING_MANUAL_DECISION); IR now writes its own manual
 * response plan (mandatory note) and approves it. The approval is recorded as a new, already-decided IR_TEAM approval
 * on the ticket, so StartResponse sees "approved" as the latest decision. The manual plan is kept on the ticket
 * (executionResult.manualDecision) and in the audit (MANUAL_DECISION_APPROVED). Nothing is executed here.
 */
export class ManualDecisionUseCase {
  constructor(
    private readonly approvalRepository: IApprovalRepository,
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { responseId: string; tenantId: string; decidedBy: string; decidedByRole: string; note: string | null }): Promise<Result<ResponsePlan, ManualDecisionError>> {
    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response) return Result.fail("NOT_FOUND");
    const note = input.note?.trim() || null;
    const denied =
      response.status !== "PENDING_MANUAL_DECISION"
        ? ("INVALID_STATE" as const)
        : input.decidedByRole === "admin"
          ? ("ADMIN_NOT_APPROVER" as const)
          : input.decidedByRole !== "IR_TEAM"
            ? ("ROLE_MISMATCH" as const)
            : !note
              ? ("NOTE_REQUIRED" as const)
              : null;
    if (denied) return Result.fail(denied);

    const previous = await this.approvalRepository.findByResponse(response.id, input.tenantId);
    const stepOrder = previous.reduce((max, a) => Math.max(max, a.stepOrder), 0) + 1;
    const opened = await this.approvalRepository.create({
      tenantId: input.tenantId,
      recommendationId: response.recommendationId,
      responseId: response.id,
      approvalRole: "IR_TEAM",
      reason: `Manual decision after IR reject: ${note}`,
      stepOrder,
    });
    const approval = await this.approvalRepository.decide(opened.id, input.tenantId, { status: "approved", decidedBy: input.decidedBy, comment: note });

    const decidedAt = new Date();
    const updated = await this.responsePlanRepository.updateStatus(response.id, input.tenantId, {
      approvalStatus: "APPROVED",
      status: "READY_FOR_EXECUTION",
      executionResult: { manualDecision: { note, decidedBy: input.decidedBy, decidedAt: decidedAt.toISOString(), approvalId: approval.id } },
    });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.decidedBy,
      action: "MANUAL_DECISION_APPROVED",
      entity: "ResponsePlan",
      entityId: response.id,
      metadata: { incidentId: response.incidentId, recommendationId: response.recommendationId, approvalId: approval.id, note },
    });

    return Result.ok(updated);
  }
}
