import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IApprovalRepository } from "../../../domain/approval/repositories/IApprovalRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";
import { IN_APP_ROLES, InAppNotifier } from "../../notification/services/InAppNotifier";

export type StartResponseError = "NOT_FOUND" | "APPROVAL_PENDING" | "APPROVAL_REJECTED" | "INVALID_STATE";

/**
 * StartResponseUseCase — records that IR Team has BEGUN manual execution of an APPROVED Response Ticket.
 * This method contains no shell/API/n8n call of any kind — "starting" a response means a human clicked a button after
 * physically beginning the containment action; this only updates persisted state and timestamps.
 *
 * Every ticket needs the IR decision first: the ticket must be READY_FOR_EXECUTION (or legacy APPROVED) and its IR
 * approval must be decided "approved". A ticket still waiting for the decision (APPROVAL_PENDING) or rejected
 * (APPROVAL_REJECTED) can never start (RULE-010: AI/nothing can bypass the IR decision). Legacy tickets that never had
 * an approval (Policy "not required" before the two-role change) were migrated to PENDING_IR_DECISION.
 */
export class StartResponseUseCase {
  constructor(
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly approvalRepository: IApprovalRepository,
    private readonly auditLogger: AuditLogger,
    private readonly inApp?: InAppNotifier
  ) {}

  async execute(input: { responseId: string; tenantId: string; startedBy: string }): Promise<Result<ResponsePlan, StartResponseError>> {
    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response) return Result.fail("NOT_FOUND");

    if (response.status === "PENDING_IR_DECISION" || response.status === "PENDING_APPROVAL") return Result.fail("APPROVAL_PENDING");
    if (response.status === "REJECTED") return Result.fail("APPROVAL_REJECTED");
    if (!["READY_FOR_EXECUTION", "APPROVED"].includes(response.status)) return Result.fail("INVALID_STATE");

    // Prefer this ticket's own approval; only approvals with no responseId (legacy recommendation-level rows) may stand in.
    const own = await this.approvalRepository.findByResponse(response.id, input.tenantId);
    const approvals = own.length
      ? own
      : (await this.approvalRepository.findByRecommendation(response.recommendationId, input.tenantId)).filter((a) => a.responseId === null);
    if (!approvals.length || approvals.some((a) => a.isOpen)) return Result.fail("APPROVAL_PENDING");
    const decided = approvals.filter((a) => a.status !== "cancelled").sort((x, y) => (x.decidedAt?.getTime() ?? 0) - (y.decidedAt?.getTime() ?? 0));
    if (!decided.length || decided[decided.length - 1].status !== "approved") return Result.fail("APPROVAL_REJECTED");

    const now = new Date();
    const updated = await this.responsePlanRepository.updateStatus(response.id, input.tenantId, {
      approvalStatus: "APPROVED",
      status: "IN_PROGRESS",
      assignedTo: input.startedBy,
      executedAt: now,
    });

    await this.responsePlanRepository.recordStepExecution?.(response.id, input.tenantId, { status: "IN_PROGRESS", executedBy: input.startedBy, at: now });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.startedBy,
      action: "RESPONSE_STARTED",
      entity: "ResponsePlan",
      entityId: response.id,
      metadata: { incidentId: response.incidentId, recommendationId: response.recommendationId, actionId: response.actionId },
    });

    await this.inApp?.notify({
      tenantId: input.tenantId,
      eventType: "RESPONSE_STARTED",
      roles: IN_APP_ROLES.RESPONSE_STARTED,
      incidentId: response.incidentId,
      responseId: response.id,
      title: `Response started${response.target ? ` on ${response.target}` : ""}`,
      body: null,
    });

    return Result.ok(updated);
  }
}
