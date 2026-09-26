import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";

export type FailResponseError = "NOT_FOUND" | "INVALID_STATE";

export class FailResponseUseCase {
  constructor(
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: {
    responseId: string;
    tenantId: string;
    failedBy: string;
    executionResult: Record<string, unknown>;
  }): Promise<Result<ResponsePlan, FailResponseError>> {
    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response) return Result.fail("NOT_FOUND");
    if (response.status !== "IN_PROGRESS") return Result.fail("INVALID_STATE");

    const updated = await this.responsePlanRepository.updateStatus(response.id, input.tenantId, {
      status: "FAILED",
      completedAt: new Date(),
      executionResult: input.executionResult,
    });

    await this.responsePlanRepository.recordStepExecution?.(response.id, input.tenantId, { status: "FAILED", executedBy: input.failedBy, at: updated.completedAt ?? new Date(), actualResult: JSON.stringify(input.executionResult) });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.failedBy,
      action: "RESPONSE_FAILED",
      entity: "ResponsePlan",
      entityId: response.id,
      metadata: { recommendationId: response.recommendationId, executionResult: input.executionResult },
    });

    return Result.ok(updated);
  }
}
