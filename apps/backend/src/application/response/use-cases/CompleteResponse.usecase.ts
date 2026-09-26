import { IResponsePlanRepository } from "../../../domain/response/repositories/IResponsePlanRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { IRecommendationContextRepository } from "../../recommendation/ports/IRecommendationContextRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { ResponsePlan } from "../../../domain/response/entities/ResponsePlan.entity";
import { Result } from "../../../shared/result/Result";
import { INotificationDispatcherPort } from "../../notification/ports/INotificationDispatcherPort";
import { buildResponseCompletedEvent } from "../../notification/services/NotificationEventBuilder";

export type CompleteResponseError = "NOT_FOUND" | "INVALID_STATE";

/**
 * CompleteResponseUseCase — IR Team reports the manually-executed action's
 * real-world result. `executionResult` is opaque, human-supplied evidence
 * (e.g. { hostIsolated: true, tool: "CrowdStrike", notes: "..." }) — this
 * use-case does not interpret or validate its contents; it is a record of
 * what a human did, not a computed outcome.
 */
export class CompleteResponseUseCase {
  constructor(
    private readonly responsePlanRepository: IResponsePlanRepository,
    private readonly auditLogger: AuditLogger,
    private readonly incidentRepository: IIncidentRepository,
    private readonly actionRepository: IActionRepository,
    private readonly contextRepository: IRecommendationContextRepository,
    private readonly notificationDispatcher: INotificationDispatcherPort,
    private readonly vigixBaseUrl: string
  ) {}

  async execute(input: {
    responseId: string;
    tenantId: string;
    completedBy: string;
    executionResult: Record<string, unknown>;
  }): Promise<Result<ResponsePlan, CompleteResponseError>> {
    const response = await this.responsePlanRepository.findById(input.responseId, input.tenantId);
    if (!response) return Result.fail("NOT_FOUND");
    if (response.status !== "IN_PROGRESS") return Result.fail("INVALID_STATE");

    const updated = await this.responsePlanRepository.updateStatus(response.id, input.tenantId, {
      status: "COMPLETED",
      completedAt: new Date(),
      executionResult: input.executionResult,
    });

    await this.responsePlanRepository.recordStepExecution?.(response.id, input.tenantId, { status: "COMPLETED", executedBy: input.completedBy, at: updated.completedAt ?? new Date(), actualResult: JSON.stringify(input.executionResult) });

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.completedBy,
      action: "RESPONSE_COMPLETED",
      entity: "ResponsePlan",
      entityId: response.id,
      metadata: { recommendationId: response.recommendationId, executionResult: input.executionResult },
    });

    try {
      const incident = await this.incidentRepository.findById(updated.incidentId, input.tenantId);
      const action = await this.actionRepository.findById(updated.actionId, input.tenantId);
      if (incident) {
        await this.notificationDispatcher.emit(
          buildResponseCompletedEvent({
            tenantId: input.tenantId,
            baseUrl: this.vigixBaseUrl,
            incident,
            response: updated,
            action,
            // ResponsePlan doesn't itself store sourceRunbookId — resolving it would
            // need an extra Recommendation+step lookup, deliberately not added here to
            // keep this call site's fetch list matching what the contract documented.
            runbook: null,
          })
        );
      }
    } catch (err) {
      console.error("Failed to emit RESPONSE_COMPLETED notification for response plan", updated.id, err);
    }

    return Result.ok(updated);
  }
}
