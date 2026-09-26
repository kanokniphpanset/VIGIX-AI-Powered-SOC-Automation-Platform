import { ResponsePlan as PrismaResponsePlan } from "@prisma/client";
import {
  ResponsePlan,
  ResponseApprovalStatus,
  ResponseStatus,
} from "../../../../domain/response/entities/ResponsePlan.entity";

export class ResponsePlanMapper {
  static toDomain(raw: PrismaResponsePlan): ResponsePlan {
    if (!raw.actionId) {
      throw new Error(
        `ResponsePlan ${raw.id} has no actionId and cannot be mapped to the domain`
      );
    }

    return ResponsePlan.create({
      id: raw.id,
      tenantId: raw.tenantId,
      incidentId: raw.incidentId,
      recommendationId: raw.recommendationId,
      recommendationStepId: raw.recommendationStepId ?? null,
      actionId: raw.actionId,
      target: raw.target,
      reason: raw.reason,
      expectedResult: raw.expectedResult,
      approvalStatus: raw.approvalStatus as ResponseApprovalStatus,
      assignedRole: raw.assignedRole,
      assignedTo: raw.assignedTo,
      status: raw.status as ResponseStatus,
      executionResult:
        (raw.executionResult as Record<string, unknown> | null) ?? null,
      executedAt: raw.executedAt,
      completedAt: raw.completedAt,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  }
}