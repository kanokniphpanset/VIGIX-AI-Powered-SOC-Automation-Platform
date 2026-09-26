import { Action as PrismaAction } from "@prisma/client";
import { Action } from "../../../../domain/action/entities/Action.entity";
import { ActionCategory, ActionImpactLevel } from "../../../../domain/action/entities/Action.entity";

export class ActionMapper {
  static toDomain(raw: PrismaAction): Action {
    return Action.create({
      id: raw.id,
      tenantId: raw.tenantId,
      code: raw.code,
      name: raw.name,
      description: raw.description,
      category: raw.category as ActionCategory,
      enabled: raw.enabled,
      impactLevel: raw.impactLevel as ActionImpactLevel,
      defaultApprovalRequired: raw.defaultApprovalRequired,
      runbookId: raw.runbookId,
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  }
}
