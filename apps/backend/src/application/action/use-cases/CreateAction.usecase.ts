import { IActionRepository, ActionRunbookRelationshipError, ActionRunbookErrorCode } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";
import { CreateActionDto } from "../dto/ActionDto";
import { ActionGovernanceErrorCode, canCreateWithGovernance } from "./ActionGovernance";

export interface CreateActionInput extends CreateActionDto {
  tenantId: string;
  /** Role of the authenticated human; governs impactLevel / defaultApprovalRequired (see ActionGovernance). */
  actorRole: string;
}

export class CreateActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: CreateActionInput): Promise<Result<Action, "DUPLICATE_CODE" | ActionRunbookErrorCode | ActionGovernanceErrorCode>> {
    if (!canCreateWithGovernance(input.actorRole, input)) return Result.fail("ACTION_GOVERNANCE_FIELD_FORBIDDEN");
    const existing = await this.actionRepository.findByCode(input.code, input.tenantId);
    if (existing) return Result.fail("DUPLICATE_CODE");

    try {
      const action = await this.actionRepository.create({
        tenantId: input.tenantId,
        code: input.code,
        name: input.name,
        description: input.description ?? null,
        category: input.category,
        impactLevel: input.impactLevel,
        defaultApprovalRequired: input.defaultApprovalRequired,
        runbookId: input.runbookId ?? null,
      });
      return Result.ok(action);
    } catch (error) {
      if (error instanceof ActionRunbookRelationshipError) return Result.fail(error.code);
      throw error;
    }
  }
}
