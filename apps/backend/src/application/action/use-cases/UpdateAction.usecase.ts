import { IActionRepository, ActionRunbookRelationshipError, ActionRunbookErrorCode } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";
import { UpdateActionDto } from "../dto/ActionDto";
import { ActionGovernanceErrorCode, canUpdateGovernance } from "./ActionGovernance";

export interface UpdateActionInput extends UpdateActionDto {
  id: string;
  tenantId: string;
  /** Role of the authenticated human; only admin may change impactLevel / defaultApprovalRequired. */
  actorRole: string;
}

export class UpdateActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: UpdateActionInput): Promise<Result<Action, "NOT_FOUND" | ActionRunbookErrorCode | ActionGovernanceErrorCode>> {
    const existing = await this.actionRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");
    if (!canUpdateGovernance(input.actorRole, existing, input)) return Result.fail("ACTION_GOVERNANCE_FIELD_FORBIDDEN");

    try {
      const updated = await this.actionRepository.update(input.id, input.tenantId, {
        name: input.name,
        description: input.description,
        impactLevel: input.impactLevel,
        defaultApprovalRequired: input.defaultApprovalRequired,
        runbookId: input.runbookId,
      });
      return Result.ok(updated);
    } catch (error) {
      if (error instanceof ActionRunbookRelationshipError) return Result.fail(error.code);
      throw error;
    }
  }
}
