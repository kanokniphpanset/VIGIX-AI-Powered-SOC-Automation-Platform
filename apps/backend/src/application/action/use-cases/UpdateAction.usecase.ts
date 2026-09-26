import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";
import { UpdateActionDto } from "../dto/ActionDto";

export interface UpdateActionInput extends UpdateActionDto {
  id: string;
  tenantId: string;
}

export class UpdateActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: UpdateActionInput): Promise<Result<Action, "NOT_FOUND">> {
    const existing = await this.actionRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");

    const updated = await this.actionRepository.update(input.id, input.tenantId, {
      name: input.name,
      description: input.description,
      impactLevel: input.impactLevel,
      defaultApprovalRequired: input.defaultApprovalRequired,
      runbookId: input.runbookId,
    });
    return Result.ok(updated);
  }
}
