import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";
import { CreateActionDto } from "../dto/ActionDto";

export interface CreateActionInput extends CreateActionDto {
  tenantId: string;
}

export class CreateActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: CreateActionInput): Promise<Result<Action, "DUPLICATE_CODE">> {
    const existing = await this.actionRepository.findByCode(input.code, input.tenantId);
    if (existing) return Result.fail("DUPLICATE_CODE");

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
  }
}
