import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";

export class GetActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Action, "NOT_FOUND">> {
    const action = await this.actionRepository.findById(input.id, input.tenantId);
    if (!action) return Result.fail("NOT_FOUND");
    return Result.ok(action);
  }
}
