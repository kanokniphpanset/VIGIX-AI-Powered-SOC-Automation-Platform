import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";

export class DisableActionUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Action, "NOT_FOUND">> {
    const existing = await this.actionRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");
    return Result.ok(await this.actionRepository.setEnabled(input.id, input.tenantId, false));
  }
}
