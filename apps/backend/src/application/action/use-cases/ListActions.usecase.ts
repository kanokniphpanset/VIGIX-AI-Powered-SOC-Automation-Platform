import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";

export class ListActionsUseCase {
  constructor(private readonly actionRepository: IActionRepository) {}

  async execute(input: { tenantId: string }): Promise<Action[]> {
    return this.actionRepository.findAll(input.tenantId);
  }
}
