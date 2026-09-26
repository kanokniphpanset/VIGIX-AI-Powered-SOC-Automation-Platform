import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../../domain/runbook/entities/Runbook.entity";

export class ListRunbooksUseCase {
  constructor(private readonly runbookRepository: IRunbookRepository) {}

  async execute(input: { tenantId: string }): Promise<Runbook[]> {
    return this.runbookRepository.findAll(input.tenantId);
  }
}
