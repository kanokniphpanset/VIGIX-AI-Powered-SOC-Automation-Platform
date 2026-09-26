import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../../domain/runbook/entities/Runbook.entity";
import { Result } from "../../../shared/result/Result";

export class GetRunbookUseCase {
  constructor(private readonly runbookRepository: IRunbookRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Runbook, "NOT_FOUND">> {
    const runbook = await this.runbookRepository.findById(input.id, input.tenantId);
    if (!runbook) return Result.fail("NOT_FOUND");
    return Result.ok(runbook);
  }
}
