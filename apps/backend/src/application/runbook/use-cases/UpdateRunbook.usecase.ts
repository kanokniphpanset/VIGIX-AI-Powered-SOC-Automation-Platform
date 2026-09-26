import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../../domain/runbook/entities/Runbook.entity";
import { Result } from "../../../shared/result/Result";
import { UpdateRunbookDto } from "../dto/RunbookDto";

export interface UpdateRunbookInput extends UpdateRunbookDto {
  id: string;
  tenantId: string;
}

export class UpdateRunbookUseCase {
  constructor(private readonly runbookRepository: IRunbookRepository) {}

  async execute(input: UpdateRunbookInput): Promise<Result<Runbook, "NOT_FOUND">> {
    const existing = await this.runbookRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");

    const updated = await this.runbookRepository.update(input.id, input.tenantId, {
      name: input.name,
      version: input.version,
      status: input.status,
      description: input.description,
      trigger: input.trigger,
      preconditions: input.preconditions,
      objective: input.objective,
      procedure: input.procedure,
      decisionPoints: input.decisionPoints,
      expectedResult: input.expectedResult,
      escalation: input.escalation,
      verificationCriteria: input.verificationCriteria,
    });
    return Result.ok(updated);
  }
}
