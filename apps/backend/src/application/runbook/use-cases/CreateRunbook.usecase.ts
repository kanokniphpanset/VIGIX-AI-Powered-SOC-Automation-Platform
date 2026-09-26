import { IRunbookRepository } from "../../../domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../../domain/runbook/entities/Runbook.entity";
import { Result } from "../../../shared/result/Result";
import { CreateRunbookDto } from "../dto/RunbookDto";

export interface CreateRunbookInput extends CreateRunbookDto {
  tenantId: string;
}

export class CreateRunbookUseCase {
  constructor(private readonly runbookRepository: IRunbookRepository) {}

  async execute(input: CreateRunbookInput): Promise<Result<Runbook, "DUPLICATE_CODE">> {
    const existing = await this.runbookRepository.findByCode(input.code, input.tenantId);
    if (existing) return Result.fail("DUPLICATE_CODE");

    const runbook = await this.runbookRepository.create({
      tenantId: input.tenantId,
      code: input.code,
      name: input.name,
      version: input.version,
      description: input.description ?? null,
      trigger: input.trigger ?? null,
      preconditions: input.preconditions,
      objective: input.objective ?? null,
      procedure: input.procedure,
      decisionPoints: input.decisionPoints,
      expectedResult: input.expectedResult ?? null,
      escalation: input.escalation ?? null,
      verificationCriteria: input.verificationCriteria,
    });
    return Result.ok(runbook);
  }
}
