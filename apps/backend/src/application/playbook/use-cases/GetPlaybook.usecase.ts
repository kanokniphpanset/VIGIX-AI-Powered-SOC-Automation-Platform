import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { Result } from "../../../shared/result/Result";

export class GetPlaybookUseCase {
  constructor(private readonly playbookRepository: IPlaybookRepository) {}

  async execute(input: { id: string; tenantId: string }): Promise<Result<Playbook, "NOT_FOUND">> {
    const playbook = await this.playbookRepository.findById(input.id, input.tenantId);
    if (!playbook) return Result.fail("NOT_FOUND");
    return Result.ok(playbook);
  }
}
