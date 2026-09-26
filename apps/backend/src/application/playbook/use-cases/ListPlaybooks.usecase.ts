import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";

export class ListPlaybooksUseCase {
  constructor(private readonly playbookRepository: IPlaybookRepository) {}

  async execute(input: { tenantId: string }): Promise<Playbook[]> {
    return this.playbookRepository.findAll(input.tenantId);
  }
}
