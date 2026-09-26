import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { Result } from "../../../shared/result/Result";
import { CreatePlaybookDto } from "../dto/PlaybookDto";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";

export class CreatePlaybookUseCase {
  constructor(
    private readonly playbookRepository: IPlaybookRepository,
    private readonly audit?: IPlaybookAuditRecorder
  ) {}

  async execute(input: CreatePlaybookDto & { tenantId: string; actor?: string }): Promise<Result<Playbook, "DUPLICATE_CODE">> {
    if (input.code) {
      const existing = await this.playbookRepository.findByCode(input.code, input.tenantId);
      if (existing) return Result.fail("DUPLICATE_CODE");
    }
    const playbook = await this.playbookRepository.create({
      tenantId: input.tenantId,
      code: input.code ?? null,
      name: input.name,
      description: input.description ?? null,
      version: input.version ?? "1.0",
      status: input.status ?? "ACTIVE",
      incidentType: input.incidentType ?? null,
      steps: input.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description ?? null })),
    });
    await this.audit?.record({
      tenantId: input.tenantId,
      actor: input.actor ?? "system",
      action: "CREATE_PLAYBOOK",
      entity: "Playbook",
      entityId: playbook.id,
      metadata: { code: playbook.code, name: playbook.name, status: playbook.status, version: playbook.version, stepCount: playbook.steps.length },
    });
    return Result.ok(playbook);
  }
}
