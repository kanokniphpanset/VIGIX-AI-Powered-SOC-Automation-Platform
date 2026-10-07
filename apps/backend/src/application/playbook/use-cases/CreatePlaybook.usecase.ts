import { IPlaybookRepository, CreatedPlaybookRevision } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { Result } from "../../../shared/result/Result";
import { CreatePlaybookDto } from "../dto/PlaybookDto";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";

/**
 * Creates a playbook as a DRAFT (Phase 1D): the playbooks row (status DRAFT, no published revision, never selectable)
 * and revision 1 (DRAFT, created by the actor) in one transaction. The requested status is what the playbook takes once
 * that revision is submitted, approved and published; nothing is submitted, approved or published here.
 */
export class CreatePlaybookUseCase {
  constructor(
    private readonly playbookRepository: IPlaybookRepository,
    private readonly audit?: IPlaybookAuditRecorder
  ) {}

  async execute(input: CreatePlaybookDto & { tenantId: string; actor?: string }): Promise<Result<{ playbook: Playbook; revision: CreatedPlaybookRevision }, "DUPLICATE_CODE">> {
    if (input.code) {
      const existing = await this.playbookRepository.findByCode(input.code, input.tenantId);
      if (existing) return Result.fail("DUPLICATE_CODE");
    }
    const actor = input.actor ?? "system";
    const { playbook, revision } = await this.playbookRepository.createDraft({
      tenantId: input.tenantId,
      code: input.code ?? null,
      name: input.name,
      description: input.description ?? null,
      version: input.version ?? "1.0",
      publishedStatus: input.status ?? "ACTIVE",
      incidentType: input.incidentType ?? null,
      steps: input.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description ?? null })),
      createdBy: actor,
    });
    await this.audit?.record({
      tenantId: input.tenantId,
      actor,
      action: "CREATE_PLAYBOOK",
      entity: "Playbook",
      entityId: playbook.id,
      metadata: {
        code: playbook.code, name: playbook.name, status: playbook.status, version: playbook.version, stepCount: playbook.steps.length,
        revisionId: revision.id, revisionNumber: revision.revisionNumber, revisionStatus: revision.status, publishedStatus: input.status ?? "ACTIVE",
      },
    });
    return Result.ok({ playbook, revision });
  }
}
