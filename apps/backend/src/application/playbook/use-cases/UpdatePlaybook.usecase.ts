import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { Result } from "../../../shared/result/Result";
import { UpdatePlaybookDto } from "../dto/PlaybookDto";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";

/**
 * Edits a Playbook in place. It only affects FUTURE recommendations: each recommendation already recorded its own
 * playbook snapshot and steps, which are never rewritten here. A status change is audited as ACTIVATE/DEACTIVATE,
 * any other change as UPDATE_PLAYBOOK.
 */
export class UpdatePlaybookUseCase {
  constructor(
    private readonly playbookRepository: IPlaybookRepository,
    private readonly audit?: IPlaybookAuditRecorder
  ) {}

  async execute(input: UpdatePlaybookDto & { id: string; tenantId: string; actor?: string }): Promise<Result<Playbook, "NOT_FOUND">> {
    const existing = await this.playbookRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");
    const { id, tenantId, actor, ...data } = input;
    const playbook = await this.playbookRepository.update(id, tenantId, {
      ...data,
      steps: data.steps?.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description ?? null })),
    });

    const statusChanged = data.status !== undefined && data.status !== existing.status;
    const { status: _status, ...otherFields } = data;
    const changedFields = Object.keys(otherFields).filter((k) => otherFields[k as keyof typeof otherFields] !== undefined);
    const base = { tenantId, actor: actor ?? "system", entity: "Playbook" as const, entityId: id };
    if (changedFields.length) {
      await this.audit?.record({
        ...base,
        action: "UPDATE_PLAYBOOK",
        metadata: { code: playbook.code, name: playbook.name, fields: changedFields, stepCount: playbook.steps.length },
      });
    }
    if (statusChanged) {
      await this.audit?.record({
        ...base,
        action: playbook.status === "ACTIVE" ? "ACTIVATE_PLAYBOOK" : "DEACTIVATE_PLAYBOOK",
        metadata: { code: playbook.code, name: playbook.name, from: existing.status, to: playbook.status },
      });
    }
    return Result.ok(playbook);
  }
}
