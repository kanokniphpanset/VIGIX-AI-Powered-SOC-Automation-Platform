import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { Result } from "../../../shared/result/Result";
import { UpdatePlaybookDto } from "../dto/PlaybookDto";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";

/**
 * Edits a Playbook in place. It only affects FUTURE recommendations: each recommendation already recorded its own
 * playbook snapshot and steps, which are never rewritten here. A status change is audited as ACTIVATE/DEACTIVATE,
 * any other change as UPDATE_PLAYBOOK. A published playbook (Phase 1D) is the projection of its published revision:
 * it is never edited here (PUBLISHED_IMMUTABLE, nothing written or audited); changes go through a new revision.
 * A not-yet-published playbook with revisions (created as a DRAFT) is governed by its revision too
 * (REVISION_MANAGED): editing the row here could activate it or make it drift from the revision under review.
 */
export class UpdatePlaybookUseCase {
  constructor(
    private readonly playbookRepository: IPlaybookRepository,
    private readonly audit?: IPlaybookAuditRecorder
  ) {}

  async execute(input: UpdatePlaybookDto & { id: string; tenantId: string; actor?: string }): Promise<Result<Playbook, "NOT_FOUND" | "PUBLISHED_IMMUTABLE" | "REVISION_MANAGED">> {
    const existing = await this.playbookRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");
    const revisions = await this.playbookRepository.revisionState(input.id, input.tenantId);
    if (revisions?.publishedRevisionId) return Result.fail("PUBLISHED_IMMUTABLE");
    if (revisions && revisions.revisionCount > 0) return Result.fail("REVISION_MANAGED");
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
