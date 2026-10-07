import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { Result } from "../../../shared/result/Result";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";

/**
 * Removes a Playbook and its steps (Knowledge → Playbooks). Only FUTURE recommendations are affected: every existing
 * recommendation keeps its own playbook snapshot (code / version / steps), which references the playbook by code, not by
 * a foreign key. A playbook referenced by a playbook execution cannot be deleted (IN_USE). The full playbook is copied
 * into the audit record (with the reason, if one was given), so it can be recreated if it was deleted by mistake.
 * Phase 1D: a playbook that is or was published keeps its revision history and is never deleted (REVISION_HISTORY_EXISTS,
 * nothing written or audited). A never-published playbook (only DRAFT revisions) is deleted with its drafts, whose
 * contents are copied into the audit record.
 */
export class DeletePlaybookUseCase {
  constructor(
    private readonly playbookRepository: IPlaybookRepository,
    private readonly audit?: IPlaybookAuditRecorder
  ) {}

  async execute(input: { id: string; tenantId: string; actor?: string; reason?: string | null }): Promise<Result<{ id: string; code: string | null }, "NOT_FOUND" | "IN_USE" | "REVISION_HISTORY_EXISTS">> {
    const existing = await this.playbookRepository.findById(input.id, input.tenantId);
    if (!existing) return Result.fail("NOT_FOUND");
    if ((await this.playbookRepository.countExecutions(input.id)) > 0) return Result.fail("IN_USE");
    const revisions = await this.playbookRepository.revisionState(input.id, input.tenantId);
    if (revisions && (revisions.publishedRevisionId || revisions.historyCount > 0)) return Result.fail("REVISION_HISTORY_EXISTS");

    await this.playbookRepository.delete(input.id, input.tenantId);
    await this.audit?.record({
      tenantId: input.tenantId,
      actor: input.actor ?? "system",
      action: "DELETE_PLAYBOOK",
      entity: "Playbook",
      entityId: input.id,
      metadata: { code: existing.code, name: existing.name, reason: input.reason ?? null, snapshot: existing.toJSON(), draftRevisions: revisions?.revisionCount ?? 0 },
    });
    return Result.ok({ id: input.id, code: existing.code });
  }
}
