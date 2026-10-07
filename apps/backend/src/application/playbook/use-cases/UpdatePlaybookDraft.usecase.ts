import { IPlaybookRevisionRepository, PlaybookContent } from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";
import { UpdatePlaybookDto } from "../dto/PlaybookDto";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";
import { PLAYBOOK_EDITOR_ROLES, PlaybookRevisionActorInput } from "./CreatePlaybookRevision.usecase";
import { parseContent } from "./PlaybookPublication";

export type UpdatePlaybookDraftError =
  | "SERVICE_PRINCIPAL_FORBIDDEN"
  | "ROLE_FORBIDDEN"
  | "PLAYBOOK_NOT_FOUND"
  | "REVISION_NOT_FOUND"
  | "REVISION_PLAYBOOK_MISMATCH"
  | "INVALID_REVISION_STATUS"
  | "INVALID_REVISION_CONTENT"
  | "VERSION_EXISTS";

/**
 * Edits a DRAFT revision (Phase 1D). Same fields as the playbook edit form; `status` is the status the playbook takes
 * once this draft is published. The code never changes. For a playbook that was never published, its DRAFT row mirrors
 * the draft (status stays DRAFT, never selectable); for a published playbook the live runtime, the published revision
 * and the pointer are untouched. Must be wrapped with AtomicWorkflow ("playbook" scope).
 */
export class UpdatePlaybookDraftUseCase {
  constructor(private readonly revisions: IPlaybookRevisionRepository, private readonly audit: IPlaybookAuditRecorder) {}

  async execute(input: PlaybookRevisionActorInput & { revisionId: string; changes: UpdatePlaybookDto }): Promise<Result<{ revisionId: string; version: string; content: PlaybookContent }, UpdatePlaybookDraftError>> {
    const playbook = await this.revisions.lockPlaybook(input.id, input.tenantId);
    if (input.actor.principalType !== "HUMAN") return Result.fail("SERVICE_PRINCIPAL_FORBIDDEN");
    if (!input.actor.role || !PLAYBOOK_EDITOR_ROLES.includes(input.actor.role)) return Result.fail("ROLE_FORBIDDEN");
    if (!playbook) return Result.fail("PLAYBOOK_NOT_FOUND");
    const revision = await this.revisions.findRevision(input.revisionId, input.tenantId);
    if (!revision) return Result.fail("REVISION_NOT_FOUND");
    if (revision.playbookId !== playbook.id) return Result.fail("REVISION_PLAYBOOK_MISMATCH");
    if (revision.status !== "DRAFT") return Result.fail("INVALID_REVISION_STATUS");
    const current = parseContent(revision.content);
    if (!current) return Result.fail("INVALID_REVISION_CONTENT");

    const c = input.changes;
    // incidentType lives inside triggerConditions: merge it, never drop scope / mitreTechniques / allowedActions.
    const triggerConditions = { ...current.triggerConditions };
    if (c.incidentType !== undefined) {
      if (c.incidentType) triggerConditions.incidentType = c.incidentType;
      else delete triggerConditions.incidentType;
    }
    const version = c.version !== undefined && c.version !== null && c.version.trim() ? c.version.trim() : revision.version;
    if (version !== revision.version) {
      const used = (await this.revisions.listRevisions(playbook.id, input.tenantId)).filter((r) => r.id !== revision.id).map((r) => r.version);
      if (used.includes(version)) return Result.fail("VERSION_EXISTS");
    }
    const next: PlaybookContent = {
      ...current,
      name: c.name ?? current.name,
      description: c.description !== undefined ? c.description : current.description,
      triggerConditions,
      playbookStatus: c.status ?? current.playbookStatus,
      version,
      steps: c.steps
        ? [...c.steps].sort((a, b) => a.stepOrder - b.stepOrder).map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description ?? null }))
        : current.steps,
    };
    if (!(await this.revisions.updateDraftContent(revision.id, version, next))) return Result.fail("INVALID_REVISION_STATUS");
    if (!playbook.publishedRevisionId) await this.revisions.projectContent(playbook.id, version, next, "DRAFT");

    await this.audit.record({
      tenantId: input.tenantId,
      actor: input.actor.id,
      action: "PLAYBOOK_REVISION_UPDATED",
      entity: "PlaybookRevision",
      entityId: revision.id,
      metadata: {
        playbookId: playbook.id, revisionId: revision.id, version, fields: Object.keys(c).filter((k) => c[k as keyof UpdatePlaybookDto] !== undefined),
        reason: input.reason ?? null, actor: input.actor.id, principalType: input.actor.principalType,
        before: { version: revision.version, content: current }, after: { version, content: next },
      },
    });
    return Result.ok({ revisionId: revision.id, version, content: next });
  }
}
