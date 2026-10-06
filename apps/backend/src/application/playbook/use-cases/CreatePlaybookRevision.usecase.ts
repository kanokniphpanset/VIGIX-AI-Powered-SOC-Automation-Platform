import { IPlaybookRevisionRepository, PlaybookRevisionSummary } from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";
import { parseContent } from "./PlaybookPublication";

/** Roles that maintain playbook content (the existing /api/playbooks management policy). Publishing is narrower. */
export const PLAYBOOK_EDITOR_ROLES = ["SOC", "IR_TEAM", "admin"];

/** `id` is the playbook id: AtomicWorkflow's "playbook" scope locks that playbook row FOR UPDATE before any other statement. */
export interface PlaybookRevisionActorInput {
  tenantId: string;
  id: string;
  actor: { id: string; role?: string; principalType: "HUMAN" | "SERVICE" };
  reason?: string | null;
}

export type CreatePlaybookRevisionError =
  | "SERVICE_PRINCIPAL_FORBIDDEN"
  | "ROLE_FORBIDDEN"
  | "PLAYBOOK_NOT_FOUND"
  | "NOT_PUBLISHED"
  | "DRAFT_EXISTS"
  | "INVALID_REVISION_CONTENT";

/** Next free version: "1.0" → "1.1" (minor bump), anything else → "<v>.1"; skips versions already used by this playbook. */
export function nextVersion(current: string, used: string[]): string {
  const taken = new Set(used);
  const m = /^(\d+)\.(\d+)$/.exec(current);
  let candidate = m ? `${m[1]}.${Number(m[2]) + 1}` : `${current}.1`;
  while (taken.has(candidate)) {
    const n = /^(.*)\.(\d+)$/.exec(candidate)!;
    candidate = `${n[1]}.${Number(n[2]) + 1}`;
  }
  return candidate;
}

/**
 * "Create New Version" (Phase 1D): copies the currently PUBLISHED revision into a new DRAFT (next revision number and
 * version), created by the human actor. The published revision, the pointer and the runtime playbook are not touched;
 * the draft goes live only through PublishPlaybookRevisionUseCase. One open draft per playbook. Must be wrapped with
 * AtomicWorkflow ("playbook" scope).
 */
export class CreatePlaybookRevisionUseCase {
  constructor(private readonly revisions: IPlaybookRevisionRepository, private readonly audit: IPlaybookAuditRecorder) {}

  async execute(input: PlaybookRevisionActorInput): Promise<Result<PlaybookRevisionSummary, CreatePlaybookRevisionError>> {
    const playbook = await this.revisions.lockPlaybook(input.id, input.tenantId);
    if (input.actor.principalType !== "HUMAN") return Result.fail("SERVICE_PRINCIPAL_FORBIDDEN");
    if (!input.actor.role || !PLAYBOOK_EDITOR_ROLES.includes(input.actor.role)) return Result.fail("ROLE_FORBIDDEN");
    if (!playbook) return Result.fail("PLAYBOOK_NOT_FOUND");
    if (!playbook.publishedRevisionId) return Result.fail("NOT_PUBLISHED"); // never published: edit its draft instead

    const all = await this.revisions.listRevisions(playbook.id, input.tenantId);
    if (all.some((r) => r.status === "DRAFT")) return Result.fail("DRAFT_EXISTS");
    const published = all.find((r) => r.id === playbook.publishedRevisionId && r.status === "PUBLISHED");
    const content = published ? parseContent(published.content) : null;
    if (!published || !content) return Result.fail("INVALID_REVISION_CONTENT");

    const version = nextVersion(published.version, all.map((r) => r.version));
    const revisionNumber = Math.max(...all.map((r) => r.revisionNumber)) + 1;
    const draft = await this.revisions.createDraftRevision({
      tenantId: input.tenantId, playbookId: playbook.id, revisionNumber, version, content: { ...content, version },
      createdBy: input.actor.id, proposalReason: input.reason ?? null,
    });
    await this.audit.record({
      tenantId: input.tenantId,
      actor: input.actor.id,
      action: "PLAYBOOK_REVISION_CREATED",
      entity: "PlaybookRevision",
      entityId: draft.id,
      metadata: {
        playbookId: playbook.id, revisionId: draft.id, revisionNumber, version, copiedFrom: published.id, copiedFromVersion: published.version,
        reason: input.reason ?? null, actor: input.actor.id, principalType: input.actor.principalType, after: { status: "DRAFT" },
      },
    });
    return Result.ok(draft);
  }
}
