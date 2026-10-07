import {
  IPlaybookRevisionRepository,
  PlaybookContent,
  PlaybookProjection,
  PlaybookRevisionRecord,
} from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";
import { IPlaybookPublicationListener } from "../ports/IPlaybookPublicationListener";

/** `id` is the playbook id: AtomicWorkflow's "playbook" scope locks that playbook row FOR UPDATE before any other statement. */
export interface PlaybookPublicationInput {
  tenantId: string;
  id: string;
  revisionId: string;
  actor: { id: string; role?: string; principalType: "HUMAN" | "SERVICE" };
  reason?: string | null;
}

export type PlaybookPublicationError =
  | "SERVICE_PRINCIPAL_FORBIDDEN"
  | "ROLE_FORBIDDEN"
  | "PLAYBOOK_NOT_FOUND"
  | "REVISION_NOT_FOUND"
  | "REVISION_PLAYBOOK_MISMATCH"
  | "INVALID_REVISION_STATUS"
  | "ALREADY_PUBLISHED"
  | "NEVER_PUBLISHED"
  | "NO_PUBLISHED_REVISION"
  | "INVALID_REVISION_CONTENT"
  | "PLAYBOOK_CODE_MISMATCH"
  | "PROJECTION_MISMATCH";

export interface PlaybookPublicationResult {
  playbookId: string;
  revisionId: string;
  /** null for the first publish of a playbook created as a DRAFT. */
  previousRevisionId: string | null;
  version: string;
  publishedBy: string;
  publishedAt: Date;
}

type Kind = "PUBLISH" | "ROLLBACK";
/** SOC and IR_TEAM maintain playbooks and publish / roll back directly (no approval step; admin is not a publisher). */
export const PLAYBOOK_PUBLISHER_ROLES = ["SOC", "IR_TEAM"];

/**
 * Shared publish / rollback flow (Phase 1D). Publish takes a DRAFT revision live directly (no review / approval step);
 * rollback re-publishes a previously published (SUPERSEDED) revision. PlaybookRevision.content is the source of truth; playbooks + playbook_steps
 * are its runtime projection (read by PlaybookSelector / RecommendationValidator), rewritten here and verified field by
 * field. Runs inside AtomicWorkflow: any failure after a write rolls the whole transaction back (revision states,
 * pointer, projection and audit), and SET CONSTRAINTS ALL IMMEDIATE is the last statement so a publication-invariant
 * violation surfaces to the caller instead of being lost at COMMIT.
 */
export class PlaybookPublication {
  constructor(
    private readonly revisions: IPlaybookRevisionRepository,
    private readonly audit: IPlaybookAuditRecorder,
    private readonly listener?: IPlaybookPublicationListener
  ) {}

  async run(kind: Kind, input: PlaybookPublicationInput): Promise<Result<PlaybookPublicationResult, PlaybookPublicationError>> {
    // Re-reads the row locked by AtomicWorkflow (same transaction), scoped to the trusted tenant.
    const playbook = await this.revisions.lockPlaybook(input.id, input.tenantId);
    if (input.actor.principalType !== "HUMAN") return Result.fail("SERVICE_PRINCIPAL_FORBIDDEN");
    if (!input.actor.role || !PLAYBOOK_PUBLISHER_ROLES.includes(input.actor.role)) return Result.fail("ROLE_FORBIDDEN");
    if (!playbook) return Result.fail("PLAYBOOK_NOT_FOUND");

    const target = await this.revisions.findRevision(input.revisionId, input.tenantId);
    if (!target) return Result.fail("REVISION_NOT_FOUND");
    if (target.playbookId !== playbook.id) return Result.fail("REVISION_PLAYBOOK_MISMATCH");

    if (kind === "PUBLISH") {
      if (target.status === "PUBLISHED") return Result.fail("ALREADY_PUBLISHED");
      // Only a DRAFT goes live; legacy IN_REVIEW / APPROVED / REJECTED rows from the removed approval flow never do.
      if (target.status !== "DRAFT") return Result.fail("INVALID_REVISION_STATUS");
    } else {
      if (target.status !== "SUPERSEDED") return Result.fail("INVALID_REVISION_STATUS");
      if (!target.publishedAt) return Result.fail("NEVER_PUBLISHED");
    }

    // First publish (a playbook created as a DRAFT has no pointer): nothing to supersede. Rollback always needs a current one.
    const current = playbook.publishedRevisionId ? await this.revisions.findRevision(playbook.publishedRevisionId, input.tenantId) : null;
    if (playbook.publishedRevisionId && (!current || current.status !== "PUBLISHED" || current.playbookId !== playbook.id)) return Result.fail("NO_PUBLISHED_REVISION");
    if (!current && kind === "ROLLBACK") return Result.fail("NO_PUBLISHED_REVISION");

    const content = parseContent(target.content);
    if (!content) return Result.fail("INVALID_REVISION_CONTENT");
    if (content.code !== playbook.code) return Result.fail("PLAYBOOK_CODE_MISMATCH");

    const publishedAt = new Date();
    if (current) await this.revisions.markSuperseded(current.id);
    await this.revisions.markPublished(target.id, input.actor.id, publishedAt);
    await this.revisions.setPublishedPointer(playbook.id, target.id);
    await this.revisions.projectContent(playbook.id, target.version, content);

    // Returning a failure after these writes makes AtomicWorkflow roll everything back.
    const projection = await this.revisions.readProjection(playbook.id);
    if (!projectionMatches(projection, content, target.version, playbook.code)) return Result.fail("PROJECTION_MISMATCH");

    const meta = { playbookId: playbook.id, reason: input.reason ?? null, actor: input.actor.id, principalType: input.actor.principalType };
    if (current) {
      await this.audit.record({
        tenantId: input.tenantId,
        actor: input.actor.id,
        action: "PLAYBOOK_REVISION_SUPERSEDED",
        entity: "PlaybookRevision",
        entityId: current.id,
        metadata: {
          ...meta, revisionId: current.id, version: current.version, supersededBy: target.id,
          before: state(current, current.id), after: { status: "SUPERSEDED", publishedBy: current.publishedBy, publishedAt: current.publishedAt, publishedRevisionId: target.id },
        },
      });
    }
    const previousRevisionId = current?.id ?? null;
    await this.audit.record({
      tenantId: input.tenantId,
      actor: input.actor.id,
      action: kind === "PUBLISH" ? "PLAYBOOK_REVISION_PUBLISHED" : "PLAYBOOK_REVISION_ROLLED_BACK",
      entity: "PlaybookRevision",
      entityId: target.id,
      metadata: {
        ...meta, revisionId: target.id, version: target.version, previousRevisionId,
        before: state(target, previousRevisionId), after: { status: "PUBLISHED", publishedBy: input.actor.id, publishedAt, publishedRevisionId: target.id },
      },
    });

    await this.listener?.published({
      tenantId: input.tenantId, playbookId: playbook.id, revisionId: target.id, previousRevisionId, version: target.version, kind, actor: input.actor.id,
    });
    await this.revisions.assertPublicationConsistent();
    return Result.ok({ playbookId: playbook.id, revisionId: target.id, previousRevisionId, version: target.version, publishedBy: input.actor.id, publishedAt });
  }
}

function state(r: PlaybookRevisionRecord, publishedRevisionId: string | null) {
  return { status: r.status, publishedBy: r.publishedBy, publishedAt: r.publishedAt, publishedRevisionId };
}

const isString = (v: unknown): v is string => typeof v === "string";
const isNullableString = (v: unknown): v is string | null => v === null || typeof v === "string";

/** Validates a stored revision content (shape, at least one step, titled, unique step order); steps come back sorted. */
export function parseContent(raw: unknown): PlaybookContent | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const c = raw as Record<string, unknown>;
  if (!isNullableString(c.code) || !isString(c.name) || !isNullableString(c.description) || !isNullableString(c.n8nWorkflowId) ||
      !isNullableString(c.playbookStatus) || !isNullableString(c.version)) return null;
  if (!c.triggerConditions || typeof c.triggerConditions !== "object" || Array.isArray(c.triggerConditions)) return null;
  if (!Array.isArray(c.steps)) return null;
  const steps = [];
  for (const s of c.steps as unknown[]) {
    const step = s as Record<string, unknown> | null;
    if (!step || !Number.isInteger(step.stepOrder) || !isString(step.title) || !step.title.trim() || !isNullableString(step.description)) return null;
    steps.push({ stepOrder: step.stepOrder as number, title: step.title, description: step.description });
  }
  if (!steps.length || new Set(steps.map((s) => s.stepOrder)).size !== steps.length) return null;
  steps.sort((a, b) => a.stepOrder - b.stepOrder);
  return {
    code: c.code, name: c.name, description: c.description, triggerConditions: c.triggerConditions as Record<string, unknown>,
    n8nWorkflowId: c.n8nWorkflowId, playbookStatus: c.playbookStatus, version: c.version, steps,
  };
}

/** Key-order independent JSON (jsonb does not keep key order). */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

function projectionMatches(p: PlaybookProjection, c: PlaybookContent, version: string, code: string | null): boolean {
  return p.code === code && p.code === c.code &&
    p.name === c.name && p.description === c.description && p.n8nWorkflowId === c.n8nWorkflowId && p.status === c.playbookStatus &&
    p.version === version &&
    canonical(p.triggerConditions) === canonical(c.triggerConditions) &&
    canonical(p.steps) === canonical(c.steps);
}
