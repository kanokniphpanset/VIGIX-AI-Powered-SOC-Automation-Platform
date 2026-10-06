import { Request, Response } from "express";
import { z } from "zod";
import { authenticatedTenant } from "../middlewares/auth.middleware";
import { validateBody } from "../validators/validateBody";
import { updatePlaybookSchema } from "../../../application/playbook/dto/PlaybookDto";
import { ListPlaybookRevisionsUseCase } from "../../../application/playbook/use-cases/ListPlaybookRevisions.usecase";
import { CreatePlaybookRevisionUseCase } from "../../../application/playbook/use-cases/CreatePlaybookRevision.usecase";
import { UpdatePlaybookDraftUseCase } from "../../../application/playbook/use-cases/UpdatePlaybookDraft.usecase";
import { PublishPlaybookRevisionUseCase } from "../../../application/playbook/use-cases/PublishPlaybookRevision.usecase";
import { RollbackPlaybookRevisionUseCase } from "../../../application/playbook/use-cases/RollbackPlaybookRevision.usecase";

const reasonSchema = z.object({ reason: z.string().trim().max(2000).optional() }).strict();

/** Use-case errors → HTTP. Internal states (pointer, SUPERSEDED, projection) are never exposed as such. */
const ERRORS: Record<string, [number, string]> = {
  SERVICE_PRINCIPAL_FORBIDDEN: [403, "SERVICE_PRINCIPAL_FORBIDDEN"],
  ROLE_FORBIDDEN: [403, "FORBIDDEN"],
  NOT_FOUND: [404, "PLAYBOOK_NOT_FOUND"],
  PLAYBOOK_NOT_FOUND: [404, "PLAYBOOK_NOT_FOUND"],
  REVISION_NOT_FOUND: [404, "PLAYBOOK_REVISION_NOT_FOUND"],
  REVISION_PLAYBOOK_MISMATCH: [404, "PLAYBOOK_REVISION_NOT_FOUND"],
  INVALID_REVISION_STATUS: [409, "INVALID_REVISION_TRANSITION"],
  ALREADY_PUBLISHED: [409, "INVALID_REVISION_TRANSITION"],
  NEVER_PUBLISHED: [409, "INVALID_REVISION_TRANSITION"],
  NO_PUBLISHED_REVISION: [409, "INVALID_REVISION_TRANSITION"],
  NOT_PUBLISHED: [409, "INVALID_REVISION_TRANSITION"],
  DRAFT_EXISTS: [409, "PLAYBOOK_DRAFT_EXISTS"],
  VERSION_EXISTS: [409, "PLAYBOOK_VERSION_EXISTS"],
  INVALID_REVISION_CONTENT: [422, "PLAYBOOK_REVISION_INVALID"],
  PLAYBOOK_CODE_MISMATCH: [422, "PLAYBOOK_REVISION_INVALID"],
  PROJECTION_MISMATCH: [422, "PLAYBOOK_REVISION_INVALID"],
};
function fail(res: Response, error: string): void {
  const [status, code] = ERRORS[error] ?? [409, "INVALID_REVISION_TRANSITION"];
  res.status(status).json({ error: code, reason: error });
}

/**
 * Playbook versions (Phase 1D), mounted under /api/playbooks/:id/revisions. Tenant and actor come from the verified
 * JWT; every mutation runs in an AtomicWorkflow-wrapped use case (playbook row locked, audited in the same transaction).
 */
export class PlaybookRevisionController {
  constructor(
    private readonly listRevisions: ListPlaybookRevisionsUseCase,
    private readonly createRevision: CreatePlaybookRevisionUseCase,
    private readonly updateDraft: UpdatePlaybookDraftUseCase,
    private readonly publishRevision: PublishPlaybookRevisionUseCase,
    private readonly rollbackRevision: RollbackPlaybookRevisionUseCase
  ) {}

  private actor(req: Request) {
    return { id: req.user!.id, role: req.user!.role, principalType: (req.user!.principalType ?? "HUMAN") as "HUMAN" };
  }

  /** GET /:id/revisions — version history (oldest first). */
  list = async (req: Request, res: Response): Promise<void> => {
    const result = await this.listRevisions.execute({ tenantId: authenticatedTenant(req), id: req.params.id });
    if (result.isFailure) return fail(res, result.error);
    res.json(result.value);
  };

  /** POST /:id/revisions — "Create New Version": a DRAFT copy of the published revision. */
  create = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(reasonSchema, req, res);
    if (!body) return;
    const result = await this.createRevision.execute({ tenantId: authenticatedTenant(req), id: req.params.id, actor: this.actor(req), reason: body.reason || null });
    if (result.isFailure) return fail(res, result.error);
    res.status(201).json(result.value);
  };

  /** PUT /:id/revisions/:revisionId — edit a DRAFT. */
  update = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(updatePlaybookSchema, req, res);
    if (!body) return;
    const result = await this.updateDraft.execute({ tenantId: authenticatedTenant(req), id: req.params.id, revisionId: req.params.revisionId, actor: this.actor(req), changes: body });
    if (result.isFailure) return fail(res, result.error);
    res.json(result.value);
  };

  /** POST /:id/revisions/:revisionId/publish — DRAFT → PUBLISHED (SOC / IR_TEAM). */
  publish = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(reasonSchema, req, res);
    if (!body) return;
    const result = await this.publishRevision.execute({ tenantId: authenticatedTenant(req), id: req.params.id, revisionId: req.params.revisionId, actor: this.actor(req), reason: body.reason || null });
    if (result.isFailure) return fail(res, result.error);
    res.json({ revisionId: result.value.revisionId, version: result.value.version, publishedAt: result.value.publishedAt });
  };

  /** POST /:id/revisions/:revisionId/rollback — re-publish a previous version (SOC / IR_TEAM). */
  rollback = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(reasonSchema, req, res);
    if (!body) return;
    const result = await this.rollbackRevision.execute({ tenantId: authenticatedTenant(req), id: req.params.id, revisionId: req.params.revisionId, actor: this.actor(req), reason: body.reason || null });
    if (result.isFailure) return fail(res, result.error);
    res.json({ revisionId: result.value.revisionId, version: result.value.version, publishedAt: result.value.publishedAt });
  };
}
