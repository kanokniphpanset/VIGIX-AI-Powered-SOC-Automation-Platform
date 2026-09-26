import { Request, Response } from "express";
import { z } from "zod";
import { PreviewArticleEmailUseCase, SendArticleToIrUseCase } from "../../../application/knowledge/use-cases/KnowledgeArticles.usecases";
import { PreviewResponseGuideUseCase, SendResponseGuideToIrUseCase } from "../../../application/incident/use-cases/ResponseGuide.usecases";
import { IrEmailOutcome } from "../../../application/notification/services/IrEmailService";
import { validateBody } from "../validators/validateBody";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";
const uuid = z.string().uuid();
/**
 * The client may only choose the subject (and, for a guide, which of the incident's tickets it is about) — never the
 * recipient, body or sender. idempotencyKey (one per confirmation dialog) makes a repeated click a no-op.
 */
const sendArticleSchema = z.object({ subject: z.string().trim().max(200).nullable().optional(), idempotencyKey: uuid.optional() }).strict();
const sendGuideSchema = sendArticleSchema.extend({ responseId: uuid.nullable().optional() }).strict();

function reply(res: Response, outcome: IrEmailOutcome): void {
  // Failures carry `error` (IR_TEAM_EMAIL_NOT_CONFIGURED / CHANNEL_NOT_CONFIGURED / DELIVERY_FAILED / DUPLICATE_IN_PROGRESS).
  const status =
    outcome.status === "SENT" ? 200 : outcome.error === "DELIVERY_FAILED" ? 502 : outcome.error === "DUPLICATE_IN_PROGRESS" ? 409 : 400;
  res.status(status).json(outcome);
}

/** Knowledge article / incident response guide → IR Team email (preview + send). */
export class IrEmailController {
  constructor(
    private readonly previewArticle: PreviewArticleEmailUseCase,
    private readonly sendArticle: SendArticleToIrUseCase,
    private readonly previewGuide: PreviewResponseGuideUseCase,
    private readonly sendGuide: SendResponseGuideToIrUseCase
  ) {}

  article = async (req: Request, res: Response): Promise<void> => {
    const result = await this.previewArticle.execute({ tenantId: req.user?.tenantId ?? DEFAULT_TENANT_ID, articleId: req.params.articleId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  sendArticleToIr = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(sendArticleSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.sendArticle.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      articleId: req.params.articleId,
      actor: req.user.id,
      subject: body.subject ?? null,
      idempotencyKey: body.idempotencyKey ?? null,
    });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    reply(res, result.value);
  };

  responseGuide = async (req: Request, res: Response): Promise<void> => {
    const responseId = typeof req.query.responseId === "string" && req.query.responseId ? req.query.responseId : null;
    if (!uuid.safeParse(req.params.incidentId).success) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    if (responseId && !uuid.safeParse(responseId).success) {
      res.status(404).json({ error: "RESPONSE_NOT_FOUND" });
      return;
    }
    const result = await this.previewGuide.execute({ tenantId: req.user?.tenantId ?? DEFAULT_TENANT_ID, incidentId: req.params.incidentId, responseId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value);
  };

  sendResponseGuideToIr = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(sendGuideSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    if (!uuid.safeParse(req.params.incidentId).success) {
      res.status(404).json({ error: "INCIDENT_NOT_FOUND" });
      return;
    }
    const result = await this.sendGuide.execute({
      tenantId: req.user.tenantId ?? DEFAULT_TENANT_ID,
      incidentId: req.params.incidentId,
      actor: req.user.id,
      subject: body.subject ?? null,
      responseId: body.responseId ?? null,
      idempotencyKey: body.idempotencyKey ?? null,
    });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    reply(res, result.value);
  };
}
