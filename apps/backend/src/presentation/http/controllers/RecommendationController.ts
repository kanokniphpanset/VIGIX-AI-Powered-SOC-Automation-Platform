import { authenticatedTenant } from "../middlewares/auth.middleware";
import { Request, Response } from "express";
import { GenerateRecommendationUseCase } from "../../../application/recommendation/use-cases/GenerateRecommendation.usecase";
import { GetRecommendationUseCase } from "../../../application/recommendation/use-cases/GetRecommendation.usecase";
import { ListRecommendationsUseCase } from "../../../application/recommendation/use-cases/ListRecommendations.usecase";
import { ValidateRecommendationUseCase } from "../../../application/recommendation/use-cases/ValidateRecommendation.usecase";
import { generateRecommendationSchema } from "../../../application/recommendation/dto/GenerateRecommendationDto";
import { SendRecommendationToIrUseCase } from "../../../application/response/use-cases/SendRecommendationToIr.usecase";
import { RejectRecommendationUseCase } from "../../../application/recommendation/use-cases/RejectRecommendation.usecase";
import { validateBody } from "../validators/validateBody";
import { IRecommendationAuditRepository } from "../../../domain/recommendation/repositories/IRecommendationAuditRepository";
import { renderUserText } from "../../../domain/subtype/composer";
import { z } from "zod";

const sendToIrSchema = z.object({ note: z.string().trim().max(2000).nullable().optional() }).strict();
const rejectSchema = z.object({ note: z.string().trim().max(2000) }).strict();


/**
 * User-facing recommendation. Steps built from the subtype knowledge carry contract-format instructions (title / impact / verify);
 * for them the numbered "คำแนะนำเพื่อยับยั้ง Incident" text is rendered from the STORED steps by the same renderer that composed it, so
 * API / UI / Response Ticket all show the same text. The internal audit is NOT part of this payload (GET /:id/audit, SOC / IR only).
 */
export function presentRecommendation(json: Record<string, any>): Record<string, any> {
  const steps = Array.isArray(json.steps) ? json.steps : [];
  const subtype = steps.some((s: any) => Array.isArray(s.instructions) && s.instructions.some((i: any) => i && typeof i === "object" && "kind" in i));
  if (!subtype) return json;
  const text = renderUserText(steps.map((s: any) => ({ stepType: s.stepType ?? (s.actionId ? "ACTION" : "CHECK"), title: s.title, instructions: (s.instructions ?? []).map((i: any) => ({ title: i.title ?? i.instruction, instruction: i.instruction, impact: i.impact ?? null, verify: i.verify ?? null, kind: i.kind ?? "action", manualOwner: i.manualOwner ?? null, method: i.method, methodKind: i.methodKind, preconditions: i.preconditions, rollback: i.rollback, note: i.note })) })));
  return { ...json, recommendationText: text };
}

export class RecommendationController {
  constructor(
    private readonly generateRecommendation: GenerateRecommendationUseCase,
    private readonly getRecommendation: GetRecommendationUseCase,
    private readonly listRecommendations: ListRecommendationsUseCase,
    private readonly validateRecommendation: ValidateRecommendationUseCase,
    private readonly sendRecommendationToIr: SendRecommendationToIrUseCase,
    private readonly rejectRecommendation?: RejectRecommendationUseCase,
    private readonly audits?: IRecommendationAuditRepository
  ) {}

  /** Internal audit of the subtype evaluation (policy decisions, targets, versions, ordering, authority/capability). SOC / IR_TEAM only. */
  getAudit = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    if (!this.audits) { res.status(501).json({ error: "NOT_CONFIGURED" }); return; }
    const rec = await this.getRecommendation.execute({ id: req.params.id, tenantId });
    if (rec.isFailure) { res.status(404).json({ error: "RECOMMENDATION_NOT_FOUND" }); return; }
    const audit = await this.audits.findByRecommendation(req.params.id, tenantId).catch(() => null);
    if (!audit) { res.status(404).json({ error: "AUDIT_NOT_FOUND" }); return; }
    res.json(audit);
  };

  /** SOC Validation REJECT: the recommendation is rejected and the incident is closed (note mandatory). */
  reject = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(rejectSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    if (!this.rejectRecommendation) {
      res.status(501).json({ error: "NOT_CONFIGURED" });
      return;
    }
    const result = await this.rejectRecommendation.execute({ tenantId: req.user.tenantId, recommendationId: req.params.id, actor: req.user.id, note: body.note });
    if (result.isFailure) {
      res.status(result.error === "RECOMMENDATION_NOT_FOUND" ? 404 : result.error === "NOTE_REQUIRED" ? 422 : 409).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  /** SOC "Send to IR": creates the Response Tickets (PENDING_IR_DECISION) first, then notifies IR with the ticket links. */
  sendToIr = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(sendToIrSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.sendRecommendationToIr.execute({ tenantId: req.user.tenantId, recommendationId: req.params.id, actor: req.user.id, note: body.note ?? null });
    if (result.isFailure) {
      res.status(result.error === "RECOMMENDATION_NOT_FOUND" ? 404 : 409).json({ error: result.error });
      return;
    }
    res.status(201).json({ tickets: result.value.tickets.map((t) => t.toJSON()) });
  };

  generate = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(generateRecommendationSchema, req, res);
    if (!body) return;

    const result = await this.generateRecommendation.execute({ incidentId: body.incidentId, tenantId });
    if (result.isFailure) {
      // No recommendation was persisted in any failure case (see GenerateRecommendationUseCase).
      const status =
        result.error.startsWith("PLAYBOOK_PROVENANCE_") || result.error === "RECOMMENDATION_INVESTIGATION_REQUIRED" ? 409 :
        result.error === "INCIDENT_NOT_FOUND" ? 404 : result.error === "AI_UNAVAILABLE" ? 503 : result.error === "INSUFFICIENT_EVIDENCE" || result.error === "NO_NEW_RECOMMENDATION" ? 422 : 502;
      res.status(status).json({ error: result.error });
      return;
    }
    res.status(201).json(presentRecommendation(result.value.toJSON() as Record<string, any>));
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const result = await this.getRecommendation.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "RECOMMENDATION_NOT_FOUND" });
      return;
    }
    res.json(presentRecommendation(result.value.toJSON() as Record<string, any>));
  };

  listByIncident = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const recommendations = await this.listRecommendations.execute({ incidentId: req.params.incidentId, tenantId });
    res.json({ items: recommendations.map((r) => presentRecommendation(r.toJSON() as Record<string, any>)) });
  };

  validate = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const result = await this.validateRecommendation.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "RECOMMENDATION_NOT_FOUND" });
      return;
    }
    res.json({ recommendation: result.value.recommendation.toJSON(), violations: result.value.violations });
  };
}
