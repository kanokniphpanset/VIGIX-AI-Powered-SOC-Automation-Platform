import { authenticatedTenant } from "../middlewares/auth.middleware";
import { Request, Response } from "express";
import { CreateVerificationUseCase } from "../../../application/verification/use-cases/CreateVerification.usecase";
import { GetVerificationUseCase } from "../../../application/verification/use-cases/GetVerification.usecase";
import { ListVerificationsUseCase } from "../../../application/verification/use-cases/ListVerifications.usecase";
import { ListAllVerificationsUseCase } from "../../../application/verification/use-cases/ListAllVerifications.usecase";
import { createVerificationSchema } from "../../../application/verification/dto/CreateVerificationDto";
import { RunRehuntVerificationUseCase } from "../../../application/verification/use-cases/RunRehuntVerification.usecase";
import { ISiemRehuntPort } from "../../../application/verification/ports/ISiemRehuntPort";
import { z } from "zod";
import { validateBody } from "../validators/validateBody";


/** Same rule as CreateVerification's derived result: contained, no spread, no recurrence and zero matching events. */
export function wouldResolve(b: { threatContained: boolean; spreadDetected?: boolean; iocRecurrence?: boolean; matchingEvents: number }): boolean {
  return b.threatContained && !b.spreadDetected && !b.iocRecurrence && b.matchingEvents === 0;
}

export class VerificationController {
  constructor(
    private readonly createVerification: CreateVerificationUseCase,
    private readonly getVerification: GetVerificationUseCase,
    private readonly listVerifications: ListVerificationsUseCase,
    private readonly listAllVerifications: ListAllVerificationsUseCase,
    private readonly runRehunt: RunRehuntVerificationUseCase,
    private readonly rehuntPort: ISiemRehuntPort
  ) {}

  /** Admin diagnostic: is the Wazuh Indexer configured and reachable? Never returns credentials. */
  rehuntHealth = async (_req: Request, res: Response): Promise<void> => {
    res.json(await this.rehuntPort.health());
  };

  /**
   * Runs a real re-hunt against the Wazuh Indexer and records the Verification. The body carries
   * only the ticket (and optional notes) — never evidence and never a result: the backend gathers
   * the evidence and derives RESOLVED / NOT_RESOLVED itself.
   */
  rehunt = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(z.object({ responseId: z.string().uuid(), notes: z.string().nullable().optional() }).strict(), req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    const result = await this.runRehunt.execute({
      incidentId: req.params.incidentId,
      responseId: body.responseId,
      tenantId,
      verifiedBy: req.user.id,
      notes: body.notes ?? null,
    });
    if (result.isFailure) {
      const code = result.error;
      const status =
        code === "INCIDENT_NOT_FOUND" || code === "RESPONSE_NOT_FOUND"
          ? 404
          : code === "REHUNT_NOT_CONFIGURED" || code === "REHUNT_UNREACHABLE" || code === "REHUNT_QUERY_FAILED"
            ? 502
            : 409;
      res.status(status).json({ error: code });
      return;
    }
    res.status(201).json({ verification: result.value.verification.toJSON(), evidence: result.value.evidence });
  };

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const limit = req.query.limit ? Number(req.query.limit) : 100;
    const offset = req.query.offset ? Number(req.query.offset) : 0;
    const verifications = await this.listAllVerifications.execute({ tenantId, limit, offset });
    res.json({ items: verifications.map((v) => v.toJSON()) });
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const body = validateBody(createVerificationSchema, req, res);
    if (!body) return;
    if (!req.user) {
      res.status(401).json({ error: "UNAUTHENTICATED" });
      return;
    }
    // A manual observation may record that the threat is NOT contained (it re-opens investigation), but a RESOLVED
    // verdict comes only from the re-hunt (POST .../verifications/rehunt) — never from hand-entered numbers.
    if (wouldResolve(body)) {
      res.status(409).json({ error: "RESOLVE_REQUIRES_VERIFICATION", message: "RESOLVED is produced only by a re-hunt NO MATCH. Run the re-hunt instead." });
      return;
    }

    const result = await this.createVerification.execute({
      ...body,
      incidentId: req.params.incidentId,
      tenantId,
      verifiedBy: req.user.id,
    });
    if (result.isFailure) {
      const statusCode = result.error === "INCIDENT_NOT_FOUND" || result.error === "RESPONSE_NOT_FOUND" ? 404 : 409;
      res.status(statusCode).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const result = await this.getVerification.execute({ id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: "VERIFICATION_NOT_FOUND" });
      return;
    }
    res.json(result.value.toJSON());
  };

  listByIncident = async (req: Request, res: Response): Promise<void> => {
    const tenantId = authenticatedTenant(req);
    const verifications = await this.listVerifications.execute({ incidentId: req.params.incidentId, tenantId });
    res.json({ items: verifications.map((v) => v.toJSON()) });
  };
}
