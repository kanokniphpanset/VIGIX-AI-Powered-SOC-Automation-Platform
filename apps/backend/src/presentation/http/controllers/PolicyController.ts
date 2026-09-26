import { Request, Response } from "express";
import { CreatePolicyUseCase } from "../../../application/policy/use-cases/CreatePolicy.usecase";
import { UpdatePolicyUseCase } from "../../../application/policy/use-cases/UpdatePolicy.usecase";
import { EnablePolicyUseCase } from "../../../application/policy/use-cases/EnablePolicy.usecase";
import { DisablePolicyUseCase } from "../../../application/policy/use-cases/DisablePolicy.usecase";
import { DeletePolicyUseCase } from "../../../application/policy/use-cases/DeletePolicy.usecase";
import { z } from "zod";
import { GetPolicyUseCase } from "../../../application/policy/use-cases/GetPolicy.usecase";
import { ListPoliciesUseCase } from "../../../application/policy/use-cases/ListPolicies.usecase";
import { createPolicySchema } from "../../../application/policy/dto/CreatePolicyDto";
import { updatePolicySchema } from "../../../application/policy/dto/UpdatePolicyDto";
import { validateBody } from "../validators/validateBody";

// Every Policy route is authenticated (policy.routes.ts): reads for SOC / IR_TEAM (+ admin), mutations admin-only.
// The tenant always comes from the verified JWT (req.user.tenantId) — never from a query parameter, so a caller can
// never read or change another tenant's Policy. Evaluation-only access stays in PolicyEvaluationController.
const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

export class PolicyController {
  constructor(
    private readonly createPolicy: CreatePolicyUseCase,
    private readonly updatePolicy: UpdatePolicyUseCase,
    private readonly enablePolicy: EnablePolicyUseCase,
    private readonly disablePolicy: DisablePolicyUseCase,
    private readonly getPolicy: GetPolicyUseCase,
    private readonly listPolicies: ListPoliciesUseCase,
    private readonly deletePolicy?: DeletePolicyUseCase
  ) {}

  list = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const policies = await this.listPolicies.execute({ tenantId });
    res.json({ items: policies.map((p) => p.toJSON()) });
  };

  getById = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const result = await this.getPolicy.execute({ id: req.params.id, tenantId });

    if (result.isFailure) {
      res.status(404).json({ error: "Policy not found" });
      return;
    }
    res.json(result.value.toJSON());
  };

  create = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const body = validateBody(createPolicySchema, req, res);
    if (!body) return;

    const result = await this.createPolicy.execute({ ...body, actor: body.actor ?? "system", precedence: body.precedence ?? 0, tenantId });
    if (result.isFailure) {
      res.status(409).json({ error: result.error });
      return;
    }
    res.status(201).json(result.value.toJSON());
  };

  update = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const body = validateBody(updatePolicySchema, req, res);
    if (!body) return;

    const result = await this.updatePolicy.execute({ ...body, actor: body.actor ?? "system", id: req.params.id, tenantId });
    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  enable = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const actor = (req.body?.actor as string) ?? "system";
    const result = await this.enablePolicy.execute({ id: req.params.id, tenantId, actor });

    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  disable = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const actor = (req.body?.actor as string) ?? "system";
    const result = await this.disablePolicy.execute({ id: req.params.id, tenantId, actor });

    if (result.isFailure) {
      res.status(404).json({ error: result.error });
      return;
    }
    res.json(result.value.toJSON());
  };

  /** DELETE /:id — a reason is required; the actor is the signed-in user (JWT), recorded with a copy of the policy. */
  remove = async (req: Request, res: Response): Promise<void> => {
    if (!this.deletePolicy) {
      res.status(501).json({ error: "NOT_IMPLEMENTED" });
      return;
    }
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID;
    const body = validateBody(deletePolicySchema, req, res);
    if (!body) return;
    const result = await this.deletePolicy.execute({ id: req.params.id, tenantId, actor: req.user?.id ?? "system", reason: body.reason });
    if (result.isFailure) {
      res.status(404).json({ error: "POLICY_NOT_FOUND" });
      return;
    }
    res.json({ deleted: true, ...result.value });
  };
}

const deletePolicySchema = z.object({ reason: z.string().trim().min(1).max(2000) }).strict();
