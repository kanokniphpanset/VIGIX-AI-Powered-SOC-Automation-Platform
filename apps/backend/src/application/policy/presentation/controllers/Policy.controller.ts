import { Request, Response } from "express";
import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { CreatePolicyUseCase } from "../../application/use-cases/CreatePolicy.usecase";
import { UpdatePolicyUseCase } from "../../application/use-cases/UpdatePolicy.usecase";
import { GetPolicyUseCase } from "../../application/use-cases/GetPolicy.usecase";
import { ListPoliciesUseCase } from "../../application/use-cases/ListPolicies.usecase";
import { EnablePolicyUseCase } from "../../application/use-cases/EnablePolicy.usecase";
import { DisablePolicyUseCase } from "../../application/use-cases/DisablePolicy.usecase";

/**
 * ASSUMPTION — Express handlers, and `req.tenantId` set by upstream auth
 * middleware (the multi-tenant pattern IPolicyRepository's every method
 * already assumes via its `tenantId` parameter). Swap both assumptions for
 * whatever this project's actual auth middleware/framework provides —
 * every use-case call below is the part that actually matters.
 */
export class PolicyController {
  private readonly createPolicy: CreatePolicyUseCase;
  private readonly updatePolicy: UpdatePolicyUseCase;
  private readonly getPolicy: GetPolicyUseCase;
  private readonly listPolicies: ListPoliciesUseCase;
  private readonly enablePolicy: EnablePolicyUseCase;
  private readonly disablePolicy: DisablePolicyUseCase;

  constructor(policyRepository: IPolicyRepository) {
    this.createPolicy = new CreatePolicyUseCase(policyRepository);
    this.updatePolicy = new UpdatePolicyUseCase(policyRepository);
    this.getPolicy = new GetPolicyUseCase(policyRepository);
    this.listPolicies = new ListPoliciesUseCase(policyRepository);
    this.enablePolicy = new EnablePolicyUseCase(policyRepository);
    this.disablePolicy = new DisablePolicyUseCase(policyRepository);
  }

  list = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    const enabledOnly = req.query.enabled === "true";
    const policies = await this.listPolicies.execute(tenantId, enabledOnly);
    res.json(policies.map((p) => p.toJSON()));
  };

  get = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    try {
      const policy = await this.getPolicy.execute(req.params.id, tenantId);
      res.json(policy.toJSON());
    } catch (err: any) {
      res.status(404).json({ error: err.message });
    }
  };

  create = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    try {
      const policy = await this.createPolicy.execute({ ...req.body, tenantId });
      res.status(201).json(policy.toJSON());
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  };

  update = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    try {
      const policy = await this.updatePolicy.execute(req.params.id, tenantId, req.body);
      res.json(policy.toJSON());
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  };

  enable = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    const policy = await this.enablePolicy.execute(req.params.id, tenantId);
    res.json(policy.toJSON());
  };

  disable = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    const policy = await this.disablePolicy.execute(req.params.id, tenantId);
    res.json(policy.toJSON());
  };
}
