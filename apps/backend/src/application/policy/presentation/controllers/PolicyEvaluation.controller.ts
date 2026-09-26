import { Request, Response } from "express";
import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { EvaluatePolicyUseCase } from "../../application/use-cases/EvaluatePolicy.usecase";

/** ASSUMPTION — same as Policy.controller.ts: Express + req.tenantId. */
export class PolicyEvaluationController {
  private readonly evaluatePolicy: EvaluatePolicyUseCase;

  constructor(policyRepository: IPolicyRepository) {
    this.evaluatePolicy = new EvaluatePolicyUseCase(policyRepository);
  }

  evaluate = async (req: Request, res: Response) => {
    const tenantId = (req as any).tenantId;
    try {
      const result = await this.evaluatePolicy.execute(tenantId, req.body);
      res.json(result);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
  };
}
