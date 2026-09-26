import { Request, Response } from "express";
import { EvaluatePolicyUseCase } from "../../../application/policy/use-cases/EvaluatePolicy.usecase";
import { evaluatePolicySchema } from "../../../application/policy/dto/EvaluatePolicyDto";
import { validateBody } from "../validators/validateBody";
import { PolicyEvaluationInput } from "../../../domain/policy/entities/PolicyEvaluationTypes";

const DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001";

/**
 * PolicyEvaluationController — kept separate from PolicyController on
 * purpose. This is the only Policy HTTP surface an AI/LLM/RAG agent (or
 * any other automated caller) should ever be pointed at: it can only read
 * enabled policies and run the deterministic engine, never create, edit,
 * enable, or disable one. See EvaluatePolicy.usecase.ts / PolicyEvaluator.ts.
 */
export class PolicyEvaluationController {
  constructor(private readonly evaluatePolicy: EvaluatePolicyUseCase) {}

  evaluate = async (req: Request, res: Response): Promise<void> => {
    const tenantId = req.user?.tenantId ?? DEFAULT_TENANT_ID; // from the verified JWT, never from the query string
    const body = validateBody(evaluatePolicySchema, req, res);
    if (!body) return;

    const result = await this.evaluatePolicy.execute({ tenantId, context: body as PolicyEvaluationInput });
    res.json(result);
  };
}
