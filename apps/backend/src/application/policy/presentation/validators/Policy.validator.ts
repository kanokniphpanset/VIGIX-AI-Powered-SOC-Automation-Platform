import { Request, Response, NextFunction } from "express";

/**
 * ASSUMPTION — Express is assumed as the HTTP framework since none was
 * specified. If this project actually uses Fastify/Nest/Koa, only the
 * function signatures in this file and Policy.controller.ts /
 * PolicyEvaluation.controller.ts need to change — application/domain code
 * is framework-agnostic and untouched either way.
 *
 * This validator only checks that the request body has the right shape
 * (required keys present, roughly the right types) before it reaches the
 * controller. Deeper, domain-level validation (enum membership, numeric
 * ranges, condition/result well-formedness) is deliberately left to
 * CreatePolicy.dto.ts / UpdatePolicy.dto.ts / PolicyEvaluationInput.dto.ts
 * so that validation logic isn't duplicated across two layers.
 */
export function validateCreatePolicyBody(req: Request, res: Response, next: NextFunction) {
  const body = req.body ?? {};
  const missing: string[] = [];
  if (!body.code) missing.push("code");
  if (!body.name) missing.push("name");
  if (!body.type) missing.push("type");
  if (body.precedence === undefined) missing.push("precedence");
  if (!Array.isArray(body.rules) || body.rules.length === 0) missing.push("rules");

  if (missing.length > 0) {
    return res.status(400).json({ error: `Missing required field(s): ${missing.join(", ")}` });
  }
  next();
}

export function validateUpdatePolicyBody(req: Request, res: Response, next: NextFunction) {
  const body = req.body ?? {};
  if (body.rules !== undefined && (!Array.isArray(body.rules) || body.rules.length === 0)) {
    return res.status(400).json({ error: "rules, if provided, must be a non-empty array" });
  }
  next();
}

export function validateEvaluatePolicyBody(req: Request, res: Response, next: NextFunction) {
  const body = req.body ?? {};
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return res.status(400).json({ error: "request body must be a JSON object" });
  }
  next();
}
