import { z } from "zod";
import {
  SEVERITIES,
  VERIFICATION_RESULTS,
  ASSET_CRITICALITIES,
  ACTION_IMPACT_LEVELS,
} from "../../../domain/policy/entities/PolicyEvaluationTypes";

/**
 * evaluatePolicySchema — validates POST /api/policies/evaluate's body.
 * Every field is optional (different policy groups key off different
 * fields), but any field that IS present must be a genuinely valid value —
 * invalid input is rejected (400), never silently coerced or dropped, per
 * the module's validation requirements.
 */
export const evaluatePolicySchema = z
  .object({
    severity: z.enum(SEVERITIES as [string, ...string[]]).optional(),
    /** DEPRECATED — accepted so older clients are not rejected, but IGNORED: Risk Score is not a Policy input. */
    riskScore: z.number().min(0).max(100).optional(),
    assetCriticality: z.enum(ASSET_CRITICALITIES as [string, ...string[]]).optional(),
    actionImpactLevel: z.enum(ACTION_IMPACT_LEVELS as [string, ...string[]]).optional(),
    verificationResult: z.enum(VERIFICATION_RESULTS as [string, ...string[]]).optional(),
    spreadDetected: z.boolean().optional(),
    threatContained: z.boolean().optional(),
  })
  .strict();

export type EvaluatePolicyDto = z.infer<typeof evaluatePolicySchema>;
