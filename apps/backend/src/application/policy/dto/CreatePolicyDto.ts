import { z } from "zod";
import { POLICY_TYPES } from "../../../domain/policy/entities/PolicyEvaluationTypes";
import { EVIDENCE_REQUIREMENT_IDS } from "../../../domain/knowledge/knowledgeTypes";

// "riskScore" is retired: new/updated rules cannot key on a risk score (Severity is the classification input).
const CONDITION_FIELDS = ["severity", "incidentType", "actionCode", "verificationResult", "spreadDetected", "threatContained"] as const;
const CONDITION_OPERATORS = ["eq", "neq", "gte", "lte", "gt", "lt"] as const;

/**
 * policyConditionSchema — recursive validator for the declarative condition
 * tree. This is the write-side enforcement of "never store arbitrary
 * executable conditions": every leaf must name one of the known context
 * fields and one of the known operators, and the tree can only nest via
 * `all`/`any`. z.lazy() is required here purely because the type is
 * recursive, not for anything dynamic/unsafe.
 */
const policyConditionLeafSchema = z.object({
  field: z.enum(CONDITION_FIELDS),
  operator: z.enum(CONDITION_OPERATORS),
  value: z.union([z.string(), z.number(), z.boolean()]),
});

export const policyConditionSchema: z.ZodType<unknown> = z.lazy(() =>
  z.union([
    policyConditionLeafSchema,
    z.object({ all: z.array(policyConditionSchema).min(1) }),
    z.object({ any: z.array(policyConditionSchema).min(1) }),
  ])
);

const responsibleRoleSchema = z.enum(["SOC", "IR_TEAM"]);
const prioritySchema = z.enum(["P0", "P1", "P2", "P3"]);

/** policyResultFragmentSchema — every field a rule's result JSON is allowed
 * to set. Mirrors PolicyResultFragment exactly; `.strict()` rejects any
 * field not in this list instead of silently persisting it. */
export const policyResultFragmentSchema = z
  .object({
    priority: prioritySchema.optional(),
    responsibleRole: responsibleRoleSchema.optional(),
    reviewRequired: z.boolean().optional(),
    reviewRole: responsibleRoleSchema.optional(),
    approvalRequired: z.boolean().optional(),
    approvalRole: responsibleRoleSchema.optional(),
    approvalReason: z.array(z.string().min(1)).optional(),
    approvalChain: z.array(responsibleRoleSchema).min(1).optional(),
    executorRole: responsibleRoleSchema.optional(),
    autoCreateIncident: z.boolean().optional(),
    highRiskReview: z.boolean().optional(),
    responseRequired: z.boolean().optional(),
    investigationRequired: z.boolean().optional(),
    additionalInvestigation: z.boolean().optional(),
    standardInvestigation: z.boolean().optional(),
    incidentStatus: z.string().optional(),
    requireNewInvestigation: z.boolean().optional(),
    requireNewRecommendation: z.boolean().optional(),
    requireEscalation: z.boolean().optional(),
    requireAdditionalEvidence: z.boolean().optional(),
    firstResponseSlaMinutes: z.number().positive().optional(),
    triageSlaMinutes: z.number().int().positive().optional(),
    allowedActions: z.array(z.string().trim().min(1)).max(50).optional(),
    guidanceNote: z.string().trim().max(2000).optional(),
    requiredEvidence: z.array(z.enum(EVIDENCE_REQUIREMENT_IDS as [string, ...string[]])).min(1).optional(),
  })
  .strict();

const policyRuleInputSchema = z.object({
  condition: policyConditionSchema,
  result: policyResultFragmentSchema,
});

export const createPolicySchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(1)
      .regex(/^[A-Z0-9-]+$/, "code must be upper-case alphanumeric with hyphens, e.g. POL-001"),
    name: z.string().trim().min(1),
    description: z.string().trim().nullable().optional(),
    type: z.enum(POLICY_TYPES as [string, ...string[]]),
    precedence: z.number().int().optional().default(0),
    rules: z.array(policyRuleInputSchema).min(1),
    /** Who's making the change — see PolicyController.ts's own note on why
     * this is a body field rather than req.user (no auth middleware exists
     * in this backend yet). Recorded on the AuditLog entry. */
    actor: z.string().trim().min(1).optional().default("system"),
  })
  .strict();

export type CreatePolicyDto = z.infer<typeof createPolicySchema>;
