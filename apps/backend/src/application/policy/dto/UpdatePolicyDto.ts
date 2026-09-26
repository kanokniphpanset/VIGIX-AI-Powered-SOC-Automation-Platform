import { z } from "zod";
import { policyConditionSchema, policyResultFragmentSchema } from "./CreatePolicyDto";

const policyRuleInputSchema = z.object({
  condition: policyConditionSchema,
  result: policyResultFragmentSchema,
});

export const updatePolicySchema = z
  .object({
    name: z.string().trim().min(1).optional(),
    description: z.string().trim().nullable().optional(),
    precedence: z.number().int().optional(),
    rules: z.array(policyRuleInputSchema).min(1).optional(),
    actor: z.string().trim().min(1).optional().default("system"),
  })
  .strict();

export type UpdatePolicyDto = z.infer<typeof updatePolicySchema>;
