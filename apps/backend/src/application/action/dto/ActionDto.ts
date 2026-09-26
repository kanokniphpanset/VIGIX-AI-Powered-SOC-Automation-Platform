import { z } from "zod";

export const createActionSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(1)
      .regex(/^[A-Z0-9-]+$/, "code must be upper-case alphanumeric with hyphens, e.g. ACT-001"),
    name: z.string().trim().min(1),
    description: z.string().trim().nullable().optional(),
    category: z.enum(["CONTAINMENT", "INVESTIGATION", "VERIFICATION"]),
    impactLevel: z.enum(["LOW", "MEDIUM", "HIGH"]),
    defaultApprovalRequired: z.boolean().optional().default(false),
    runbookId: z.string().trim().nullable().optional(),
  })
  .strict();
export type CreateActionDto = z.infer<typeof createActionSchema>;

export const updateActionSchema = z
  .object({
    name: z.string().trim().min(1).optional(),
    description: z.string().trim().nullable().optional(),
    impactLevel: z.enum(["LOW", "MEDIUM", "HIGH"]).optional(),
    defaultApprovalRequired: z.boolean().optional(),
    runbookId: z.string().trim().nullable().optional(),
  })
  .strict();
export type UpdateActionDto = z.infer<typeof updateActionSchema>;
