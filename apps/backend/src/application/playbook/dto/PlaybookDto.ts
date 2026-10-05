import { z } from "zod";

const stepSchema = z
  .object({
    stepOrder: z.number().int().positive(),
    title: z.string().trim().min(1),
    description: z.string().nullable().optional(),
  })
  .strict();

/** Response steps: at least one, each stepOrder used once. */
const stepsSchema = z
  .array(stepSchema)
  .min(1)
  .refine((steps) => new Set(steps.map((s) => s.stepOrder)).size === steps.length, { message: "Step order must be unique" });

/** Applicable incident category, stored as triggerConditions.incidentType (e.g. SSH_BRUTE_FORCE). */
const incidentTypeSchema = z.string().trim().regex(/^[A-Z0-9_]+$/).max(64);

/** triggerConditions.mitreTechniques — the playbook selector matches these against the incident (e.g. T1110, T1110.001). */
const mitreTechniquesSchema = z.array(z.string().trim().regex(/^T\d{4}(\.\d{3})?$/)).max(50);

/** triggerConditions.allowedActions — action catalog codes the recommendation may expand (e.g. ACT-BLOCK-SOURCE-IP). */
const allowedActionsSchema = z.array(z.string().trim().regex(/^[A-Z0-9-]+$/)).max(50);

export const createPlaybookSchema = z
  .object({
    code: z.string().regex(/^[A-Z0-9-]+$/).optional(),
    name: z.string().trim().min(1),
    description: z.string().nullable().optional(),
    incidentType: incidentTypeSchema.nullable().optional(),
    mitreTechniques: mitreTechniquesSchema.optional(),
    allowedActions: allowedActionsSchema.optional(),
    version: z.string().optional().default("1.0"),
    status: z.enum(["ACTIVE", "DEPRECATED"]).optional().default("ACTIVE"),
    steps: stepsSchema,
  })
  .strict();

export const updatePlaybookSchema = z
  .object({
    name: z.string().trim().min(1).optional(),
    description: z.string().nullable().optional(),
    incidentType: incidentTypeSchema.nullable().optional(),
    mitreTechniques: mitreTechniquesSchema.optional(),
    allowedActions: allowedActionsSchema.optional(),
    version: z.string().optional(),
    status: z.enum(["ACTIVE", "DEPRECATED"]).optional(),
    steps: stepsSchema.optional(),
  })
  .strict();

export type CreatePlaybookDto = z.infer<typeof createPlaybookSchema>;
export type UpdatePlaybookDto = z.infer<typeof updatePlaybookSchema>;
