import { z } from "zod";

export const createRunbookSchema = z
  .object({
    code: z
      .string()
      .trim()
      .min(1)
      .regex(/^[A-Z0-9-]+$/, "code must be upper-case alphanumeric with hyphens, e.g. RB-MALWARE-001"),
    name: z.string().trim().min(1),
    version: z.string().trim().min(1).optional().default("1.0"),
    description: z.string().trim().nullable().optional(),
    trigger: z.string().trim().nullable().optional(),
    preconditions: z.array(z.string()).optional().default([]),
    objective: z.string().trim().nullable().optional(),
    procedure: z.array(z.string()).min(1),
    decisionPoints: z.array(z.string()).optional().default([]),
    expectedResult: z.string().trim().nullable().optional(),
    escalation: z.string().trim().nullable().optional(),
    verificationCriteria: z.array(z.string()).optional().default([]),
  })
  .strict();
export type CreateRunbookDto = z.infer<typeof createRunbookSchema>;

export const updateRunbookSchema = z
  .object({
    name: z.string().trim().min(1).optional(),
    version: z.string().trim().min(1).optional(),
    status: z.enum(["ACTIVE", "DEPRECATED"]).optional(),
    description: z.string().trim().nullable().optional(),
    trigger: z.string().trim().nullable().optional(),
    preconditions: z.array(z.string()).optional(),
    objective: z.string().trim().nullable().optional(),
    procedure: z.array(z.string()).min(1).optional(),
    decisionPoints: z.array(z.string()).optional(),
    expectedResult: z.string().trim().nullable().optional(),
    escalation: z.string().trim().nullable().optional(),
    verificationCriteria: z.array(z.string()).optional(),
  })
  .strict();
export type UpdateRunbookDto = z.infer<typeof updateRunbookSchema>;
