import { z } from "zod";

/**
 * `priority` is the Incident's own severity (low | medium | high | critical). It is chosen by the
 * analyst and is NOT derived from, or constrained by, the severity of the alerts being grouped.
 */
export const createIncidentSchema = z
  .object({
    title: z.string().trim().min(3).max(200),
    priority: z.enum(["low", "medium", "high", "critical"]),
    alertIds: z.array(z.string().uuid()).min(1).max(50),
    note: z.string().trim().max(2000).nullable().optional(),
  })
  .strict();

export type CreateIncidentDto = z.infer<typeof createIncidentSchema>;
