import { z } from "zod";

export const createVerificationSchema = z
  .object({
    responseId: z.string().uuid(),
    wazuhIndex: z.string().nullable().optional(),
    query: z.string().trim().min(1),
    timeRangeStart: z.coerce.date().nullable().optional(),
    timeRangeEnd: z.coerce.date().nullable().optional(),
    matchingEvents: z.number().int().min(0),
    affectedHosts: z.array(z.string()).optional(),
    iocRecurrence: z.boolean().optional(),
    spreadDetected: z.boolean().optional(),
    threatContained: z.boolean(),
    beforeState: z.record(z.unknown()).nullable().optional(),
    afterState: z.record(z.unknown()).nullable().optional(),
    notes: z.string().nullable().optional(),
  })
  .strict();

export type CreateVerificationDto = z.infer<typeof createVerificationSchema>;
