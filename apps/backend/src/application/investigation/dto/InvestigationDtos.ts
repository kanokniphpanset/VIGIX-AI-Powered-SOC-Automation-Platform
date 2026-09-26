import { z } from "zod";
import { EVIDENCE_RELEVANCE, EVIDENCE_TYPES, IOC_STATUSES, IOC_TYPES, MANUAL_EVIDENCE_SOURCES } from "../../../domain/investigation/Investigation.types";

const MAX_JSON_BYTES = 100_000;
const jsonValue = z.unknown().refine((v) => v === undefined || JSON.stringify(v).length <= MAX_JSON_BYTES, { message: "must be smaller than 100 KB" });

/**
 * Manual evidence. There is deliberately NO `origin` field: the backend stamps origin=MANUAL, so a client cannot
 * present its own entry as system-derived evidence. WAZUH_ALERT / WAZUH_EVENT are rejected in the use case
 * (they are only ever derived from a stored alert or a SIEM query).
 */
export const createEvidenceSchema = z
  .object({
    type: z.enum(EVIDENCE_TYPES),
    source: z.enum(MANUAL_EVIDENCE_SOURCES),
    title: z.string().trim().min(3).max(300),
    description: z.string().trim().max(5000).nullable().optional(),
    timestamp: z.coerce.date().optional(),
    structuredData: z.record(z.unknown()).nullable().optional(),
    rawData: jsonValue.nullable().optional(),
    confidence: z.number().min(0).max(1).nullable().optional(),
    relevance: z.enum(EVIDENCE_RELEVANCE).nullable().optional(),
    alertId: z.string().uuid().nullable().optional(),
    iocIds: z.array(z.string().uuid()).max(50).optional(),
  })
  .strict()
  .refine((v) => v.structuredData === undefined || v.structuredData === null || JSON.stringify(v.structuredData).length <= MAX_JSON_BYTES, {
    message: "structuredData must be smaller than 100 KB",
    path: ["structuredData"],
  });

export const createIocSchema = z
  .object({
    iocType: z.enum(IOC_TYPES),
    iocValue: z.string().trim().min(1).max(2048),
    source: z.string().trim().min(2).max(100),
    confidence: z.number().min(0).max(1).nullable().optional(),
    reputationScore: z.number().min(0).max(100).nullable().optional(),
    status: z.enum(IOC_STATUSES).optional(),
    firstSeen: z.coerce.date().nullable().optional(),
    lastSeen: z.coerce.date().nullable().optional(),
    /** Related-alert evidence: the OTHER Wazuh alert this indicator was observed in (1 Alert = 1 Incident stays). */
    sourceAlertId: z.string().trim().min(1).max(100).nullable().optional(),
    /** Why the SOC links this indicator to the incident — required with sourceAlertId. */
    reason: z.string().trim().min(5).max(1000).nullable().optional(),
  })
  .strict()
  .refine((b) => !b.sourceAlertId || !!b.reason, { message: "A reason is required when the indicator comes from another alert", path: ["reason"] });

export type CreateEvidenceDto = z.infer<typeof createEvidenceSchema>;
export type CreateIocDto = z.infer<typeof createIocSchema>;
