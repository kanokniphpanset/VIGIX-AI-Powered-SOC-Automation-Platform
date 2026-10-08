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

/**
 * structuredData.subtypeFacts of an ANALYST_ASSERTION evidence row: the only way judgement-type facts (an unauthorized logon, a C2 channel, a
 * scheduled task tied to a payload, the role of a destination ...) enter the subtype knowledge. Unknown evidence ids are ignored (and audited)
 * at evaluation time; raw secrets / tokens are refused here. The author is the authenticated user, never "system" and never an AI.
 */
const SECRET_LIKE = /Bearer\s+\S{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}/;
const noSecrets = (v: unknown): boolean => JSON.stringify(v ?? null).search(SECRET_LIKE) === -1;
const idLike = z.string().regex(/^[a-z][a-z0-9_]{2,80}$/);
const refs = z.array(z.string().min(1).max(80)).max(30).optional();
export const subtypeFactsSchema = z
  .object({
    evidence: z.array(z.object({
      id: idLike, status: z.enum(["PRESENT", "ABSENT", "UNKNOWN"]), authorization_status: z.enum(["AUTHORIZED", "UNAUTHORIZED", "UNKNOWN"]).optional(),
      source_event_refs: refs, lineage: refs, note: z.string().max(500).optional(), observed_at: z.string().datetime().optional(),
    }).strict()).max(40).optional(),
    targets: z.array(z.object({ type: idLike, fields: z.record(z.unknown()), source_event_refs: refs }).strict()).max(40).optional(),
    scope: z.array(idLike).max(40).optional(),
    context: z.object({ active_damage_ongoing: z.boolean().optional() }).strict().optional(),
  })
  .strict()
  .refine((v) => !!(v.evidence?.length || v.targets?.length || v.scope?.length || v.context), { message: "an assertion must state at least one fact" })
  .refine(noSecrets, { message: "raw secrets / tokens must never be recorded - reference credentials by id only" });

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
