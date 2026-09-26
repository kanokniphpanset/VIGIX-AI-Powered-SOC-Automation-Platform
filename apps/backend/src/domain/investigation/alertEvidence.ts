import { CreateEvidenceData } from "./Investigation.types";

/** The parts of a stored alert this needs (kept structural so it works for the entity and for raw rows). */
export interface AlertLike {
  id: string;
  externalAlertId: string;
  siemSource: string;
  severity: string;
  rawPayload: unknown;
  receivedAt: Date;
}

function asObject(v: unknown): Record<string, unknown> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/**
 * Derives the facts VIGIX already holds about an alert into a WAZUH_ALERT-type Evidence row. Handles the
 * native Wazuh shape (rule/agent are objects) and simplified payloads (plain strings). Only fields actually
 * present in the alert are copied; nothing is invented. The raw payload is NOT duplicated - the row references
 * the alert through alertId.
 */
export function buildAlertEvidence(alert: AlertLike, investigationId: string, createdBy: string): CreateEvidenceData {
  const payload = asObject(alert.rawPayload) ?? {};
  const rule = payload.rule;
  const ruleObj = asObject(rule);
  const agent = payload.agent;
  const agentObj = asObject(agent);

  const description =
    typeof rule === "string" ? rule : typeof ruleObj?.description === "string" ? (ruleObj.description as string) : null;
  const host = typeof agent === "string" ? agent : typeof agentObj?.name === "string" ? (agentObj.name as string) : null;

  const structured: Record<string, unknown> = {
    ruleId: ruleObj?.id,
    level: ruleObj?.level,
    description: description ?? undefined,
    agent: host ?? undefined,
    alertSeverity: alert.severity,
    siemSource: alert.siemSource,
    externalAlertId: alert.externalAlertId,
  };
  for (const k of Object.keys(structured)) if (structured[k] === undefined || structured[k] === null) delete structured[k];

  return {
    investigationId,
    alertId: alert.id,
    type: "WAZUH_ALERT",
    source: alert.siemSource.toUpperCase(),
    origin: "SYSTEM",
    timestamp: alert.receivedAt,
    title: description ?? `Alert ${alert.externalAlertId}`,
    description: `Alert received from ${alert.siemSource} (${alert.externalAlertId}).`,
    rawData: null,
    structuredData: structured,
    confidence: null,
    relevance: null,
    createdBy,
    iocIds: [],
  };
}
