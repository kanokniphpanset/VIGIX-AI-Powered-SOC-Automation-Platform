import { extractAlertIocs } from "../../../domain/investigation/alertIocs";
import { summarizeAlert } from "../../../domain/alert/alertSummary";
import { Result } from "../../../shared/result/Result";

/**
 * Related-alert evidence for an incident's investigation (READ ONLY). 1 Alert = 1 Incident is kept: nothing is
 * grouped, moved or linked here. It only lists OTHER Wazuh alerts that may belong to the same activity so the SOC can
 * look at their indicators and — if the SOC confirms the relation — record one on this incident with its source alert
 * and a reason (POST /api/v1/investigations/:id/iocs with sourceAlertId). Deterministic criteria, no AI:
 *   SAME_HOST   the same monitored host (Wazuh agent) within ±24 h of the incident's alert(s)
 *   SHARED_IOC  an indicator of this incident appears in the alert's payload, within ±7 days
 */

export const SAME_HOST_WINDOW_MS = 24 * 3600_000;
export const SHARED_IOC_WINDOW_MS = 7 * 24 * 3600_000;
export const RELATED_ALERT_LIMIT = 25;

export interface IncidentAlertFacts {
  alertIds: string[];
  alerts: { rawPayload: unknown; receivedAt: Date }[];
  /** Indicator values already recorded on this incident (any investigation). */
  iocValues: string[];
}

export interface CandidateAlertRow {
  id: string;
  externalAlertId: string;
  severity: string;
  receivedAt: Date;
  rawPayload: unknown;
  incidentId: string | null;
}

export interface RelatedAlertQuery {
  tenantId: string;
  excludeAlertIds: string[];
  hosts: string[];
  hostFrom: Date;
  hostTo: Date;
  iocValues: string[];
  iocFrom: Date;
  iocTo: Date;
  limit: number;
}

export interface IRelatedAlertEvidenceReader {
  incidentFacts(incidentId: string, tenantId: string): Promise<IncidentAlertFacts | null>;
  candidates(query: RelatedAlertQuery): Promise<CandidateAlertRow[]>;
}

export interface RelatedAlertEvidence {
  alertId: string;
  externalAlertId: string;
  severity: string;
  ruleId: string | null;
  ruleDescription: string | null;
  ruleLevel: number | null;
  host: string | null;
  receivedAt: string;
  /** The alert's own incident (it stays there), or null. */
  incidentId: string | null;
  relation: ("SAME_HOST" | "SHARED_IOC")[];
  sharedIocs: string[];
  iocs: { iocType: string; value: string; path: string; onIncident: boolean }[];
}

const lc = (v: string) => v.trim().toLowerCase();

export class ListRelatedAlertEvidenceUseCase {
  constructor(private readonly reader: IRelatedAlertEvidenceReader) {}

  async execute(input: { tenantId: string; incidentId: string }): Promise<Result<{ items: RelatedAlertEvidence[]; criteria: Record<string, unknown> }, "INCIDENT_NOT_FOUND">> {
    const facts = await this.reader.incidentFacts(input.incidentId, input.tenantId);
    if (!facts) return Result.fail("INCIDENT_NOT_FOUND");

    const hosts = [...new Set(facts.alerts.map((a) => summarizeAlert(a.rawPayload).host).filter((h): h is string => !!h).map(lc))];
    const ownIocs = facts.alerts.flatMap((a) => extractAlertIocs(a.rawPayload).map((i) => i.value));
    // Only specific indicators are hunted for (short/generic values such as a bare user name would match everything).
    const iocValues = [...new Set([...ownIocs, ...facts.iocValues].map(lc))].filter((v) => v.length >= 7);
    const times = facts.alerts.map((a) => a.receivedAt.getTime());
    const first = times.length ? Math.min(...times) : Date.now();
    const last = times.length ? Math.max(...times) : Date.now();

    const rows = await this.reader.candidates({
      tenantId: input.tenantId,
      excludeAlertIds: facts.alertIds,
      hosts,
      hostFrom: new Date(first - SAME_HOST_WINDOW_MS),
      hostTo: new Date(last + SAME_HOST_WINDOW_MS),
      iocValues,
      iocFrom: new Date(first - SHARED_IOC_WINDOW_MS),
      iocTo: new Date(last + SHARED_IOC_WINDOW_MS),
      limit: RELATED_ALERT_LIMIT,
    });

    const onIncident = new Set(facts.iocValues.map(lc));
    const items = rows.map((r): RelatedAlertEvidence => {
      const s = summarizeAlert(r.rawPayload);
      const text = JSON.stringify(r.rawPayload ?? {}).toLowerCase();
      const sharedIocs = iocValues.filter((v) => text.includes(v));
      const t = r.receivedAt.getTime();
      const relation: RelatedAlertEvidence["relation"] = [];
      if (s.host && hosts.includes(lc(s.host)) && t >= first - SAME_HOST_WINDOW_MS && t <= last + SAME_HOST_WINDOW_MS) relation.push("SAME_HOST");
      if (sharedIocs.length) relation.push("SHARED_IOC");
      return {
        alertId: r.id,
        externalAlertId: r.externalAlertId,
        severity: r.severity,
        ruleId: s.ruleId,
        ruleDescription: s.ruleDescription,
        ruleLevel: s.ruleLevel,
        host: s.host,
        receivedAt: r.receivedAt.toISOString(),
        incidentId: r.incidentId,
        relation,
        sharedIocs,
        iocs: extractAlertIocs(r.rawPayload).map((i) => ({ iocType: i.iocType, value: i.value, path: i.path, onIncident: onIncident.has(lc(i.value)) })),
      };
    });

    return Result.ok({
      items,
      criteria: { hosts, sameHostWindowHours: SAME_HOST_WINDOW_MS / 3600_000, sharedIocWindowDays: SHARED_IOC_WINDOW_MS / 86400_000, iocValues },
    });
  }
}
