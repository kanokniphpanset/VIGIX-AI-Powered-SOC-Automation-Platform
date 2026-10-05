import { IIncidentRepository, MergeBlockedError, MergeBlockReason } from "../../../domain/incident/repositories/IIncidentRepository";
import { IAlertRepository } from "../../../domain/alert/repositories/IAlertRepository";
import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";
import { Result } from "../../../shared/result/Result";

export type MergeAlertsFailure =
  | { code: "ALERT_NOT_FOUND"; alertIds: string[] }
  | { code: "INCIDENT_NOT_FOUND" }
  | { code: MergeBlockReason; incidentId: string };

/**
 * MergeAlertsIntoIncidentUseCase — "Set Group" (analyst correlation, Frontend P0). Ingestion opens one incident
 * per alert automatically; when an analyst decides related alerts are the same attack, this moves them into the
 * primary incident. A selected alert that already belongs to another incident brings that WHOLE incident along
 * (its alerts move, it is closed as merged) — never half of it. Refused, with nothing written, if the target is
 * not open or a source incident is resolved or already has response plans (that work must not be orphaned).
 *
 * The merged alerts become WAZUH_ALERT evidence (+ their IOCs) of the target's Investigation #1 via the existing
 * syncIncident, so the next Recommendation cycle is grounded in them. This is analyst-driven correlation; automatic
 * correlation of a NEW alert into an open incident happens at ingestion (IngestAlertFromSiem + alertCorrelation.ts).
 */
export class MergeAlertsIntoIncidentUseCase {
  constructor(
    private readonly incidents: IIncidentRepository,
    private readonly alerts: IAlertRepository,
    private readonly investigations: IInvestigationRepository,
    private readonly auditLogger: AuditLogger
  ) {}

  async execute(input: { tenantId: string; incidentId: string; alertIds: string[]; actor: string }): Promise<Result<{ addedAlertIds: string[] }, MergeAlertsFailure>> {
    const target = await this.incidents.findById(input.incidentId, input.tenantId);
    if (!target) return Result.fail({ code: "INCIDENT_NOT_FOUND" });

    const alertIds = [...new Set(input.alertIds)];
    const found = await Promise.all(alertIds.map((id) => this.alerts.findById(id, input.tenantId)));
    const missing = alertIds.filter((_, i) => !found[i]);
    if (missing.length > 0) return Result.fail({ code: "ALERT_NOT_FOUND", alertIds: missing });

    const linked = await this.incidents.findLinkedIncidents(alertIds, input.tenantId);
    const sourceIncidentIds = [...new Set(alertIds.map((id) => linked.get(id)).filter((i): i is string => !!i && i !== target.id))];
    const unlinkedAlertIds = alertIds.filter((id) => !linked.has(id));

    let added: string[];
    try {
      added = await this.incidents.absorbIntoIncident({ tenantId: input.tenantId, targetIncidentId: target.id, sourceIncidentIds, unlinkedAlertIds, actor: input.actor });
    } catch (err) {
      if (err instanceof MergeBlockedError) return Result.fail({ code: err.reason, incidentId: err.incidentId });
      throw err;
    }

    await this.investigations.syncIncident(target.id, input.tenantId);

    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "ALERTS_MERGED",
      entity: "Incident",
      entityId: target.id,
      metadata: { selectedAlertIds: alertIds, addedAlertIds: added, mergedIncidentIds: sourceIncidentIds },
    });

    return Result.ok({ addedAlertIds: added });
  }
}
