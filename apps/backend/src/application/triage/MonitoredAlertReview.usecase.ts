import { IAlertRepository } from "../../domain/alert/repositories/IAlertRepository";
import { summarizeAlert } from "../../domain/alert/alertSummary";
import { AuditLogger } from "../../infrastructure/database/postgres/repositories/AuditLogger";
import { InAppNotifier } from "../notification/services/InAppNotifier";

/**
 * Legacy MONITORING alerts (the MONITOR decision is retired) whose review date has passed go back to the review queue
 * (MONITORING -> NEW, Needs review). Never closes an alert, never opens an incident. Idempotent: an alert moves (and is
 * audited / notified) only once — a second run finds it no longer MONITORING.
 */
export class ReturnDueMonitoredAlertsUseCase {
  constructor(
    private readonly alerts: IAlertRepository,
    private readonly auditLogger: AuditLogger,
    private readonly inApp?: InAppNotifier,
    private readonly clock: () => Date = () => new Date()
  ) {}

  async execute(limit = 100): Promise<{ returned: string[] }> {
    const now = this.clock();
    const returned: string[] = [];
    for (const due of await this.alerts.findDueMonitors(now, limit)) {
      const back = await this.alerts.returnDueMonitor(due.id, due.tenantId, now);
      if (!back) continue; // someone else (or an earlier run) already moved it
      returned.push(back.id);
      await this.auditLogger.record({
        tenantId: back.tenantId,
        actor: "system",
        action: "ALERT_REVIEW_DUE",
        entity: "Alert",
        entityId: back.id,
        metadata: { alertId: back.id, reviewAt: due.reviewAt?.toISOString() ?? null, monitorReason: due.monitorReason, previousState: "MONITORING", workflowState: back.workflowState },
      });
      const s = summarizeAlert(back.rawPayload);
      await this.inApp?.notify({
        tenantId: back.tenantId,
        eventType: "ALERT_REVIEW_DUE",
        roles: ["SOC"],
        incidentId: null,
        alertId: back.id,
        title: `Monitored ${back.severity.toUpperCase()} alert due for review: ${s.ruleDescription ?? back.externalAlertId}`,
        body: due.monitorReason ? `Monitoring reason: ${due.monitorReason}` : null,
      });
    }
    return { returned };
  }
}
