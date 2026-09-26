import { PrismaClient, Prisma } from "@prisma/client";
import { PrismaAlertRepository } from "./repositories/AlertRepository.prisma";
import { PrismaIncidentRepository } from "./repositories/IncidentRepository.prisma";
import { AuditLogger } from "./repositories/AuditLogger";
import { PrismaInAppNotificationRepository } from "./repositories/InAppNotificationRepository.prisma";
import { InAppNotifier } from "../../../application/notification/services/InAppNotifier";
import { ReturnDueMonitoredAlertsUseCase } from "../../../application/triage/MonitoredAlertReview.usecase";
import { TriageAlertUseCase } from "../../../application/triage/SocTriage.usecases";
import { CreateIncidentUseCase } from "../../../application/incident/use-cases/CreateIncident.usecase";

/** Composition boundary: each transition, its audit, and its in-app notification commit together.
 * No network call runs inside these transactions. A failed audit/notification rolls the transition back,
 * so the scheduler can retry. Conditional writes serialize competing analysts (no claim) and scheduler instances.
 */
export function alertWorkflow(prisma: PrismaClient, jobs?: { enqueue(input: { tenantId: string; incidentId: string; alertId: string; trigger: "MANUAL" }): Promise<unknown> }) {
  const parts = (tx: Prisma.TransactionClient) => ({ alerts: new PrismaAlertRepository(tx), incidents: new PrismaIncidentRepository(tx), audit: new AuditLogger(tx), notifications: new InAppNotifier(new PrismaInAppNotificationRepository(tx), true) });
  return {
    review: { execute: (limit = 100) => prisma.$transaction(tx => { const p = parts(tx); return new ReturnDueMonitoredAlertsUseCase(p.alerts, p.audit, p.notifications).execute(limit); }, { timeout: 30000 }) },
    triage: { execute: async (input: Parameters<TriageAlertUseCase["execute"]>[0]) => {
      const result = await prisma.$transaction(tx => {
        const p = parts(tx);
        const create = new CreateIncidentUseCase(p.incidents, p.alerts, p.audit, undefined, p.notifications);
        return new TriageAlertUseCase(p.alerts, p.incidents, p.audit, create).execute(input);
      });
      if (result.isSuccess && result.value.incidentId) {
        await jobs?.enqueue({ tenantId: input.tenantId, incidentId: result.value.incidentId, alertId: input.alertId, trigger: "MANUAL" })
          .catch(err => console.error("Incident analysis queue unavailable; manual Run AI Analysis remains available", err instanceof Error ? err.message : err));
      }
      return result;
    } },
  };
}
