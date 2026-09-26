import { ApprovalService } from "../../approval/services/ApprovalService";
import { AuditLogger } from "../../../infrastructure/database/postgres/repositories/AuditLogger";

/**
 * Records who owns an incident (after each AI analysis job and after a human severity change): Policy (ApprovalService.evaluate — the same
 * evaluation Response/Approval use, audited as POLICY_EVALUATED) decides responsibleRole from the incident SEVERITY
 * (SOC for LOW/MEDIUM, IR_TEAM for HIGH/CRITICAL in the seeded rules). Read-only: nothing is approved, created or executed; audited as INCIDENT_ASSIGNED.
 */
export class IncidentAssignmentService {
  constructor(private readonly approvalService: ApprovalService, private readonly auditLogger: AuditLogger) {}

  async assign(input: { tenantId: string; incidentId: string; actor: string; trigger: string }): Promise<void> {
    const { policy, severity } = await this.approvalService.evaluate({ tenantId: input.tenantId, incidentId: input.incidentId });
    await this.auditLogger.record({
      tenantId: input.tenantId,
      actor: input.actor,
      action: "INCIDENT_ASSIGNED",
      entity: "Incident",
      entityId: input.incidentId,
      metadata: {
        trigger: input.trigger,
        responsibleRole: policy.responsibleRole,
        executorRole: policy.executorRole,
        severity,
        priority: policy.priority,
        matchedPolicies: policy.matchedPolicies,
      },
    });
  }
}
