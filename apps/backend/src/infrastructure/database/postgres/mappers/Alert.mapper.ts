import { Alert as PrismaAlert } from "@prisma/client";
import { Alert, AlertSeverity, AlertStatus, AlertTriageDisposition, SiemSource } from "../../../../domain/alert/entities/Alert.entity";
import type { AlertWorkflowState } from "../../../../domain/alert/triageWorkflow";

/**
 * Translates between the Prisma-generated Alert model and the domain Alert entity.
 * This is the ONLY place in the codebase that knows both shapes.
 */
export class AlertMapper {
  static toDomain(raw: PrismaAlert): Alert {
    return Alert.create({
      id: raw.id,
      tenantId: raw.tenantId,
      externalAlertId: raw.externalAlertId,
      siemSource: raw.siemSource as SiemSource,
      rawPayload: raw.rawPayload as Record<string, unknown>,
      severity: raw.severity as AlertSeverity,
      status: raw.status as AlertStatus,
      receivedAt: raw.receivedAt,
      createdAt: raw.createdAt,
      triage:
        raw.triageDisposition && raw.triagedBy && raw.triagedAt
          ? { disposition: raw.triageDisposition as AlertTriageDisposition, note: raw.triageNote, triagedBy: raw.triagedBy, triagedAt: raw.triagedAt }
          : null,
      workflowState: (raw.workflowState ?? "NEW") as AlertWorkflowState,
      reviewAt: raw.reviewAt,
      monitorReason: raw.monitorReason,
      closedAt: raw.closedAt,
    });
  }
}
