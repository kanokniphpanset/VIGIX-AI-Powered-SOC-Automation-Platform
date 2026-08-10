import { Alert as PrismaAlert } from "@prisma/client";
import { Alert, AlertSeverity, AlertStatus, SiemSource } from "../../../../domain/alert/entities/Alert.entity";

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
    });
  }
}
