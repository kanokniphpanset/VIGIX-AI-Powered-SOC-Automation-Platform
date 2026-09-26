import { Verification as PrismaVerification } from "@prisma/client";
import { Verification, VerificationResult } from "../../../../domain/verification/entities/Verification.entity";

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

export class VerificationMapper {
  static toDomain(raw: PrismaVerification): Verification {
    return Verification.create({
      id: raw.id,
      tenantId: raw.tenantId,
      incidentId: raw.incidentId,
      responseId: raw.responseId,
      wazuhIndex: raw.wazuhIndex,
      query: raw.query,
      timeRangeStart: raw.timeRangeStart,
      timeRangeEnd: raw.timeRangeEnd,
      matchingEvents: raw.matchingEvents,
      affectedHosts: asStringArray(raw.affectedHosts),
      iocRecurrence: raw.iocRecurrence,
      spreadDetected: raw.spreadDetected,
      threatContained: raw.threatContained,
      beforeState: (raw.beforeState as Record<string, unknown> | null) ?? null,
      afterState: (raw.afterState as Record<string, unknown> | null) ?? null,
      result: raw.result as VerificationResult,
      notes: raw.notes,
      verifiedBy: raw.verifiedBy,
      verifiedAt: raw.verifiedAt,
    });
  }
}
