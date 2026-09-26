import { Runbook as PrismaRunbook } from "@prisma/client";
import { Runbook, RunbookStatus } from "../../../../domain/runbook/entities/Runbook.entity";

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

export class RunbookMapper {
  static toDomain(raw: PrismaRunbook): Runbook {
    return Runbook.create({
      id: raw.id,
      tenantId: raw.tenantId,
      code: raw.code,
      name: raw.name,
      version: raw.version,
      status: raw.status as RunbookStatus,
      description: raw.description,
      trigger: raw.trigger,
      preconditions: asStringArray(raw.preconditions),
      objective: raw.objective,
      procedure: asStringArray(raw.procedure),
      decisionPoints: asStringArray(raw.decisionPoints),
      expectedResult: raw.expectedResult,
      escalation: raw.escalation,
      verificationCriteria: asStringArray(raw.verificationCriteria),
      createdAt: raw.createdAt,
      updatedAt: raw.updatedAt,
    });
  }
}
