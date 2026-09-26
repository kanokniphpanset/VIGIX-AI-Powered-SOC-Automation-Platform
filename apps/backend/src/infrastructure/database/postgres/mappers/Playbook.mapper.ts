import { Playbook as PrismaPlaybook, PlaybookStep as PrismaPlaybookStep } from "@prisma/client";
import { Playbook } from "../../../../domain/playbook/entities/Playbook.entity";

type PrismaPlaybookWithSteps = PrismaPlaybook & { steps: PrismaPlaybookStep[] };

export class PlaybookMapper {
  static toDomain(raw: PrismaPlaybookWithSteps): Playbook {
    return Playbook.create({
      id: raw.id,
      tenantId: raw.tenantId,
      code: raw.code,
      name: raw.name,
      description: raw.description,
      version: raw.version,
      status: raw.status as "ACTIVE" | "DEPRECATED" | null,
      triggerConditions:
        raw.triggerConditions && typeof raw.triggerConditions === "object" && !Array.isArray(raw.triggerConditions)
          ? (raw.triggerConditions as Record<string, unknown>)
          : {},
      steps: raw.steps.map((s) => ({
        id: s.id,
        stepOrder: s.stepOrder,
        title: s.title,
        description: s.description,
      })),
    });
  }
}
