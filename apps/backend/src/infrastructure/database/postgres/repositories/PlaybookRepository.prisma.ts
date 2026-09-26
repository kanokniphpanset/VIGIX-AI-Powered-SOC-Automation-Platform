import { PrismaClient, Prisma } from "@prisma/client";
import {
  IPlaybookRepository,
  CreatePlaybookData,
  UpdatePlaybookData,
} from "../../../../domain/playbook/repositories/IPlaybookRepository";
import { Playbook } from "../../../../domain/playbook/entities/Playbook.entity";
import { PlaybookMapper } from "../mappers/Playbook.mapper";

const includeSteps = { steps: true } as const;

export class PrismaPlaybookRepository implements IPlaybookRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Playbook | null> {
    const raw = await this.prisma.playbook.findFirst({ where: { id, tenantId }, include: includeSteps });
    return raw ? PlaybookMapper.toDomain(raw) : null;
  }

  async findByCode(code: string, tenantId: string): Promise<Playbook | null> {
    const raw = await this.prisma.playbook.findFirst({ where: { code, tenantId }, include: includeSteps });
    return raw ? PlaybookMapper.toDomain(raw) : null;
  }

  async findAll(tenantId: string): Promise<Playbook[]> {
    const rows = await this.prisma.playbook.findMany({ where: { tenantId }, include: includeSteps });
    return rows.map(PlaybookMapper.toDomain);
  }

  async create(data: CreatePlaybookData): Promise<Playbook> {
    const raw = await this.prisma.playbook.create({
      data: {
        tenantId: data.tenantId,
        code: data.code,
        name: data.name,
        description: data.description,
        version: data.version,
        status: data.status,
        triggerConditions: (data.incidentType ? { incidentType: data.incidentType } : {}) as Prisma.InputJsonValue,
        steps: { create: data.steps },
      },
      include: includeSteps,
    });
    return PlaybookMapper.toDomain(raw);
  }

  async countExecutions(id: string): Promise<number> {
    return this.prisma.playbookExecution.count({ where: { playbookId: id } });
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.playbook.findFirstOrThrow({ where: { id, tenantId }, select: { id: true } });
      await tx.playbookStep.deleteMany({ where: { playbookId: id } });
      await tx.playbook.delete({ where: { id } });
    });
  }

  async update(id: string, tenantId: string, data: UpdatePlaybookData): Promise<Playbook> {
    const { incidentType, steps, ...fields } = data;
    const raw = await this.prisma.$transaction(async (tx) => {
      const current = await tx.playbook.findFirstOrThrow({ where: { id, tenantId } });
      // incidentType lives inside triggerConditions: merge it, never drop scope / mitreTechniques / allowedActions.
      let triggerConditions: Prisma.InputJsonValue | undefined;
      if (incidentType !== undefined) {
        const existing =
          current.triggerConditions && typeof current.triggerConditions === "object" && !Array.isArray(current.triggerConditions)
            ? { ...(current.triggerConditions as Record<string, unknown>) }
            : {};
        if (incidentType) existing.incidentType = incidentType;
        else delete existing.incidentType;
        triggerConditions = existing as Prisma.InputJsonValue;
      }
      if (steps) {
        await tx.playbookStep.deleteMany({ where: { playbookId: id } });
        await tx.playbookStep.createMany({ data: steps.map((s) => ({ playbookId: id, stepOrder: s.stepOrder, title: s.title, description: s.description })) });
      }
      return tx.playbook.update({
        where: { id },
        data: { ...fields, ...(triggerConditions !== undefined ? { triggerConditions } : {}) },
        include: includeSteps,
      });
    });
    return PlaybookMapper.toDomain(raw);
  }
}
