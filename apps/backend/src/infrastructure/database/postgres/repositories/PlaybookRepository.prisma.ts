import { PrismaClient, Prisma } from "@prisma/client";
import {
  IPlaybookRepository,
  CreatePlaybookData,
  CreatedPlaybookRevision,
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

  async createDraft(data: CreatePlaybookData): Promise<{ playbook: Playbook; revision: CreatedPlaybookRevision }> {
    return this.prisma.$transaction(async (tx) => {
      const raw = await tx.playbook.create({
        data: {
          tenantId: data.tenantId,
          code: data.code,
          name: data.name,
          description: data.description,
          version: data.version,
          status: "DRAFT",
          triggerConditions: (data.incidentType ? { incidentType: data.incidentType } : {}) as Prisma.InputJsonValue,
          steps: { create: data.steps },
        },
        include: includeSteps,
      });
      const revision = await this.createInitialRevision(tx, raw, data);
      return { playbook: PlaybookMapper.toDomain(raw), revision };
    });
  }

  /** Revision 1, DRAFT: content is the row just created; playbookStatus is the status it takes once published. */
  protected async createInitialRevision(
    tx: Prisma.TransactionClient,
    raw: Prisma.PlaybookGetPayload<{ include: typeof includeSteps }>,
    data: CreatePlaybookData
  ): Promise<CreatedPlaybookRevision> {
    const content = {
      code: raw.code, name: raw.name, description: raw.description, triggerConditions: raw.triggerConditions, n8nWorkflowId: raw.n8nWorkflowId,
      playbookStatus: data.publishedStatus, version: data.version,
      steps: [...raw.steps].sort((a, b) => a.stepOrder - b.stepOrder).map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })),
    };
    const r = await tx.playbookRevision.create({
      data: { tenantId: raw.tenantId, playbookId: raw.id, revisionNumber: 1, version: data.version, status: "DRAFT", content: content as Prisma.InputJsonValue, createdBy: data.createdBy },
    });
    return { id: r.id, revisionNumber: r.revisionNumber, status: "DRAFT", version: r.version };
  }

  async countExecutions(id: string): Promise<number> {
    return this.prisma.playbookExecution.count({ where: { playbookId: id } });
  }

  async revisionState(id: string, tenantId: string): Promise<{ publishedRevisionId: string | null; revisionCount: number; historyCount: number } | null> {
    const row = await this.prisma.playbook.findFirst({ where: { id, tenantId }, select: { publishedRevisionId: true, _count: { select: { revisions: true } } } });
    if (!row) return null;
    const historyCount = await this.prisma.playbookRevision.count({ where: { playbookId: id, OR: [{ status: { not: "DRAFT" } }, { publishedAt: { not: null } }] } });
    return { publishedRevisionId: row.publishedRevisionId, revisionCount: row._count.revisions, historyCount };
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.playbook.findFirstOrThrow({ where: { id, tenantId }, select: { id: true } });
      // Only never-published drafts; published / superseded revisions are also protected by a DB trigger.
      await tx.playbookRevision.deleteMany({ where: { playbookId: id, status: "DRAFT", publishedAt: null } });
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
