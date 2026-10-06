import { Prisma, PrismaClient } from "@prisma/client";
import {
  IPlaybookRevisionRepository,
  LockedPlaybook,
  PlaybookContent,
  PlaybookProjection,
  NewPlaybookRevision,
  PlaybookRevisionRecord,
  PlaybookRevisionSummary,
} from "../../../../domain/playbook/repositories/IPlaybookRevisionRepository";

/**
 * Prisma persistence for playbook publish / rollback. Constructed with AtomicWorkflow.prisma, so inside a workflow every
 * call (including the raw lock and SET CONSTRAINTS) runs on the workflow's transaction. DB triggers from migration
 * 20261006030000_playbook_revisions still guard content immutability and the publication invariant.
 */
export class PrismaPlaybookRevisionRepository implements IPlaybookRevisionRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async lockPlaybook(playbookId: string, tenantId: string): Promise<LockedPlaybook | null> {
    const rows = await this.prisma.$queryRaw<{ id: string; tenant_id: string; code: string | null; published_revision_id: string | null }[]>`
      SELECT id, tenant_id, code, published_revision_id FROM playbooks WHERE id = ${playbookId} AND tenant_id = ${tenantId} FOR UPDATE`;
    const row = rows[0];
    return row ? { id: row.id, tenantId: row.tenant_id, code: row.code, publishedRevisionId: row.published_revision_id } : null;
  }

  async findRevision(revisionId: string, tenantId: string): Promise<PlaybookRevisionRecord | null> {
    const r = await this.prisma.playbookRevision.findFirst({ where: { id: revisionId, tenantId } });
    return r
      ? { id: r.id, tenantId: r.tenantId, playbookId: r.playbookId, revisionNumber: r.revisionNumber, version: r.version, status: r.status, content: r.content,
          createdBy: r.createdBy, approvedBy: r.approvedBy, publishedBy: r.publishedBy, publishedAt: r.publishedAt }
      : null;
  }

  async listRevisions(playbookId: string, tenantId: string): Promise<PlaybookRevisionSummary[]> {
    const rows = await this.prisma.playbookRevision.findMany({ where: { playbookId, tenantId }, orderBy: { revisionNumber: "asc" } });
    return rows.map(summary);
  }

  async createDraftRevision(data: NewPlaybookRevision): Promise<PlaybookRevisionSummary> {
    const r = await this.prisma.playbookRevision.create({
      data: {
        tenantId: data.tenantId, playbookId: data.playbookId, revisionNumber: data.revisionNumber, version: data.version, status: "DRAFT",
        content: data.content as unknown as Prisma.InputJsonValue, createdBy: data.createdBy, proposalReason: data.proposalReason,
      },
    });
    return summary(r);
  }

  async updateDraftContent(revisionId: string, version: string, content: PlaybookContent): Promise<boolean> {
    const { count } = await this.prisma.playbookRevision.updateMany({
      where: { id: revisionId, status: "DRAFT" },
      data: { version, content: content as unknown as Prisma.InputJsonValue },
    });
    return count === 1;
  }

  async markSuperseded(revisionId: string): Promise<void> {
    await this.prisma.playbookRevision.update({ where: { id: revisionId }, data: { status: "SUPERSEDED" } });
  }

  async markPublished(revisionId: string, publishedBy: string, publishedAt: Date): Promise<void> {
    await this.prisma.playbookRevision.update({ where: { id: revisionId }, data: { status: "PUBLISHED", publishedBy, publishedAt } });
  }

  async setPublishedPointer(playbookId: string, revisionId: string): Promise<void> {
    await this.prisma.playbook.update({ where: { id: playbookId }, data: { publishedRevisionId: revisionId } });
  }

  async projectContent(playbookId: string, version: string, content: PlaybookContent, status?: "DRAFT"): Promise<void> {
    await this.prisma.playbook.update({
      where: { id: playbookId },
      data: {
        name: content.name,
        description: content.description,
        triggerConditions: content.triggerConditions as Prisma.InputJsonValue,
        n8nWorkflowId: content.n8nWorkflowId,
        status: status ?? content.playbookStatus,
        version,
      },
    });
    // The whole step set follows the revision (no FK references playbook_steps rows).
    await this.prisma.playbookStep.deleteMany({ where: { playbookId } });
    if (content.steps.length) {
      await this.prisma.playbookStep.createMany({
        data: content.steps.map((s) => ({ playbookId, stepOrder: s.stepOrder, title: s.title, description: s.description })),
      });
    }
  }

  async readProjection(playbookId: string): Promise<PlaybookProjection> {
    const p = await this.prisma.playbook.findUniqueOrThrow({ where: { id: playbookId }, include: { steps: { orderBy: { stepOrder: "asc" } } } });
    return {
      code: p.code, name: p.name, description: p.description, triggerConditions: p.triggerConditions, n8nWorkflowId: p.n8nWorkflowId,
      status: p.status, version: p.version,
      steps: p.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })),
    };
  }

  async assertPublicationConsistent(): Promise<void> {
    await this.prisma.$executeRaw`SET CONSTRAINTS ALL IMMEDIATE`;
  }
}

function summary(r: {
  id: string; revisionNumber: number; version: string; status: PlaybookRevisionSummary["status"]; content: unknown; createdBy: string;
  createdAt: Date; updatedAt: Date; publishedBy: string | null; publishedAt: Date | null;
}): PlaybookRevisionSummary {
  return {
    id: r.id, revisionNumber: r.revisionNumber, version: r.version, status: r.status, content: r.content, createdBy: r.createdBy,
    createdAt: r.createdAt, updatedAt: r.updatedAt, publishedBy: r.publishedBy, publishedAt: r.publishedAt,
  };
}
