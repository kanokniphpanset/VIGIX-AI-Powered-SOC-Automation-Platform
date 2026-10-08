import { Prisma, PrismaClient } from "@prisma/client";
import { IRecommendationAuditRepository, RecommendationAuditRecord, SubtypeAuditMode } from "../../../../domain/recommendation/repositories/IRecommendationAuditRepository";

export class PrismaRecommendationAuditRepository implements IRecommendationAuditRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async save(r: RecommendationAuditRecord): Promise<void> {
    await this.prisma.recommendationAudit.create({
      data: {
        tenantId: r.tenantId, incidentId: r.incidentId, recommendationId: r.recommendationId, investigationNumber: r.investigationNumber,
        mode: r.mode, knowledgeVersion: r.knowledgeVersion, knowledgeStatus: r.knowledgeStatus, audit: r.audit as Prisma.InputJsonValue,
      },
    });
  }

  async findByRecommendation(recommendationId: string, tenantId: string) {
    return this.toRecord(await this.prisma.recommendationAudit.findFirst({ where: { recommendationId, tenantId }, orderBy: { createdAt: "desc" } }));
  }

  async findLatestByIncident(incidentId: string, tenantId: string) {
    return this.toRecord(await this.prisma.recommendationAudit.findFirst({ where: { incidentId, tenantId }, orderBy: { createdAt: "desc" } }));
  }

  private toRecord(row: Awaited<ReturnType<PrismaClient["recommendationAudit"]["findFirst"]>>) {
    if (!row) return null;
    return {
      tenantId: row.tenantId, incidentId: row.incidentId, recommendationId: row.recommendationId, investigationNumber: row.investigationNumber,
      mode: row.mode as SubtypeAuditMode, knowledgeVersion: row.knowledgeVersion, knowledgeStatus: row.knowledgeStatus, audit: row.audit, createdAt: row.createdAt,
    };
  }
}
