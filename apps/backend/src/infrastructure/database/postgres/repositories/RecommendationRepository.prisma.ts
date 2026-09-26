import { PrismaClient, Prisma } from "@prisma/client";
import {
  IRecommendationRepository,
  CreateRecommendationData,
} from "../../../../domain/recommendation/repositories/IRecommendationRepository";
import { Recommendation, RecommendationStatus } from "../../../../domain/recommendation/entities/Recommendation.entity";
import { RecommendationMapper } from "../mappers/Recommendation.mapper";

const includeSteps = { steps: true } as const;

export class PrismaRecommendationRepository implements IRecommendationRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Recommendation | null> {
    const raw = await this.prisma.recommendation.findFirst({ where: { id, tenantId }, include: includeSteps });
    return raw ? RecommendationMapper.toDomain(raw) : null;
  }

  async findByIncidentAndNumber(incidentId: string, recommendationNumber: number, tenantId: string): Promise<Recommendation | null> {
    const raw = await this.prisma.recommendation.findFirst({
      where: { incidentId, recommendationNumber, tenantId },
      include: includeSteps,
    });
    return raw ? RecommendationMapper.toDomain(raw) : null;
  }

  async findAllByIncident(incidentId: string, tenantId: string): Promise<Recommendation[]> {
    const rows = await this.prisma.recommendation.findMany({
      where: { incidentId, tenantId },
      include: includeSteps,
      orderBy: { recommendationNumber: "asc" },
    });
    return rows.map(RecommendationMapper.toDomain);
  }

  async getNextRecommendationNumber(incidentId: string, tenantId: string): Promise<number> {
    const latest = await this.prisma.recommendation.findFirst({
      where: { incidentId, tenantId },
      orderBy: { recommendationNumber: "desc" },
      select: { recommendationNumber: true },
    });
    return (latest?.recommendationNumber ?? 0) + 1;
  }

  async create(data: CreateRecommendationData): Promise<Recommendation> {
    // Link to the Investigation row of the cycle this recommendation was generated from (Alert -> ... -> Recommendation).
    const investigation = await this.prisma.investigation.findUnique({
      where: { incidentId_investigationNumber: { incidentId: data.incidentId, investigationNumber: data.investigationNumber } },
      select: { id: true },
    });
    // One PlaybookSnapshot per investigation cycle: what this cycle's recommendation was grounded in
    // (selected playbook, action runbooks, policy results). Regenerating within the same cycle refreshes it.
    let snapshotId: string | null = null;
    if (data.snapshot && investigation) {
      const snap = data.snapshot;
      const content = {
        playbookCode: snap.playbookCode,
        playbookVersion: snap.playbookVersion,
        procedureCode: snap.procedureCode,
        procedureVersion: snap.procedureVersion,
        procedureContent: snap.procedureContent as Prisma.InputJsonValue,
        policyResult: snap.policyResult as Prisma.InputJsonValue,
      };
      const snapshot = await this.prisma.playbookSnapshot.upsert({
        where: { incidentId_investigationNumber: { incidentId: data.incidentId, investigationNumber: data.investigationNumber } },
        update: content,
        create: {
          ...content,
          tenantId: data.tenantId,
          incidentId: data.incidentId,
          investigationId: investigation.id,
          investigationNumber: data.investigationNumber,
          code: `SNAP-${data.incidentId}-${data.investigationNumber}`,
        },
      });
      snapshotId = snapshot.id;
    }

    const raw = await this.prisma.recommendation.create({
      data: {
        investigationId: investigation?.id ?? null,
        snapshotId,
        tenantId: data.tenantId,
        incidentId: data.incidentId,
        investigationNumber: data.investigationNumber,
        recommendationNumber: data.recommendationNumber,
        status: data.status,
        summary: data.summary,
        createdBy: data.createdBy,
        steps: {
          create: data.steps.map((s) => ({
            stepOrder: s.stepOrder,
            title: s.title,
            objective: s.objective,
            actionId: s.actionId,
            target: s.target,
            reason: s.reason,
            evidence: s.evidence as Prisma.InputJsonValue,
            sourceRunbookId: s.sourceRunbookId,
            precondition: s.precondition,
            expectedResult: s.expectedResult,
            requiresApproval: s.requiresApproval,
            phase: "ACTION",
            instructions: s.instructions as unknown as Prisma.InputJsonValue,
            verificationCriteria: s.verificationCriteria,
          })),
        },
      },
      include: includeSteps,
    });
    return RecommendationMapper.toDomain(raw);
  }

  async updateStatus(id: string, tenantId: string, status: RecommendationStatus): Promise<Recommendation> {
    await this.prisma.recommendation.findFirstOrThrow({ where: { id, tenantId } });
    const raw = await this.prisma.recommendation.update({ where: { id }, data: { status }, include: includeSteps });
    return RecommendationMapper.toDomain(raw);
  }

  async supersedePrevious(incidentId: string, tenantId: string, keepRecommendationId: string): Promise<void> {
    await this.prisma.recommendation.updateMany({
      where: { incidentId, tenantId, id: { not: keepRecommendationId }, status: { in: ["GENERATED", "VALIDATED"] } },
      data: { status: "SUPERSEDED" },
    });
  }
}
