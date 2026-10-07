import { PrismaClient, Prisma } from "@prisma/client";
import { canonicalRevisionContent, hashRevisionContent, pinRevision, PlaybookProvenanceError } from "../../../../domain/playbook/PlaybookRevisionProvenance";
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
    return this.prisma.$transaction(async (tx) => {
      // Serialize numbering for this incident only. Snapshot and recommendation commit together,
      // so a failed recommendation insert cannot leave an unreferenced snapshot behind.
      const owned = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM incidents WHERE id = ${data.incidentId} AND tenant_id = ${data.tenantId} FOR UPDATE`;
      if (!owned.length) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_NOT_FOUND");
      const latest = await tx.recommendation.findFirst({
        where: { incidentId: data.incidentId, tenantId: data.tenantId },
        orderBy: { recommendationNumber: "desc" }, select: { recommendationNumber: true },
      });
      const recommendationNumber = Math.max(data.recommendationNumber, (latest?.recommendationNumber ?? 0) + 1);
      // Link to the Investigation row of the cycle this recommendation was generated from (Alert -> ... -> Recommendation).
      const investigation = await tx.investigation.findUnique({
        where: { incidentId_investigationNumber: { incidentId: data.incidentId, investigationNumber: data.investigationNumber } },
        select: { id: true },
      });
      if (!investigation) throw new PlaybookProvenanceError("RECOMMENDATION_INVESTIGATION_REQUIRED");
      if (!data.snapshot || !data.provenance) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
      if (data.provenance.tenantId !== data.tenantId) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_TENANT_MISMATCH");
      // Copy once before awaiting: persistence never follows the current published pointer.
      const pinned = pinRevision(data.provenance);
      if (pinned.contentHash !== data.provenance.contentHash) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_MISMATCH");
      const revision = await tx.playbookRevision.findFirst({
        where: { id: pinned.revisionId, tenantId: data.tenantId, playbook: { tenantId: data.tenantId } },
      });
      // Wrong-tenant IDs are indistinguishable from missing IDs; no cross-tenant lookup.
      if (!revision) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_NOT_FOUND");
      if (revision.playbookId !== pinned.playbookId || revision.version !== pinned.version ||
          !["PUBLISHED", "SUPERSEDED"].includes(revision.status) || !revision.publishedAt ||
          data.snapshot.playbookVersion !== pinned.version ||
          (revision.content as Record<string, unknown> | null)?.code !== data.snapshot.playbookCode ||
          hashRevisionContent(revision.content) !== pinned.contentHash ||
          canonicalRevisionContent(revision.content) !== canonicalRevisionContent(pinned.content))
        throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_MISMATCH");
      // One immutable grounding artifact per successful generation, even when content is identical.
      let snapshotId: string | null = null;
      if (data.snapshot && investigation) {
        const snap = data.snapshot;
        const content = {
          playbookId: pinned.playbookId,
          playbookRevisionId: pinned.revisionId,
          contentHash: pinned.contentHash,
          frozenRevisionContent: pinned.content as Prisma.InputJsonValue,
          playbookCode: snap.playbookCode,
          playbookVersion: snap.playbookVersion,
          procedureCode: snap.procedureCode,
          procedureVersion: snap.procedureVersion,
          procedureContent: snap.procedureContent as Prisma.InputJsonValue,
          policyResult: snap.policyResult as Prisma.InputJsonValue,
        };
        const snapshot = await tx.playbookSnapshot.create({
          data: {
            ...content,
            tenantId: data.tenantId,
            incidentId: data.incidentId,
            investigationId: investigation.id,
            investigationNumber: data.investigationNumber,
            code: `SNAP-${data.incidentId}-${data.investigationNumber}-${recommendationNumber}`,
          },
        });
        snapshotId = snapshot.id;
      }

      const raw = await tx.recommendation.create({
        data: {
          investigationId: investigation?.id ?? null,
          snapshotId,
          tenantId: data.tenantId,
          incidentId: data.incidentId,
          investigationNumber: data.investigationNumber,
          recommendationNumber,
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
    });
  }

  async updateStatus(id: string, tenantId: string, status: RecommendationStatus): Promise<Recommendation> {
    await this.prisma.recommendation.findFirstOrThrow({ where: { id, tenantId } });
    const raw = await this.prisma.recommendation.update({ where: { id }, data: { status }, include: includeSteps });
    return RecommendationMapper.toDomain(raw);
  }

  async supersedePrevious(incidentId: string, tenantId: string, keepRecommendationId: string): Promise<void> {
    const keep = await this.prisma.recommendation.findFirstOrThrow({
      where: { id: keepRecommendationId, incidentId, tenantId }, select: { recommendationNumber: true },
    });
    await this.prisma.recommendation.updateMany({
      where: { incidentId, tenantId, recommendationNumber: { lt: keep.recommendationNumber }, status: { in: ["GENERATED", "VALIDATED"] } },
      data: { status: "SUPERSEDED" },
    });
  }
}
