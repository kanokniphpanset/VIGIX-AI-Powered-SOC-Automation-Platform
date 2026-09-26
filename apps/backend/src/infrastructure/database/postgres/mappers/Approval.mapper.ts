import { Approval as PrismaApproval, Recommendation as PrismaRecommendation } from "@prisma/client";
import { Approval, ApprovalStatus } from "../../../../domain/approval/entities/Approval.entity";

type PrismaApprovalWithRecommendation = PrismaApproval & { recommendation: PrismaRecommendation | null };

/**
 * ApprovalMapper — the `Approval` table has NO tenantId column of its own
 * (see schema.prisma's own note: it is additive on top of the legacy
 * Decision-pipeline Approval, which also has no tenantId). Every query in
 * ApprovalRepository.prisma.ts joins `recommendation` and filters by
 * `recommendation.tenantId`, so tenant isolation is enforced via that join
 * rather than a direct column — this mapper requires the join result to
 * derive `tenantId` for the domain entity.
 */
export class ApprovalMapper {
  static toDomain(raw: PrismaApprovalWithRecommendation): Approval {
    if (!raw.recommendation) {
      throw new Error("ApprovalMapper: expected recommendation to be joined for tenant derivation");
    }
    return Approval.create({
      id: raw.id,
      tenantId: raw.recommendation.tenantId,
      recommendationId: raw.recommendationId,
      responseId: raw.responseId,
      approvalRole: raw.approvalRole ?? "UNKNOWN",
      reason: raw.reason ?? "",
      status: raw.status as ApprovalStatus,
      stepOrder: raw.stepOrder ?? 1,
      requestedTo: raw.requestedTo,
      decidedBy: raw.decidedBy,
      decidedAt: raw.decidedAt,
      comment: raw.comment,
      createdAt: raw.createdAt,
    });
  }
}
