import { PrismaClient } from "@prisma/client";
import {
  IApprovalRepository,
  CreateApprovalData,
} from "../../../../domain/approval/repositories/IApprovalRepository";
import { Approval, ApprovalStatus } from "../../../../domain/approval/entities/Approval.entity";
import { ApprovalMapper } from "../mappers/Approval.mapper";

const includeRecommendation = { recommendation: true } as const;

export class PrismaApprovalRepository implements IApprovalRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Approval | null> {
    const raw = await this.prisma.approval.findFirst({
      where: { id, recommendation: { tenantId } },
      include: includeRecommendation,
    });
    return raw ? ApprovalMapper.toDomain(raw) : null;
  }

  async findByRecommendation(recommendationId: string, tenantId: string): Promise<Approval[]> {
    const rows = await this.prisma.approval.findMany({
      where: { recommendationId, recommendation: { tenantId } },
      include: includeRecommendation,
      orderBy: [{ createdAt: "asc" }, { stepOrder: "asc" }],
    });
    return rows.map(ApprovalMapper.toDomain);
  }

  async findByResponse(responseId: string, tenantId: string): Promise<Approval[]> {
    const rows = await this.prisma.approval.findMany({
      where: { responseId, recommendation: { tenantId } },
      include: includeRecommendation,
      orderBy: [{ createdAt: "asc" }, { stepOrder: "asc" }],
    });
    return rows.map(ApprovalMapper.toDomain);
  }

  async create(data: CreateApprovalData): Promise<Approval> {
    if (!data.recommendationId) {
      throw new Error("ApprovalRepository.create: recommendationId is required until the Response module exists");
    }
    const raw = await this.prisma.approval.create({
      data: {
        recommendationId: data.recommendationId,
        responseId: data.responseId,
        approvalRole: data.approvalRole,
        reason: data.reason,
        status: data.status ?? "pending",
        stepOrder: data.stepOrder ?? 1,
      },
      include: includeRecommendation,
    });
    return ApprovalMapper.toDomain(raw);
  }

  async activate(id: string, tenantId: string): Promise<Approval> {
    await this.prisma.approval.findFirstOrThrow({ where: { id, status: "waiting", recommendation: { tenantId } } });
    const raw = await this.prisma.approval.update({ where: { id }, data: { status: "pending" }, include: includeRecommendation });
    return ApprovalMapper.toDomain(raw);
  }

  async cancel(ids: string[], tenantId: string): Promise<void> {
    if (!ids.length) return;
    await this.prisma.approval.updateMany({ where: { id: { in: ids }, status: "waiting", recommendation: { tenantId } }, data: { status: "cancelled" } });
  }

  async decide(
    id: string,
    tenantId: string,
    data: { status: ApprovalStatus; decidedBy: string; comment: string | null }
  ): Promise<Approval> {
    await this.prisma.approval.findFirstOrThrow({ where: { id, status: "pending", recommendation: { tenantId } } });
    const raw = await this.prisma.approval.update({
      where: { id },
      data: { status: data.status, decidedBy: data.decidedBy, decidedAt: new Date(), comment: data.comment },
      include: includeRecommendation,
    });
    return ApprovalMapper.toDomain(raw);
  }
}
