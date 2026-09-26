import { PrismaClient, Prisma } from "@prisma/client";
import {
  IResponsePlanRepository,
  CreateResponsePlanData,
  RecordStepExecutionData,
} from "../../../../domain/response/repositories/IResponsePlanRepository";
import { ResponsePlan } from "../../../../domain/response/entities/ResponsePlan.entity";
import { ResponsePlanMapper } from "../mappers/ResponsePlan.mapper";

export class PrismaResponsePlanRepository
  implements IResponsePlanRepository
{
  constructor(private readonly prisma: PrismaClient) {}

  async findById(
    id: string,
    tenantId: string
  ): Promise<ResponsePlan | null> {
    const raw = await this.prisma.responsePlan.findFirst({
      where: {
        id,
        tenantId,
      },
    });

    return raw ? ResponsePlanMapper.toDomain(raw) : null;
  }

  async findByRecommendation(
    recommendationId: string,
    tenantId: string
  ): Promise<ResponsePlan[]> {
    const rows = await this.prisma.responsePlan.findMany({
      where: {
        recommendationId,
        tenantId,
      },
      orderBy: {
        createdAt: "asc",
      },
    });

    return rows.map(ResponsePlanMapper.toDomain);
  }

  async findAll(
    tenantId: string,
    limit = 25,
    offset = 0,
    incidentId?: string
  ): Promise<ResponsePlan[]> {
    const rows = await this.prisma.responsePlan.findMany({
      where: {
        tenantId,
        ...(incidentId ? { incidentId } : {}),
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
      skip: offset,
    });

    return rows.map(ResponsePlanMapper.toDomain);
  }

  async countAll(tenantId: string, incidentId?: string): Promise<number> {
    return this.prisma.responsePlan.count({
      where: {
        tenantId,
        ...(incidentId ? { incidentId } : {}),
      },
    });
  }

  async create(
    data: CreateResponsePlanData
  ): Promise<ResponsePlan> {
    const raw = await this.prisma.responsePlan.create({
      data: {
        tenantId: data.tenantId,
        incidentId: data.incidentId,
        recommendationId: data.recommendationId,
        recommendationStepId: data.recommendationStepId,
        actionId: data.actionId,
        target: data.target,
        reason: data.reason,
        expectedResult: data.expectedResult,
        approvalStatus: data.approvalStatus,
        assignedRole: data.assignedRole,
        status: data.status,
      },
    });

    return ResponsePlanMapper.toDomain(raw);
  }

  async recordStepExecution(planId: string, tenantId: string, data: RecordStepExecutionData): Promise<void> {
    const plan = await this.prisma.responsePlan.findFirstOrThrow({ where: { id: planId, tenantId } });
    if (!plan.recommendationStepId) return;
    // One plan = one Action = one execution step (stepOrder 1); a retry after FAILED updates the same row.
    const finished = data.status !== "IN_PROGRESS";
    await this.prisma.stepExecution.upsert({
      where: { planId_stepOrder: { planId, stepOrder: 1 } },
      create: {
        planId,
        stepOrder: 1,
        recommendationStepId: plan.recommendationStepId,
        status: data.status,
        executedBy: data.executedBy,
        startedAt: data.at,
        completedAt: finished ? data.at : null,
        actualResult: data.actualResult ?? null,
        approvalStatus: plan.approvalStatus,
      },
      update: {
        status: data.status,
        executedBy: data.executedBy,
        ...(finished ? { completedAt: data.at, actualResult: data.actualResult ?? null } : { startedAt: data.at, completedAt: null, actualResult: null }),
        approvalStatus: plan.approvalStatus,
      },
    });
  }

  async updateStatus(
    id: string,
    tenantId: string,
    data: Partial<{
      approvalStatus: string;
      status: string;
      assignedTo: string | null;
      executionResult: Record<string, unknown> | null;
      executedAt: Date | null;
      completedAt: Date | null;
    }>
  ): Promise<ResponsePlan> {
    await this.prisma.responsePlan.findFirstOrThrow({
      where: {
        id,
        tenantId,
      },
    });

    const raw = await this.prisma.responsePlan.update({
      where: {
        id,
      },
      data: {
        ...data,
        executionResult:
          data.executionResult as Prisma.InputJsonValue | undefined,
      },
    });

    return ResponsePlanMapper.toDomain(raw);
  }
}