import { PrismaClient, Prisma } from "@prisma/client";
import {
  IVerificationRepository,
  CreateVerificationData,
} from "../../../../domain/verification/repositories/IVerificationRepository";
import { Verification } from "../../../../domain/verification/entities/Verification.entity";
import { VerificationMapper } from "../mappers/Verification.mapper";

export class PrismaVerificationRepository implements IVerificationRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Verification | null> {
    const raw = await this.prisma.verification.findFirst({ where: { id, tenantId } });
    return raw ? VerificationMapper.toDomain(raw) : null;
  }

  async findAllByIncident(incidentId: string, tenantId: string): Promise<Verification[]> {
    const rows = await this.prisma.verification.findMany({ where: { incidentId, tenantId }, orderBy: { verifiedAt: "asc" } });
    return rows.map(VerificationMapper.toDomain);
  }

  async findAll(tenantId: string, limit = 100, offset = 0): Promise<Verification[]> {
    const rows = await this.prisma.verification.findMany({
      where: { tenantId },
      orderBy: { verifiedAt: "desc" },
      take: limit,
      skip: offset,
    });
    return rows.map(VerificationMapper.toDomain);
  }

  async create(data: CreateVerificationData): Promise<Verification> {
    const raw = await this.prisma.verification.create({
      data: {
        tenantId: data.tenantId,
        incidentId: data.incidentId,
        responseId: data.responseId,
        wazuhIndex: data.wazuhIndex,
        query: data.query,
        timeRangeStart: data.timeRangeStart,
        timeRangeEnd: data.timeRangeEnd,
        matchingEvents: data.matchingEvents,
        affectedHosts: data.affectedHosts as Prisma.InputJsonValue,
        iocRecurrence: data.iocRecurrence,
        spreadDetected: data.spreadDetected,
        threatContained: data.threatContained,
        beforeState: data.beforeState as Prisma.InputJsonValue | undefined,
        afterState: data.afterState as Prisma.InputJsonValue | undefined,
        result: data.result,
        notes: data.notes,
        verifiedBy: data.verifiedBy,
      },
    });
    return VerificationMapper.toDomain(raw);
  }
}
