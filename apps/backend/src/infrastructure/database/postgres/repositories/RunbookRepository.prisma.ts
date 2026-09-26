import { PrismaClient, Prisma } from "@prisma/client";
import { IRunbookRepository, NewRunbookInput, UpdateRunbookInput } from "../../../../domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../../../domain/runbook/entities/Runbook.entity";
import { RunbookMapper } from "../mappers/Runbook.mapper";

export class PrismaRunbookRepository implements IRunbookRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Runbook | null> {
    const raw = await this.prisma.runbook.findFirst({ where: { id, tenantId } });
    return raw ? RunbookMapper.toDomain(raw) : null;
  }

  async findByCode(code: string, tenantId: string): Promise<Runbook | null> {
    const raw = await this.prisma.runbook.findFirst({ where: { code, tenantId } });
    return raw ? RunbookMapper.toDomain(raw) : null;
  }

  async findByCodes(codes: string[], tenantId: string): Promise<Runbook[]> {
    if (codes.length === 0) return [];
    const rows = await this.prisma.runbook.findMany({ where: { code: { in: codes }, tenantId } });
    return rows.map(RunbookMapper.toDomain);
  }

  async findAll(tenantId: string): Promise<Runbook[]> {
    const rows = await this.prisma.runbook.findMany({ where: { tenantId }, orderBy: { code: "asc" } });
    return rows.map(RunbookMapper.toDomain);
  }

  async create(input: NewRunbookInput): Promise<Runbook> {
    const raw = await this.prisma.runbook.create({
      data: {
        tenantId: input.tenantId,
        code: input.code,
        name: input.name,
        version: input.version,
        description: input.description,
        trigger: input.trigger,
        preconditions: input.preconditions as Prisma.InputJsonValue,
        objective: input.objective,
        procedure: input.procedure as Prisma.InputJsonValue,
        decisionPoints: input.decisionPoints as Prisma.InputJsonValue,
        expectedResult: input.expectedResult,
        escalation: input.escalation,
        verificationCriteria: input.verificationCriteria as Prisma.InputJsonValue,
      },
    });
    return RunbookMapper.toDomain(raw);
  }

  async update(id: string, _tenantId: string, input: UpdateRunbookInput): Promise<Runbook> {
    const raw = await this.prisma.runbook.update({
      where: { id },
      data: {
        name: input.name,
        version: input.version,
        status: input.status,
        description: input.description,
        trigger: input.trigger,
        preconditions: input.preconditions as Prisma.InputJsonValue | undefined,
        objective: input.objective,
        procedure: input.procedure as Prisma.InputJsonValue | undefined,
        decisionPoints: input.decisionPoints as Prisma.InputJsonValue | undefined,
        expectedResult: input.expectedResult,
        escalation: input.escalation,
        verificationCriteria: input.verificationCriteria as Prisma.InputJsonValue | undefined,
      },
    });
    return RunbookMapper.toDomain(raw);
  }
}
