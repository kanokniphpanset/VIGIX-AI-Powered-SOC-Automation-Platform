import { PrismaClient } from "@prisma/client";
import { IActionRepository, NewActionInput, UpdateActionInput, ActionRunbookRelationshipError } from "../../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../../domain/action/entities/Action.entity";
import { ActionMapper } from "../mappers/Action.mapper";

export class PrismaActionRepository implements IActionRepository {
  constructor(private readonly prisma: PrismaClient) {}

  private async validateRunbookOwnership(runbookId: string | null | undefined, tenantId: string): Promise<void> {
    if (runbookId === null || runbookId === undefined) return;
    const runbook = await this.prisma.runbook.findUnique({ where: { id: runbookId }, select: { tenantId: true } });
    if (!runbook) throw new ActionRunbookRelationshipError("RUNBOOK_NOT_FOUND");
    if (runbook.tenantId !== tenantId) throw new ActionRunbookRelationshipError("ACTION_RUNBOOK_TENANT_MISMATCH");
  }

  async findById(id: string, tenantId: string): Promise<Action | null> {
    const raw = await this.prisma.action.findFirst({ where: { id, tenantId } });
    return raw ? ActionMapper.toDomain(raw) : null;
  }

  async findByCode(code: string, tenantId: string): Promise<Action | null> {
    const raw = await this.prisma.action.findFirst({ where: { code, tenantId } });
    return raw ? ActionMapper.toDomain(raw) : null;
  }

  async findByCodes(codes: string[], tenantId: string): Promise<Action[]> {
    if (codes.length === 0) return [];
    const rows = await this.prisma.action.findMany({ where: { code: { in: codes }, tenantId } });
    return rows.map(ActionMapper.toDomain);
  }

  async findAll(tenantId: string): Promise<Action[]> {
    const rows = await this.prisma.action.findMany({ where: { tenantId }, orderBy: { code: "asc" } });
    return rows.map(ActionMapper.toDomain);
  }

  async create(input: NewActionInput): Promise<Action> {
    await this.validateRunbookOwnership(input.runbookId, input.tenantId);
    const raw = await this.prisma.action.create({
      data: {
        tenantId: input.tenantId,
        code: input.code,
        name: input.name,
        description: input.description,
        category: input.category,
        impactLevel: input.impactLevel,
        defaultApprovalRequired: input.defaultApprovalRequired,
        runbookId: input.runbookId,
      },
    });
    return ActionMapper.toDomain(raw);
  }

  async update(id: string, tenantId: string, input: UpdateActionInput): Promise<Action> {
    await this.validateRunbookOwnership(input.runbookId, tenantId);
    const raw = await this.prisma.action.update({
      where: { id, tenantId },
      data: {
        name: input.name,
        description: input.description,
        impactLevel: input.impactLevel,
        defaultApprovalRequired: input.defaultApprovalRequired,
        runbookId: input.runbookId,
      },
    });
    return ActionMapper.toDomain(raw);
  }

  async setEnabled(id: string, tenantId: string, enabled: boolean): Promise<Action> {
    const raw = await this.prisma.action.update({ where: { id, tenantId }, data: { enabled } });
    return ActionMapper.toDomain(raw);
  }
}
