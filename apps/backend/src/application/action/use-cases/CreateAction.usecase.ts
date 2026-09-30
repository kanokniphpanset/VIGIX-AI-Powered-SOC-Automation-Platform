import { IActionRepository } from "../../../domain/action/repositories/IActionRepository";
import { Action } from "../../../domain/action/entities/Action.entity";
import { Result } from "../../../shared/result/Result";
import { CreateActionDto } from "../dto/ActionDto";

export interface CreateActionInput extends CreateActionDto {
  tenantId: string;
  /** The signed-in user (JWT); recorded on the CREATE_ACTION audit entry. */
  actor?: string;
}

/** Audit of catalog changes made from Knowledge (implemented by the existing AuditLogger / audit_logs). */
export interface IActionAuditRecorder {
  record(input: { tenantId: string; actor: string; action: "CREATE_ACTION"; entity: "Action"; entityId: string; metadata?: Record<string, unknown> }): Promise<void>;
}

export class CreateActionUseCase {
  constructor(
    private readonly actionRepository: IActionRepository,
    private readonly audit?: IActionAuditRecorder
  ) {}

  async execute(input: CreateActionInput): Promise<Result<Action, "DUPLICATE_CODE">> {
    const existing = await this.actionRepository.findByCode(input.code, input.tenantId);
    if (existing) return Result.fail("DUPLICATE_CODE");

    const action = await this.actionRepository.create({
      tenantId: input.tenantId,
      code: input.code,
      name: input.name,
      description: input.description ?? null,
      category: input.category,
      impactLevel: input.impactLevel,
      defaultApprovalRequired: input.defaultApprovalRequired,
      runbookId: input.runbookId ?? null,
    });
    await this.audit?.record({
      tenantId: input.tenantId,
      actor: input.actor ?? "system",
      action: "CREATE_ACTION",
      entity: "Action",
      entityId: action.id,
      metadata: { code: input.code, name: input.name, category: input.category, impactLevel: input.impactLevel, defaultApprovalRequired: input.defaultApprovalRequired },
    });
    return Result.ok(action);
  }
}
