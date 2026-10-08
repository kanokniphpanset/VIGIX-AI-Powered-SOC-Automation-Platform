import { Action, ActionCategory, ActionImpactLevel } from "../entities/Action.entity";

export type ActionRunbookErrorCode = "RUNBOOK_NOT_FOUND" | "ACTION_RUNBOOK_TENANT_MISMATCH";

/** Relationship validation failure, independent of the persistence provider. */
export class ActionRunbookRelationshipError extends Error {
  constructor(readonly code: ActionRunbookErrorCode) {
    super(code);
    this.name = "ActionRunbookRelationshipError";
  }
}

export interface NewActionInput {
  tenantId: string;
  code: string;
  name: string;
  description: string | null;
  category: ActionCategory;
  impactLevel: ActionImpactLevel;
  defaultApprovalRequired: boolean;
  runbookId: string | null;
}

export interface UpdateActionInput {
  name?: string;
  description?: string | null;
  impactLevel?: ActionImpactLevel;
  defaultApprovalRequired?: boolean;
  runbookId?: string | null;
}

export interface IActionRepository {
  findById(id: string, tenantId: string): Promise<Action | null>;
  findByCode(code: string, tenantId: string): Promise<Action | null>;
  /** Bulk lookup by code — used by RecommendationValidator to check every
   * AI-referenced actionId in one query rather than N. */
  findByCodes(codes: string[], tenantId: string): Promise<Action[]>;
  findAll(tenantId: string): Promise<Action[]>;
  create(input: NewActionInput): Promise<Action>;
  update(id: string, tenantId: string, input: UpdateActionInput): Promise<Action>;
  setEnabled(id: string, tenantId: string, enabled: boolean): Promise<Action>;
}
