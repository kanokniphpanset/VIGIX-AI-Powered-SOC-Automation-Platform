import { Action, ActionImpactLevel } from "../../../domain/action/entities/Action.entity";

/**
 * Field-level governance of the Action Catalog. `impactLevel` feeds the approval policy (ApprovalService) and
 * `defaultApprovalRequired` is the approval baseline, so only admin sets them freely. SOC / IR_TEAM may create an
 * Action only at the strictest level (HIGH + approval required) and may not change either field afterwards; a request
 * asking for anything else is rejected, never silently rewritten.
 */
export type ActionGovernanceErrorCode = "ACTION_GOVERNANCE_FIELD_FORBIDDEN";

const GOVERNANCE_ROLE = "admin";

export function canCreateWithGovernance(actorRole: string, input: { impactLevel: ActionImpactLevel; defaultApprovalRequired: boolean }): boolean {
  return actorRole === GOVERNANCE_ROLE || (input.impactLevel === "HIGH" && input.defaultApprovalRequired === true);
}

/** A field that is sent with its current value is not a change. */
export function canUpdateGovernance(actorRole: string, existing: Action, input: { impactLevel?: ActionImpactLevel; defaultApprovalRequired?: boolean }): boolean {
  if (actorRole === GOVERNANCE_ROLE) return true;
  const changesImpact = input.impactLevel !== undefined && input.impactLevel !== existing.impactLevel;
  const changesApproval = input.defaultApprovalRequired !== undefined && input.defaultApprovalRequired !== existing.defaultApprovalRequired;
  return !changesImpact && !changesApproval;
}
