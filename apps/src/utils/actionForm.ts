// Action form governance (Knowledge → Actions). Pure; runs under `node --test`. Mirrors the backend rule
// (ActionGovernance): impactLevel feeds the approval policy, so only admin sets impactLevel / defaultApprovalRequired.
// SOC / IR_TEAM create Actions at the strictest level (HIGH + approval required) and never change either field; the
// backend rejects anything else with ACTION_GOVERNANCE_FIELD_FORBIDDEN, never rewriting it silently.

export type ActionImpactLevel = 'LOW' | 'MEDIUM' | 'HIGH'
export interface ActionGovernanceFields { impactLevel: string; defaultApprovalRequired: boolean }

/** Only admin may choose the impact level and the approval requirement. */
export const canSetActionGovernance = (role: string | null) => role === 'admin'

/** The values the form starts with: SOC / IR_TEAM creating get the only values they may send. */
export function initialActionGovernance(role: string | null, creating: boolean, stored: Record<string, unknown> = {}): ActionGovernanceFields {
  if (creating && !canSetActionGovernance(role)) return { impactLevel: 'HIGH', defaultApprovalRequired: true }
  return { impactLevel: String(stored.impactLevel ?? 'LOW'), defaultApprovalRequired: stored.defaultApprovalRequired === true }
}

/**
 * The governance part of the request body. Admin sends what the form holds; SOC / IR_TEAM send HIGH + true explicitly
 * when creating (never left to the backend default) and nothing when editing, so the current values stay unchanged.
 */
export function actionGovernanceBody(role: string | null, creating: boolean, form: ActionGovernanceFields): Partial<ActionGovernanceFields> {
  if (canSetActionGovernance(role)) return { impactLevel: form.impactLevel, defaultApprovalRequired: form.defaultApprovalRequired }
  return creating ? { impactLevel: 'HIGH', defaultApprovalRequired: true } : {}
}
