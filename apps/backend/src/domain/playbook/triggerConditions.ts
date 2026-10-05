/**
 * Playbook selector keys, as the seeded incident-level playbooks store them:
 * triggerConditions = { scope: "INCIDENT", incidentType, mitreTechniques[], allowedActions[] }.
 * PlaybookSelector only picks ACTIVE playbooks with scope "INCIDENT" whose mitreTechniques match the incident, so a
 * playbook created or edited in Knowledge must be able to set the same keys.
 */
export interface TriggerConditionsPatch {
  /** undefined = keep; null / "" = remove. */
  incidentType?: string | null;
  /** undefined = keep; [] = remove. */
  mitreTechniques?: string[];
  /** Action codes (e.g. ACT-BLOCK-SOURCE-IP). undefined = keep; [] = remove. */
  allowedActions?: string[];
}

/** Applies a patch on top of the stored triggerConditions; keys the patch does not name are kept as they are. */
export function mergeTriggerConditions(current: unknown, patch: TriggerConditionsPatch): Record<string, unknown> {
  const next: Record<string, unknown> =
    current && typeof current === "object" && !Array.isArray(current) ? { ...(current as Record<string, unknown>) } : {};
  if (patch.incidentType !== undefined) {
    if (patch.incidentType) next.incidentType = patch.incidentType;
    else delete next.incidentType;
  }
  for (const key of ["mitreTechniques", "allowedActions"] as const) {
    const list = patch[key];
    if (list === undefined) continue;
    if (list.length) next[key] = [...new Set(list)];
    else delete next[key];
  }
  // A playbook that lists techniques or actions is an incident-level playbook (the selector requires the scope).
  if ((next.mitreTechniques || next.allowedActions) && next.scope === undefined) next.scope = "INCIDENT";
  return next;
}
