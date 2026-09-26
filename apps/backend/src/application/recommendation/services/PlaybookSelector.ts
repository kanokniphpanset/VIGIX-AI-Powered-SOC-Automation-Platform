import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";

export interface SelectedPlaybook {
  code: string;
  name: string;
  version: string;
  incidentType: string;
  allowedActions: string[];
  matchedTechniques: string[];
  strategy: { stepOrder: number; title: string; description: string | null }[];
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** T1110.001 also matches a playbook listing T1110 (sub-technique of a listed parent). */
function techniqueMatches(incidentTechnique: string, playbookTechnique: string): boolean {
  return incidentTechnique === playbookTechnique || incidentTechnique.startsWith(`${playbookTechnique}.`);
}

/**
 * PlaybookSelector — deterministic choice of the ONE incident-level playbook a
 * Recommendation must follow (Task 10.3). The backend picks it from the
 * incident's recorded MITRE techniques; the AI never chooses it, and
 * RecommendationValidator rejects a candidate that names any other playbook.
 *
 * Only ACTIVE playbooks with triggerConditions.scope === "INCIDENT" are
 * candidates — STC-001 (the generic Core Flow) never is. The playbook matching
 * the most distinct techniques wins; ties go to the most specific playbook
 * (fewest listed techniques), then to code order, so the result never depends
 * on row order. No match -> null (no incident-level playbook applies).
 */
export class PlaybookSelector {
  select(playbooks: Playbook[], techniqueIds: string[]): SelectedPlaybook | null {
    const ranked = playbooks
      .filter((p) => p.status === "ACTIVE" && p.code && p.triggerConditions.scope === "INCIDENT")
      .map((p) => {
        const listed = asStrings(p.triggerConditions.mitreTechniques);
        const matched = [...new Set(techniqueIds.filter((t) => listed.some((l) => techniqueMatches(t, l))))];
        return { p, listed, matched };
      })
      .filter((r) => r.matched.length > 0)
      .sort(
        (a, b) =>
          b.matched.length - a.matched.length ||
          a.listed.length - b.listed.length ||
          String(a.p.code).localeCompare(String(b.p.code))
      );

    const best = ranked[0];
    if (!best) return null;
    return {
      code: best.p.code as string,
      name: best.p.name,
      version: best.p.version ?? "1.0",
      incidentType: typeof best.p.triggerConditions.incidentType === "string" ? best.p.triggerConditions.incidentType : "UNKNOWN",
      allowedActions: asStrings(best.p.triggerConditions.allowedActions),
      matchedTechniques: best.matched.sort(),
      strategy: best.p.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })),
    };
  }
}
