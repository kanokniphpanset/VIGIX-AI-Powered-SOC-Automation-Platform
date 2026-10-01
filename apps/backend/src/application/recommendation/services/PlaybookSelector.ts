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
 *
 * `primaryTechniqueIds` are the techniques the SIEM itself asserted in the alert(s). When two playbooks match the
 * same NUMBER of techniques, the one matching more SIEM-asserted techniques wins BEFORE the specificity / code-order
 * tie-breaks: a technique the AI analysis inferred on top of the SIEM's own must not be able to flip the playbook by
 * alphabetical accident (found in the Real-Wazuh evaluation: Wazuh T1048 + AI-inferred T1071.001 tied PB-DATA-EXFIL
 * with PB-C2 and code order picked PB-C2). Scores that differ are unaffected.
 */
export class PlaybookSelector {
  select(playbooks: Playbook[], techniqueIds: string[], primaryTechniqueIds: string[] = []): SelectedPlaybook | null {
    const ranked = playbooks
      .filter((p) => p.status === "ACTIVE" && p.code && p.triggerConditions.scope === "INCIDENT")
      .map((p) => {
        const listed = asStrings(p.triggerConditions.mitreTechniques);
        const matched = [...new Set(techniqueIds.filter((t) => listed.some((l) => techniqueMatches(t, l))))];
        const primaryMatched = new Set(primaryTechniqueIds.filter((t) => listed.some((l) => techniqueMatches(t, l)))).size;
        return { p, listed, matched, primaryMatched };
      })
      .filter((r) => r.matched.length > 0)
      .sort(
        (a, b) =>
          b.matched.length - a.matched.length ||
          b.primaryMatched - a.primaryMatched ||
          a.listed.length - b.listed.length ||
          String(a.p.code).localeCompare(String(b.p.code))
      );

    const best = ranked[0];
    if (!best) return null;
    return this.toSelected(best.p, best.matched.sort());
  }

  /** The incident-level playbooks a SOC analyst can choose a type from (ACTIVE, scope INCIDENT, with a type). */
  incidentPlaybooks(playbooks: Playbook[]): Playbook[] {
    return playbooks
      .filter((p) => p.status === "ACTIVE" && p.code && p.triggerConditions.scope === "INCIDENT" && typeof p.triggerConditions.incidentType === "string")
      .sort((a, b) => String(a.code).localeCompare(String(b.code)));
  }

  /**
   * The playbook for an incident type the SOC confirmed (instead of the MITRE match). Techniques already recorded
   * that the playbook lists are kept as matchedTechniques. Unknown / inactive type -> null.
   */
  selectByType(playbooks: Playbook[], incidentType: string, techniqueIds: string[] = []): SelectedPlaybook | null {
    const p = this.incidentPlaybooks(playbooks).find((x) => x.triggerConditions.incidentType === incidentType);
    if (!p) return null;
    const listed = asStrings(p.triggerConditions.mitreTechniques);
    return this.toSelected(p, [...new Set(techniqueIds.filter((t) => listed.some((l) => techniqueMatches(t, l))))].sort());
  }

  private toSelected(p: Playbook, matchedTechniques: string[]): SelectedPlaybook {
    return {
      code: p.code as string,
      name: p.name,
      version: p.version ?? "1.0",
      incidentType: typeof p.triggerConditions.incidentType === "string" ? p.triggerConditions.incidentType : "UNKNOWN",
      allowedActions: asStrings(p.triggerConditions.allowedActions),
      matchedTechniques,
      strategy: p.steps.map((s) => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })),
    };
  }
}
