import {
  PolicyPriority,
  PolicyResultFragment,
  ResponsibleRole,
} from "../../domain/policy/entities/PolicyEvaluationTypes";

/**
 * PolicyPrecedence — deterministic conflict resolution for combining every
 * matched PolicyRule's result fragment into one final answer.
 *
 * The Policy Engine evaluates ALL enabled rules that match the given
 * context (never findFirst/stop-at-first-match — see PolicyEvaluator.ts),
 * so a single evaluation routinely produces several PolicyResultFragments
 * that must be merged without letting a less urgent rule quietly relax a
 * more urgent one.
 *
 * Merge rules:
 *
 * 1. priority — MOST URGENT wins. P0 > P1 > P2 > P3.
 *
 * 2. responsibleRole / reviewRole / approvalRole — MOST RESTRICTIVE
 *    responsibility wins:
 *    SOC < IR_TEAM.
 *
 * 3. Boolean flags are merged using logical OR.
 *
 * 4. firstResponseSlaMinutes — MINIMUM wins.
 *
 * 5. resolutionSlaMinutes — MINIMUM wins.
 *
 * 6. incidentStatus — last matched value wins.
 *
 * 7. approvalReason — deduplicated union.
 *
 * Severity itself is never touched by this merge.
 * Severity is an input, not an output that PolicyPrecedence can change.
 */

export const PRIORITY_RANK: Record<PolicyPriority, number> = {
  P0: 0,
  P1: 1,
  P2: 2,
  P3: 3,
};

export const ROLE_RANK: Record<ResponsibleRole, number> = {
  SOC: 0,
  IR_TEAM: 1,
};

const BOOLEAN_FIELDS: (keyof PolicyResultFragment)[] = [
  "reviewRequired",
  "approvalRequired",
  "highRiskReview",
  "responseRequired",
  "investigationRequired",
  "additionalInvestigation",
  "standardInvestigation",
  "requireNewInvestigation",
  "requireNewRecommendation",
  "requireEscalation",
  "requireAdditionalEvidence",
];

const ROLE_FIELDS: (keyof PolicyResultFragment)[] = [
  "responsibleRole",
  "reviewRole",
  "approvalRole",
  "executorRole",
];

function mostUrgentPriority(
  a: PolicyPriority,
  b: PolicyPriority
): PolicyPriority {
  return PRIORITY_RANK[a] <= PRIORITY_RANK[b] ? a : b;
}

function mostRestrictiveRole(
  a: ResponsibleRole,
  b: ResponsibleRole
): ResponsibleRole {
  return ROLE_RANK[a] >= ROLE_RANK[b] ? a : b;
}

/**
 * Merges every matched rule's result fragment into one final result.
 *
 * PolicyEvaluator.ts is responsible for turning this merged
 * PolicyResultFragment into the full PolicyEvaluationResultDto by adding:
 * - severity
 * - matchedPolicies
 * - matchedRules
 * - SLA
 */
/** Deduped union of roles, ordered SOC, IR_TEAM: the approval order. */
export function orderedRoleUnion(a: ResponsibleRole[], b: ResponsibleRole[]): ResponsibleRole[] {
  return [...new Set([...a, ...b])].sort((x, y) => ROLE_RANK[x] - ROLE_RANK[y]);
}

export function mergeResultFragments(
  fragments: PolicyResultFragment[]
): PolicyResultFragment {
  const merged: PolicyResultFragment = {};

  for (const fragment of fragments) {
    /**
     * 1. Priority
     *
     * The most urgent priority wins.
     */
    if (fragment.priority) {
      merged.priority = merged.priority
        ? mostUrgentPriority(merged.priority, fragment.priority)
        : fragment.priority;
    }

    /**
     * 2. Roles
     *
     * The most restrictive role wins independently for each role field.
     */
    for (const field of ROLE_FIELDS) {
      const value = fragment[field] as ResponsibleRole | undefined;

      if (!value) continue;

      const existing = merged[field] as ResponsibleRole | undefined;

      (merged[field] as ResponsibleRole) = existing
        ? mostRestrictiveRole(existing, value)
        : value;
    }

    /**
     * 3. Boolean flags
     *
     * Once any matched rule requires a flag, the merged result keeps it true.
     */
    for (const field of BOOLEAN_FIELDS) {
      if (fragment[field] === true) {
        (merged[field] as boolean) = true;
      }
    }

    /**
     * 4. Incident status
     */
    if (fragment.approvalChain?.length) {
      merged.approvalChain = orderedRoleUnion(merged.approvalChain ?? [], fragment.approvalChain);
    }

    if (fragment.autoCreateIncident !== undefined) {
      merged.autoCreateIncident = merged.autoCreateIncident === false ? false : fragment.autoCreateIncident;
    }

    if (fragment.incidentStatus) {
      merged.incidentStatus = fragment.incidentStatus;
    }

    /**
     * 5. First-response SLA
     *
     * Minimum wins because a shorter deadline is more restrictive.
     */
    if (fragment.firstResponseSlaMinutes !== undefined) {
      merged.firstResponseSlaMinutes =
        merged.firstResponseSlaMinutes !== undefined
          ? Math.min(
              merged.firstResponseSlaMinutes,
              fragment.firstResponseSlaMinutes
            )
          : fragment.firstResponseSlaMinutes;
    }

    /**
     * 6. Resolution SLA
     *
     * Minimum wins for the same reason as first-response SLA.
     */
    if (fragment.resolutionSlaMinutes !== undefined) {
      merged.resolutionSlaMinutes =
        merged.resolutionSlaMinutes !== undefined
          ? Math.min(
              merged.resolutionSlaMinutes,
              fragment.resolutionSlaMinutes
            )
          : fragment.resolutionSlaMinutes;
    }

    /**
     * 7. Approval reasons
     *
     * Merge all reasons while removing duplicates.
     */
    if (fragment.approvalReason?.length) {
      const existing = merged.approvalReason ?? [];

      merged.approvalReason = [
        ...new Set([
          ...existing,
          ...fragment.approvalReason,
        ]),
      ];
    }
  }

  return merged;
}