import { IPolicyRepository } from "../../domain/policy/repositories/IPolicyRepository";
import { Policy } from "../../domain/policy/entities/Policy.entity";
import {
  PolicyEvaluationInput,
  PolicyResultFragment,
} from "../../domain/policy/entities/PolicyEvaluationTypes";
import { matchesCondition } from "./PolicyMatcher";
import { mergeResultFragments, orderedRoleUnion } from "./PolicyPrecedence";
import { SLAEvaluator } from "./SLAEvaluator";
import { AssignmentEvaluator } from "./AssignmentEvaluator";
import { ApprovalEvaluator } from "./ApprovalEvaluator";
import { PolicyEvaluationResultDto } from "../../application/policy/dto/PolicyEvaluationResultDto";

/**
 * PolicyEvaluator — the deterministic Policy rule engine, acting as the
 * ORCHESTRATOR over three focused evaluators:
 *
 *   AssignmentEvaluator — "who is responsible?" (type=ASSIGNMENT)
 *   ApprovalEvaluator    — "does this need review/approval, by whom?" (type=APPROVAL)
 *   SLAEvaluator         — baseline SLA lookup by final resolved Priority
 *
 * PRIORITY/VERIFICATION/ESCALATION-type policies are evaluated inline here
 * using the same matchesCondition function.
 *
 * It is a RULE ENGINE, not AI.
 *
 * Nothing here calls an LLM, nothing here is probabilistic, and nothing
 * outside this engine is allowed to authorize, approve, bypass, or change
 * a policy result.
 *
 * Every enabled policy's every enabled rule is evaluated against the given
 * context. There is no findFirst / stop-at-first-match behavior.
 *
 * All matching rule fragments are combined via PolicyPrecedence.ts, which
 * is the single source of truth for conflict resolution.
 */
export class PolicyEvaluator {
  private readonly assignmentEvaluator = new AssignmentEvaluator();
  private readonly approvalEvaluator = new ApprovalEvaluator();

  constructor(
    private readonly policyRepository: IPolicyRepository,
    private readonly slaEvaluator: SLAEvaluator = new SLAEvaluator()
  ) {}

  /**
   * Alert Inbox triage SLA targets per alert severity, from the enabled TRIAGE_SLA policies (result.triageSlaMinutes).
   * The strictest (smallest) target wins when several rules match a severity. A severity with no rule has no SLA —
   * nothing is invented. Kept apart from evaluate(): triage SLA never changes a response / approval decision.
   */
  async triageSlaMinutes(tenantId: string): Promise<Partial<Record<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL", number>>> {
    const policies = (await this.policyRepository.findAllEnabled(tenantId)).filter((p: Policy) => p.type === "TRIAGE_SLA");
    const out: Partial<Record<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL", number>> = {};
    for (const severity of ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const) {
      for (const policy of policies) {
        for (const rule of policy.activeRules()) {
          const minutes = rule.result.triageSlaMinutes;
          if (typeof minutes === "number" && minutes > 0 && matchesCondition(rule.condition, { severity })) {
            out[severity] = Math.min(out[severity] ?? Infinity, minutes);
          }
        }
      }
    }
    return out;
  }

  /**
   * Response guidance for an incident group (incidentType + severity), from the enabled RESPONSE_GUIDANCE policies.
   * allowedActions: intersection across matching rules that set it (the stricter list wins), null when none sets it;
   * notes: every matching guidanceNote. Kept apart from evaluate(): it never changes an approval / assignment result.
   */
  async responseGuidance(tenantId: string, group: { incidentType: string; severity: PolicyEvaluationInput["severity"] }): Promise<{ allowedActions: string[] | null; notes: string[]; policies: string[] }> {
    const policies = (await this.policyRepository.findAllEnabled(tenantId)).filter((p: Policy) => p.type === "RESPONSE_GUIDANCE");
    let allowed: string[] | null = null;
    const notes: string[] = [];
    const matched: string[] = [];
    for (const policy of policies) {
      for (const rule of policy.activeRules()) {
        if (!matchesCondition(rule.condition, group)) continue;
        if (!matched.includes(policy.code)) matched.push(policy.code);
        const list = rule.result.allowedActions;
        if (Array.isArray(list)) allowed = allowed === null ? [...list] : allowed.filter((a) => list.includes(a));
        if (rule.result.guidanceNote?.trim()) notes.push(rule.result.guidanceNote.trim());
      }
    }
    return { allowedActions: allowed, notes, policies: matched };
  }

  async evaluate(
    tenantId: string,
    input: PolicyEvaluationInput
  ): Promise<PolicyEvaluationResultDto> {
    const policies =
      await this.policyRepository.findAllEnabled(tenantId);

    const matchedCodes: string[] = [];
    const fragments: PolicyResultFragment[] = [];

    // ------------------------------------------------------------
    // 1. Assignment
    // ------------------------------------------------------------
    const assignmentOutcome =
      this.assignmentEvaluator.evaluate(
        policies,
        input
      );

    // ------------------------------------------------------------
    // 2. Approval
    // ------------------------------------------------------------
    const approvalOutcome =
      this.approvalEvaluator.evaluate(
        policies,
        input
      );

    fragments.push(
      ...assignmentOutcome.fragments,
      ...approvalOutcome.fragments
    );

    matchedCodes.push(
      ...assignmentOutcome.matchedCodes,
      ...approvalOutcome.matchedCodes
    );

    // ------------------------------------------------------------
    // 3. Evaluate remaining policy types
    // ------------------------------------------------------------
    const remainingPolicies = policies.filter(
      (p: Policy) =>
        p.type !== "ASSIGNMENT" &&
        p.type !== "APPROVAL" &&
        // Triage SLA targets are read separately (Alert Inbox); they never take part in this evaluation.
        p.type !== "TRIAGE_SLA"
    );

    for (const policy of remainingPolicies) {
      for (const rule of policy.activeRules()) {
        if (matchesCondition(rule.condition, input)) {
          matchedCodes.push(policy.code);
          fragments.push(rule.result);
        }
      }
    }

    // ------------------------------------------------------------
    // 4. Merge all matching policy fragments
    // ------------------------------------------------------------
    const merged = mergeResultFragments(fragments);

    // ------------------------------------------------------------
    // 6. Resolve SLA
    //
    // Priority:
    //   1. Policy-specific SLA override
    //   2. Baseline SLA for resolved priority
    // ------------------------------------------------------------
    const sla = merged.priority
      ? {
          firstResponseMinutes:
            merged.firstResponseSlaMinutes ??
            this.slaEvaluator.getBaseline(
              merged.priority
            ).firstResponseMinutes,

          resolutionMinutes:
            merged.resolutionSlaMinutes ??
            this.slaEvaluator.getBaseline(
              merged.priority
            ).resolutionMinutes,
        }
      : undefined;

    // ------------------------------------------------------------
    // 7. Approval chain: every approver the matched rules name
    // (approvalChain + approvalRole), in approval order. Empty when
    // no approval is required.
    // ------------------------------------------------------------
    const approvalRequired = merged.approvalRequired ?? false;
    const approvalChain = approvalRequired
      ? orderedRoleUnion(merged.approvalChain ?? [], merged.approvalRole ? [merged.approvalRole] : [])
      : [];

    // ------------------------------------------------------------
    // 8. Return final deterministic policy result
    // ------------------------------------------------------------
    return {
      matchedPolicies: matchedCodes,
      matchedRules: matchedCodes,

      priority: merged.priority ?? null,

      severity:
        input.severity ?? null,

      responsibleRole:
        merged.responsibleRole ?? null,

      reviewRequired:
        merged.reviewRequired ?? false,

      reviewRole:
        merged.reviewRole ?? null,

      approvalRequired:
        merged.approvalRequired ?? false,

      approvalRole:
        merged.approvalRole ?? approvalChain[approvalChain.length - 1] ?? null,

      approvalChain,

      executorRole:
        merged.executorRole ?? "IR_TEAM",

      // Every alert waits for SOC triage in the Alert Inbox; ingestion never auto-opens an incident.
      autoCreateIncident:
        merged.autoCreateIncident ?? false,

      approvalReason:
        merged.approvalReason ?? [],

      highRiskReview:
        merged.highRiskReview ?? false,

      responseRequired:
        merged.responseRequired ?? false,

      investigationRequired:
        merged.investigationRequired ?? false,

      additionalInvestigation:
        merged.additionalInvestigation ?? false,

      standardInvestigation:
        merged.standardInvestigation ?? false,

      incidentStatus:
        merged.incidentStatus ?? null,

      requireNewInvestigation:
        merged.requireNewInvestigation ?? false,

      requireNewRecommendation:
        merged.requireNewRecommendation ?? false,

      requireEscalation:
        merged.requireEscalation ?? false,

      requireAdditionalEvidence:
        merged.requireAdditionalEvidence ?? false,

      sla:
        sla ?? null,

      verificationOverrides: {
        incidentStatus:
          merged.incidentStatus ?? null,

        requireNewInvestigation:
          merged.requireNewInvestigation ?? false,

        requireNewRecommendation:
          merged.requireNewRecommendation ?? false,

        requireEscalation:
          merged.requireEscalation ?? false,

        requireAdditionalEvidence:
          merged.requireAdditionalEvidence ?? false,
      },
    };
  }
}
