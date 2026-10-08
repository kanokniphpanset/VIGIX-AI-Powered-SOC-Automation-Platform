import { PrismaClient, Prisma } from "@prisma/client";
import { SPREAD_RESPONSES, spreadPolicyCode } from "../../src/domain/knowledge/spreadResponse";

/**
 * policy.seed.ts — Policy Engine baseline rules (VIGIX Policy Engine audit
 * revision). Idempotent: every policy is upserted by its unique `code`,
 * and each run replaces that policy's rule set wholesale (delete-then-
 * recreate under the policy's id).
 *
 * REVISION NOTE: this replaces the original POL-001..017 set. Rule codes
 * below (RULE-A/R/P/V-xx) are the ones a UI/audit trail should reference —
 * see RETIRED_CODES for exactly which old codes this removes and why.
 *
 * TWO ROLES ONLY (2026-09-26): SOC investigates every incident and sends the
 * recommendation to IR; IR_TEAM decides (APPROVE / REJECT) and executes every
 * Response Ticket. There is no Manager role, approval step or queue. The
 * APPROVAL rules below only explain WHY a ticket is sensitive (reason tags
 * shown to IR); every ticket needs the IR decision regardless.
 *
 * SLA is deliberately NOT set as a per-rule result field — see
 * SLAEvaluator.ts. SLA comes from the FINAL resolved priority's baseline.
 */

export type SeedRule = { condition: Prisma.InputJsonValue; result: Prisma.InputJsonValue };

export interface SeedPolicy {
  code: string;
  name: string;
  description: string;
  type: "PRIORITY" | "ASSIGNMENT" | "APPROVAL" | "VERIFICATION" | "ESCALATION" | "INTAKE" | "TRIAGE_SLA" | "ACTION_COMPLIANCE" | "RESPONSE_GUIDANCE";
  precedence: number;
  rules: SeedRule[];
}

/**
 * Codes from the previous revision that this seed retires outright — kept
 * as an explicit list (not inferred) so re-seeding actively deletes the
 * orphaned rows rather than leaving them enabled and silently still firing.
 * POL-001/003/005/007 are NOT retired — they stay as the severity-based
 * Priority fallback (see PRIORITY group below); POL-002/004/006/008 are
 * retired in favor of the equivalent, correctly-named RULE-R01..R04.
 */
export const RETIRED_CODES = [
  "POL-002",
  "POL-004",
  "POL-006",
  "POL-008",
  "POL-009",
  "POL-010",
  "POL-011",
  "POL-012",
  "POL-013",
  "POL-014",
  "POL-015",
  "POL-016",
  "POL-017",
];

/**
 * Risk-score rules retired when VIGIX moved to Severity as the primary classification (2026-09-25):
 *   RULE-R01..R04 (priority / owner by risk band), RULE-P08 (IR approval at risk 50-74),
 *   RULE-P10 (IR approval at risk >= 75).
 * Unlike RETIRED_CODES they are NOT deleted: the rows stay for history/audit (matchedPolicies of past decisions
 * reference them) but are set enabled=false on every seed. The engine additionally never matches a riskScore
 * condition (PolicyMatcher RETIRED_CONDITION_FIELDS), so even a re-enabled row cannot make risk a decision input.
 */
export const RISK_SCORE_RETIRED_CODES = ["RULE-R01", "RULE-R02", "RULE-R03", "RULE-R04", "RULE-P08", "RULE-P10"];

/**
 * Retired by the two-role workflow (2026-09-26), disabled on every seed and never deleted (history):
 *   RULE-P01 ("no approval for low impact") contradicts the IR decision every Response Ticket now needs;
 *   RULE-P11 / RULE-P12 were the "IR before Manager" duplicates of RULE-P04 / RULE-P05.
 */
export const TWO_ROLE_RETIRED_CODES = ["RULE-P01", "RULE-P11", "RULE-P12"];

/** Actions covered by POL-A02 (network blocking) and POL-A03 (endpoint containment). */
export const NETWORK_BLOCK_ACTIONS = ["ACT-BLOCK-SOURCE-IP", "ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-RATE-LIMIT-SOURCE", "ACT-BLOCK-SENDER"];
export const ENDPOINT_CONTAINMENT_ACTIONS = ["ACT-ISOLATE-ENDPOINT", "ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE"];

export const POLICIES: SeedPolicy[] = [
  // ============================================================
  // PRIORITY — severity-based (the only priority source since the risk-score
  // rules were retired). Severity
  // itself is NEVER changed by any of this — these rules only ever set
  // `priority`, never touch the `severity` field.
  // ============================================================
  {
    code: "POL-001",
    name: "Critical Severity Priority",
    description: "Critical-severity incidents are at least P0. SOC investigates; IR decides and executes the response.",
    type: "PRIORITY",
    precedence: 10,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "CRITICAL" },
        result: { priority: "P0", responsibleRole: "SOC" },
      },
    ],
  },
  {
    code: "POL-003",
    name: "High Severity Priority",
    description: "High-severity incidents are at least P1. SOC investigates; IR decides and executes the response.",
    type: "PRIORITY",
    precedence: 20,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "HIGH" },
        result: { priority: "P1", responsibleRole: "SOC" },
      },
    ],
  },
  {
    code: "POL-005",
    name: "Medium Severity Priority",
    description: "Medium-severity incidents are at least P2, owned by SOC.",
    type: "PRIORITY",
    precedence: 30,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "MEDIUM" },
        result: { priority: "P2", responsibleRole: "SOC", investigationRequired: true },
      },
    ],
  },
  {
    code: "POL-007",
    name: "Low Severity Priority",
    description: "Low-severity incidents are at least P3, owned by SOC.",
    type: "PRIORITY",
    precedence: 40,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "LOW" },
        result: { priority: "P3", responsibleRole: "SOC", investigationRequired: true },
      },
    ],
  },

  // (RISK / PRIORITY rules RULE-R01..R04 were retired — see RISK_SCORE_RETIRED_CODES: Severity is the only
  // classification input; priority comes from the severity rules above.)

  // ============================================================
  // ASSIGNMENT — "who is responsible?" ONLY. Never sets approval.
  // SOC owns the investigation of every incident; IR_TEAM executes every response.
  // ============================================================
  {
    code: "RULE-A01",
    name: "Low Severity Assignment",
    description: "LOW severity -> SOC investigates, IR_TEAM executes.",
    type: "ASSIGNMENT",
    precedence: 50,
    rules: [{ condition: { field: "severity", operator: "eq", value: "LOW" }, result: { responsibleRole: "SOC", executorRole: "IR_TEAM" } }],
  },
  {
    code: "RULE-A02",
    name: "Medium Severity Assignment",
    description: "MEDIUM severity -> SOC investigates, IR_TEAM executes.",
    type: "ASSIGNMENT",
    precedence: 51,
    rules: [{ condition: { field: "severity", operator: "eq", value: "MEDIUM" }, result: { responsibleRole: "SOC", executorRole: "IR_TEAM" } }],
  },
  {
    code: "RULE-A03",
    name: "High Severity Assignment",
    description: "HIGH severity -> SOC investigates, IR_TEAM executes.",
    type: "ASSIGNMENT",
    precedence: 52,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "HIGH" },
        result: { responsibleRole: "SOC", executorRole: "IR_TEAM" },
      },
    ],
  },
  {
    code: "RULE-A04",
    name: "Critical Severity Assignment",
    description: "CRITICAL severity -> SOC investigates, IR_TEAM executes.",
    type: "ASSIGNMENT",
    precedence: 53,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "CRITICAL" },
        result: { responsibleRole: "SOC", executorRole: "IR_TEAM" },
      },
    ],
  },

  // ============================================================
  // APPROVAL — reason tags for the IR decision. Every Response Ticket waits
  // for IR_TEAM APPROVE / REJECT; these rules only say why it is sensitive
  // (severity, assetCriticality, actionImpactLevel). IR_TEAM is the only approver.
  // ============================================================
  // RULE-P01 ("no approval for low impact") was retired by the two-role workflow: see TWO_ROLE_RETIRED_CODES.
  {
    code: "RULE-P02",
    name: "High Severity IR Review",
    description: "HIGH severity: IR reviews the response.",
    type: "APPROVAL",
    precedence: 61,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "HIGH" },
        result: { reviewRequired: true, reviewRole: "IR_TEAM" },
      },
    ],
  },
  {
    code: "RULE-P03",
    name: "Critical Severity IR Review",
    description: "CRITICAL severity: IR reviews the response.",
    type: "APPROVAL",
    precedence: 62,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "CRITICAL" },
        result: { reviewRequired: true, reviewRole: "IR_TEAM" },
      },
    ],
  },
  {
    code: "RULE-P04",
    name: "Critical Asset High Impact IR Approval",
    description: "A critical asset combined with a high/critical-impact response action: IR_TEAM approval (reason CRITICAL_ASSET, HIGH_IMPACT_ACTION).",
    type: "APPROVAL",
    precedence: 63,
    rules: [
      {
        condition: {
          all: [
            { field: "assetCriticality", operator: "eq", value: "CRITICAL" },
            { any: [{ field: "actionImpactLevel", operator: "eq", value: "HIGH" }, { field: "actionImpactLevel", operator: "eq", value: "CRITICAL" }] },
          ],
        },
        result: { approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], approvalReason: ["CRITICAL_ASSET", "HIGH_IMPACT_ACTION"] },
      },
    ],
  },
  {
    code: "RULE-P05",
    name: "Critical Impact Action IR Approval",
    description: "A critical-impact response action: IR_TEAM approval (reason CRITICAL_IMPACT_ACTION).",
    type: "APPROVAL",
    precedence: 64,
    rules: [
      {
        condition: { field: "actionImpactLevel", operator: "eq", value: "CRITICAL" },
        result: { approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], approvalReason: ["CRITICAL_IMPACT_ACTION"] },
      },
    ],
  },
  {
    code: "RULE-P06",
    name: "Critical Severity Critical Asset IR Approval",
    description: "Critical severity AND a critical asset: IR_TEAM approval (reason CRITICAL_SEVERITY, CRITICAL_ASSET).",
    type: "APPROVAL",
    precedence: 65,
    rules: [
      {
        condition: { all: [{ field: "severity", operator: "eq", value: "CRITICAL" }, { field: "assetCriticality", operator: "eq", value: "CRITICAL" }] },
        result: {
          reviewRequired: true,
          reviewRole: "IR_TEAM",
          approvalRequired: true,
          approvalRole: "IR_TEAM",
          approvalChain: ["IR_TEAM"],
          approvalReason: ["CRITICAL_SEVERITY", "CRITICAL_ASSET"],
        },
      },
    ],
  },

  // ============================================================
  // APPROVAL CHAIN — exactly one approver: IR_TEAM. AI never approves (RULE-006).
  // ============================================================
  {
    code: "RULE-P07",
    name: "High Severity IR Approval",
    description: "HIGH severity: IR_TEAM must approve a Response before it can be executed.",
    type: "APPROVAL",
    precedence: 66,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "HIGH" },
        result: { approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], approvalReason: ["HIGH_SEVERITY"] },
      },
    ],
  },
  {
    code: "RULE-P09",
    name: "Critical Severity IR Approval",
    description: "CRITICAL severity: IR_TEAM must approve a Response before it can be executed.",
    type: "APPROVAL",
    precedence: 68,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "CRITICAL" },
        result: { approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], approvalReason: ["CRITICAL_SEVERITY"] },
      },
    ],
  },
  // ============================================================
  // ACTION COMPLIANCE (Knowledge Expansion for Evaluation, Step 6). POL-A01 is an APPROVAL reason like RULE-P04/P05
  // (no existing rule tags a HIGH-impact action on its own — P04 needs a critical asset, P05 a CRITICAL action).
  // POL-A02 / POL-A03 are ACTION_COMPLIANCE policies: the evidence an Action needs before a Recommendation may use
  // it, enforced deterministically by RecommendationValidator (domain/knowledge EVIDENCE_REQUIREMENTS ids). They
  // never approve, execute or skip anything; IR still decides every Response Ticket.
  // ============================================================
  {
    code: "POL-A01",
    name: "High Impact Action Requires IR Approval",
    description: "High-impact containment actions (Isolate Endpoint, Disable User Account, Reset User Credentials, Remove Unauthorized Privilege) require IR_TEAM approval before execution (reason HIGH_IMPACT_ACTION).",
    type: "APPROVAL",
    precedence: 67,
    rules: [
      {
        condition: { field: "actionImpactLevel", operator: "eq", value: "HIGH" },
        result: { approvalRequired: true, approvalRole: "IR_TEAM", approvalChain: ["IR_TEAM"], approvalReason: ["HIGH_IMPACT_ACTION"] },
      },
    ],
  },
  {
    code: "POL-A02",
    name: "Network Blocking Requires Validated IOC",
    description: "Block Source IP / Destination IP / Domain / URL / Sender and Rate-Limit Source need a validated IOC of the right kind, a related event naming it and supporting evidence.",
    type: "ACTION_COMPLIANCE",
    precedence: 75,
    rules: [
      {
        condition: {
          any: NETWORK_BLOCK_ACTIONS.map((code) => ({ field: "actionCode", operator: "eq", value: code })),
        },
        result: { requiredEvidence: ["VALIDATED_IOC_TARGET", "RELATED_EVENT", "SUPPORTING_EVIDENCE"] },
      },
    ],
  },
  {
    code: "POL-A03",
    name: "Endpoint Containment Requires Endpoint Evidence",
    description: "Isolate Endpoint / Terminate Malicious Process / Quarantine File need the affected endpoint and evidence of the activity on it.",
    type: "ACTION_COMPLIANCE",
    precedence: 76,
    rules: [
      {
        condition: {
          any: ENDPOINT_CONTAINMENT_ACTIONS.map((code) => ({ field: "actionCode", operator: "eq", value: code })),
        },
        result: { requiredEvidence: ["AFFECTED_ENDPOINT", "SUSPICIOUS_ACTIVITY_EVIDENCE"] },
      },
    ],
  },

  // ============================================================
  // INTAKE — Alert -> Incident (deterministic, from the Wazuh rule severity):
  //   LOW       stored only; never enters the SOC workflow, never opens an incident
  //   MEDIUM    waits in the Alert Inbox for SOC review (close, or create an incident)
  //   HIGH/CRIT open an incident automatically; SOC investigates it
  // ============================================================
  {
    code: "RULE-I01",
    name: "Low Severity Alert Not In SOC Workflow",
    description: "LOW-severity alerts are stored but do not enter the SOC workflow and never open an incident.",
    type: "INTAKE",
    precedence: 5,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "LOW" },
        result: { autoCreateIncident: false },
      },
    ],
  },
  {
    code: "RULE-I02",
    name: "Medium Severity Alert SOC Review",
    description: "MEDIUM-severity alerts wait in the Alert Inbox for SOC review (close, or create an incident).",
    type: "INTAKE",
    precedence: 5,
    rules: [{ condition: { field: "severity", operator: "eq", value: "MEDIUM" }, result: { autoCreateIncident: false } }],
  },
  {
    code: "RULE-I03",
    name: "High Severity Alert Auto Incident",
    description: "HIGH-severity alerts open an incident automatically (SOC investigates it).",
    type: "INTAKE",
    precedence: 5,
    rules: [{ condition: { field: "severity", operator: "eq", value: "HIGH" }, result: { autoCreateIncident: true } }],
  },
  {
    code: "RULE-I04",
    name: "Critical Severity Alert Auto Incident",
    description: "CRITICAL-severity alerts open an incident automatically (SOC investigates it).",
    type: "INTAKE",
    precedence: 5,
    rules: [{ condition: { field: "severity", operator: "eq", value: "CRITICAL" }, result: { autoCreateIncident: true } }],
  },

  // Alert Inbox triage SLA (TRIAGE_SLA): read on its own, never merged into the response / approval evaluation.
  {
    code: "RULE-T01",
    name: "Critical Alert Triage SLA",
    description: "SOC must triage a CRITICAL alert within 15 minutes of receipt.",
    type: "TRIAGE_SLA",
    precedence: 5,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "CRITICAL" },
        result: { triageSlaMinutes: 15 },
      },
    ],
  },
  // Alert Inbox triage SLA (TRIAGE_SLA): read on its own, never merged into the response / approval evaluation.
  {
    code: "RULE-T02",
    name: "High Alert Triage SLA",
    description: "SOC must triage a HIGH alert within 30 minutes of receipt.",
    type: "TRIAGE_SLA",
    precedence: 5,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "HIGH" },
        result: { triageSlaMinutes: 30 },
      },
    ],
  },
  // Alert Inbox triage SLA (TRIAGE_SLA): read on its own, never merged into the response / approval evaluation.
  {
    code: "RULE-T03",
    name: "Medium Alert Triage SLA",
    description: "SOC must triage a MEDIUM alert within 4 hours of receipt.",
    type: "TRIAGE_SLA",
    precedence: 5,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "MEDIUM" },
        result: { triageSlaMinutes: 240 },
      },
    ],
  },
  // Alert Inbox triage SLA (TRIAGE_SLA): read on its own, never merged into the response / approval evaluation.
  {
    code: "RULE-T04",
    name: "Low Alert Triage SLA",
    description: "SOC must triage a LOW alert within 24 hours of receipt.",
    type: "TRIAGE_SLA",
    precedence: 5,
    rules: [
      {
        condition: { field: "severity", operator: "eq", value: "LOW" },
        result: { triageSlaMinutes: 1440 },
      },
    ],
  },

  // ============================================================
  // VERIFICATION — happens AFTER Response. Only ever sets flags for a
  // caller (CreateVerification.usecase.ts) to act on; NEVER triggers a
  // Response itself. See that use-case for the investigationNumber += 1
  // mechanic these flags drive.
  // ============================================================
  {
    code: "RULE-V01",
    name: "Verification Not Resolved",
    description: "A NOT_RESOLVED verification result reopens investigation and requires a new recommendation.",
    type: "VERIFICATION",
    precedence: 70,
    rules: [
      {
        condition: { field: "verificationResult", operator: "eq", value: "NOT_RESOLVED" },
        result: { incidentStatus: "INVESTIGATING", requireNewInvestigation: true, requireNewRecommendation: true },
      },
    ],
  },
  {
    code: "RULE-V02",
    name: "Threat Spread",
    description: "Detected spread triggers escalation and a new investigation/recommendation cycle.",
    type: "VERIFICATION",
    precedence: 71,
    rules: [
      {
        condition: { field: "spreadDetected", operator: "eq", value: true },
        result: { incidentStatus: "INVESTIGATING", requireEscalation: true, requireNewInvestigation: true, requireNewRecommendation: true },
      },
    ],
  },
  {
    code: "RULE-V03",
    name: "Threat Not Contained",
    description: "A failed containment requires additional evidence and a new investigation/recommendation cycle.",
    type: "VERIFICATION",
    precedence: 72,
    rules: [
      {
        condition: { field: "threatContained", operator: "eq", value: false },
        result: { incidentStatus: "INVESTIGATING", requireNewInvestigation: true, requireAdditionalEvidence: true, requireNewRecommendation: true },
      },
    ],
  },
];

export const SPREAD_POLICIES: SeedPolicy[] = SPREAD_RESPONSES.map(response => ({
  code: spreadPolicyCode(response.incidentType),
  name: `${response.incidentType} spread containment`,
  description: `Re-hunt spread response for ${response.playbookCode}; actions require evidence and IR decision.`,
  type: "RESPONSE_GUIDANCE", precedence: 80,
  rules: [{ condition: { all: [
    { field: "incidentType", operator: "eq", value: response.incidentType },
    { field: "spreadDetected", operator: "eq", value: true },
    { field: "verificationResult", operator: "eq", value: "NOT_RESOLVED" },
  ] }, result: { allowedActions: [...response.actions], guidanceNote: response.guidance } }],
}));

export async function seedPolicies(prisma: PrismaClient, tenantId: string): Promise<void> {
  // Remove retired codes' rows outright so they can never fire again — a
  // stale enabled row silently reintroducing old behavior would be worse
  // than a clean delete-and-reseed.
  await prisma.policyRule.deleteMany({ where: { policy: { code: { in: RETIRED_CODES } } } });
  await prisma.policy.deleteMany({ where: { code: { in: RETIRED_CODES } } });

  // Risk-score rules: disabled, never deleted (history). See RISK_SCORE_RETIRED_CODES.
  await prisma.policy.updateMany({ where: { code: { in: RISK_SCORE_RETIRED_CODES } }, data: { enabled: false } });

  for (const seed of [...POLICIES, ...SPREAD_POLICIES]) {
    const policy = await prisma.policy.upsert({
      where: { code: seed.code },
      update: {
        name: seed.name,
        description: seed.description,
        type: seed.type,
        precedence: seed.precedence,
      },
      create: {
        tenantId,
        code: seed.code,
        name: seed.name,
        description: seed.description,
        type: seed.type,
        precedence: seed.precedence,
      },
    });

    // Replace this policy's rule set wholesale so re-seeding never
    // accumulates duplicate/stale rules.
    await prisma.policyRule.deleteMany({ where: { policyId: policy.id } });
    await prisma.policyRule.createMany({
      data: seed.rules.map((rule) => ({
        policyId: policy.id,
        condition: rule.condition,
        result: rule.result,
      })),
    });
  }

  await prisma.policy.updateMany({ where: { code: { in: TWO_ROLE_RETIRED_CODES } }, data: { enabled: false } });

  console.log(`  Policies: ${POLICIES.length + SPREAD_POLICIES.length} seeded (${[...POLICIES, ...SPREAD_POLICIES].map((p) => p.code).join(", ")})`);
}
