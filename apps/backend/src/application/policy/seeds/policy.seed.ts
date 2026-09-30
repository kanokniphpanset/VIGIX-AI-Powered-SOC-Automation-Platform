import { NewPolicyInput } from "../domain/repositories/IPolicyRepository";
import { PolicyCondition } from "../domain/entities/PolicyCondition";
import { PolicyResultFragment } from "../domain/entities/PolicyEvaluationTypes";

/**
 * policy.seed.ts
 *
 * Seed data transcribed from the VIGIX policy design doc: the Priority
 * table, the Assignment table, the Approval table, and the Verification
 * override rules. Grouped into four Policy records by PolicyType so each
 * group can be enabled/disabled/re-ordered independently in the admin UI:
 *
 *   1. priority-by-severity  (PRIORITY)    — RULE-001, 003, 005, 007
 *   2. priority-by-risk      (PRIORITY)    — RULE-002, 004, 006, 008
 *   3. verification-override (VERIFICATION)— RULE-009, 010, 011
 *   4. approval-and-review   (APPROVAL)    — RULE-012, 013, 014, 015
 *
 * Two things the design doc calls out explicitly are intentionally NOT
 * encoded here, because they don't belong in a PolicyResultFragment:
 *
 *   - "investigationNumber += 1" is an application-level counter change on
 *     the Incident record. The Policy Engine only ever returns
 *     requireNewInvestigation / requireEscalation / requireAdditionalEvidence
 *     as flags; whichever use-case applies this result to the Incident owns
 *     incrementing the counter — the engine itself never mutates an Incident.
 *
 *   - Verification rules never trigger a new Response by themselves. The
 *     doc is explicit about this flow:
 *       NOT_RESOLVED -> Investigation #2 -> Recommendation #2 -> Decision
 *       -> Approval (if the Approval policy requires it) -> Response
 *     — never "NOT_RESOLVED -> automatic Response". None of the fragments
 *     below set responseRequired for a verification rule.
 */

const priorityBySeverity = (tenantId: string): NewPolicyInput => ({
  tenantId,
  code: "priority-by-severity",
  name: "Priority & Assignment by Severity",
  description:
    "Assigns responsible role, P0-P3 priority, and first-response SLA from Incident severity alone (the design doc's Assignment Policy table: LOW/MEDIUM -> SOC, HIGH/CRITICAL -> IR_TEAM).",
  type: "PRIORITY",
  precedence: 10,
  rules: [
    // RULE-001 — Critical Severity Rule (P0)
    {
      condition: {
        field: "severity",
        operator: "eq",
        value: "CRITICAL",
      } as PolicyCondition,
      result: {
        priority: "P0",
        responsibleRole: "IR_TEAM",
        firstResponseSlaMinutes: 15,
        resolutionSlaMinutes: 240,
        approvalRequired: true,
        approvalRole: "IR_TEAM",
        approvalReason: ["Critical severity incident"],
      } as PolicyResultFragment,
    },

    // RULE-003 — High Severity Rule (P1)
    {
      condition: {
        field: "severity",
        operator: "eq",
        value: "HIGH",
      } as PolicyCondition,
      result: {
        priority: "P1",
        responsibleRole: "IR_TEAM",
        firstResponseSlaMinutes: 30,
        resolutionSlaMinutes: 480,
      } as PolicyResultFragment,
    },

    // RULE-005 — Medium Severity Rule (P2)
    {
      condition: {
        field: "severity",
        operator: "eq",
        value: "MEDIUM",
      } as PolicyCondition,
      result: {
        priority: "P2",
        responsibleRole: "SOC",
        firstResponseSlaMinutes: 240,
        resolutionSlaMinutes: 4320, // 3 business days, counted as 3 calendar days
      } as PolicyResultFragment,
    },

    // RULE-007 — Low Severity Rule (P3)
    {
      condition: {
        field: "severity",
        operator: "eq",
        value: "LOW",
      } as PolicyCondition,
      result: {
        priority: "P3",
        responsibleRole: "SOC",
        firstResponseSlaMinutes: 1440, // 1 business day, counted as 1 calendar day
        resolutionSlaMinutes: 10080, // 5 business days, counted as 1 calendar week
      } as PolicyResultFragment,
    },
  ],
});

const priorityByRisk = (tenantId: string): NewPolicyInput => ({
  tenantId,
  code: "priority-by-risk",
  name: "Priority Escalation by Risk Score",
  description:
    "Escalates review/investigation depth from riskScore, independent of Severity — riskScore never overwrites Severity itself (see PolicyEvaluationTypes.ts).",
  type: "PRIORITY",
  precedence: 20,
  rules: [
    // RULE-002 — Critical Risk Rule (P0)
    {
      condition: {
        field: "riskScore",
        operator: "gte",
        value: 75,
      } as PolicyCondition,
      result: {
        priority: "P0",
        responsibleRole: "IR_TEAM",
        highRiskReview: true,

        // Risk >= 75 requires IR review and IR approval.
        reviewRequired: true,
        reviewRole: "IR_TEAM",

        approvalRequired: true,
        approvalRole: "IR_TEAM",
        approvalReason: ["Risk score >= 75"],
      } as PolicyResultFragment,
    },

    // RULE-004 — High Risk Rule (P1)
    {
      condition: {
        field: "riskScore",
        operator: "gte",
        value: 50,
      } as PolicyCondition,
      result: {
        priority: "P1",
        responsibleRole: "IR_TEAM",
        highRiskReview: true,

        // Risk >= 50 requires IR technical review.
        reviewRequired: true,
        reviewRole: "IR_TEAM",
      } as PolicyResultFragment,
    },

    // RULE-006 — Medium Risk Rule (P2)
    {
      condition: {
        field: "riskScore",
        operator: "gte",
        value: 25,
      } as PolicyCondition,
      result: {
        priority: "P2",
        additionalInvestigation: true,
      } as PolicyResultFragment,
    },

    // RULE-008 — Low Risk Rule (P3)
    {
      condition: {
        field: "riskScore",
        operator: "lt",
        value: 25,
      } as PolicyCondition,
      result: {
        priority: "P3",
        standardInvestigation: true,
      } as PolicyResultFragment,
    },
  ],
});

const verificationOverride = (tenantId: string): NewPolicyInput => ({
  tenantId,
  code: "verification-override",
  name: "Verification Outcome Overrides",
  description:
    "Fires only after a Response has been verified. Never triggers a new Response by itself — only reopens the investigation loop (Verification -> Investigation #2 -> Recommendation #2 -> Decision -> Approval -> Response).",
  type: "VERIFICATION",
  precedence: 10,
  rules: [
    // RULE-009 — Verification Failure
    {
      condition: {
        field: "verificationResult",
        operator: "eq",
        value: "NOT_RESOLVED",
      } as PolicyCondition,
      result: {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireNewRecommendation: true,
      } as PolicyResultFragment,
    },

    // RULE-010 — Threat Spread
    {
      condition: {
        field: "spreadDetected",
        operator: "eq",
        value: true,
      } as PolicyCondition,
      result: {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireEscalation: true,
      } as PolicyResultFragment,
    },

    // RULE-011 — Threat Not Contained
    {
      condition: {
        field: "threatContained",
        operator: "eq",
        value: false,
      } as PolicyCondition,
      result: {
        incidentStatus: "INVESTIGATING",
        requireNewInvestigation: true,
        requireAdditionalEvidence: true,
      } as PolicyResultFragment,
    },
  ],
});

const approvalAndReview = (tenantId: string): NewPolicyInput => ({
  tenantId,
  code: "approval-and-review",
  name: "Approval & Review Requirements",
  description:
    "The design doc's Approval Policy table, kept separate from Assignment/Priority: Severity decides WHO owns the case, this policy decides WHO must sign off before Response.",
  type: "APPROVAL",
  precedence: 10,
  rules: [
    // RULE-012 — Critical incident on a critical asset needs IR
    // approval, even in cases where severity alone would not have required it.
    {
      condition: {
        all: [
          {
            field: "severity",
            operator: "eq",
            value: "CRITICAL",
          },
          {
            field: "assetCriticality",
            operator: "eq",
            value: "CRITICAL",
          },
        ],
      } as PolicyCondition,
      result: {
        approvalRequired: true,
        approvalRole: "IR_TEAM",
        approvalReason: ["Critical severity on a critical asset"],
      } as PolicyResultFragment,
    },

    // RULE-013 — Any high-impact response action needs IR approval,
    // regardless of severity.
    {
      condition: {
        any: [
          {
            field: "actionImpactLevel",
            operator: "eq",
            value: "HIGH",
          },
          {
            field: "actionImpactLevel",
            operator: "eq",
            value: "CRITICAL",
          },
        ],
      } as PolicyCondition,
      result: {
        approvalRequired: true,
        approvalRole: "IR_TEAM",
        approvalReason: ["High-impact response action"],
      } as PolicyResultFragment,
    },

    // RULE-014 — HIGH or CRITICAL incidents always get an IR Team
    // technical review before a Recommendation becomes a Response.
    {
      condition: {
        any: [
          {
            field: "severity",
            operator: "eq",
            value: "HIGH",
          },
          {
            field: "severity",
            operator: "eq",
            value: "CRITICAL",
          },
        ],
      } as PolicyCondition,
      result: {
        reviewRequired: true,
        reviewRole: "IR_TEAM",
      } as PolicyResultFragment,
    },

    // RULE-015 — HIGH/CRITICAL severity + critical asset + high-impact
    // action requires IR approval.
    {
      condition: {
        all: [
          {
            any: [
              {
                field: "severity",
                operator: "eq",
                value: "HIGH",
              },
              {
                field: "severity",
                operator: "eq",
                value: "CRITICAL",
              },
            ],
          },
          {
            field: "assetCriticality",
            operator: "eq",
            value: "CRITICAL",
          },
          {
            any: [
              {
                field: "actionImpactLevel",
                operator: "eq",
                value: "HIGH",
              },
              {
                field: "actionImpactLevel",
                operator: "eq",
                value: "CRITICAL",
              },
            ],
          },
        ],
      } as PolicyCondition,
      result: {
        approvalRequired: true,
        approvalRole: "IR_TEAM",
        approvalReason: [
          "High/critical severity + critical asset + high-impact action",
        ],
      } as PolicyResultFragment,
    },
  ],
});

export function buildPolicySeeds(tenantId: string): NewPolicyInput[] {
  return [
    priorityBySeverity(tenantId),
    priorityByRisk(tenantId),
    verificationOverride(tenantId),
    approvalAndReview(tenantId),
  ];
}

/**
 * Example seed-runner — adjust to however this repo wires up its Prisma
 * client / DI container. This file has no side effects on import, so
 * buildPolicySeeds() itself is safe to unit test in isolation:
 *
 *   import { PrismaClient } from "@prisma/client";
 *   import { PrismaPolicyRepository } from "../infrastructure/repositories/PrismaPolicyRepository";
 *   import { buildPolicySeeds } from "./policy.seed";
 *
 *   const prisma = new PrismaClient();
 *   const repo = new PrismaPolicyRepository(prisma);
 *   for (const policy of buildPolicySeeds(tenantId)) {
 *     await repo.create(policy);
 *   }
 */