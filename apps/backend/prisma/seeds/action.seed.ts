import { PrismaClient } from "@prisma/client";

/**
 * action.seed.ts — the Action Catalog. This is the ONLY source of valid,
 * executable action ids for the Recommendation/Response workflow:
 * RecommendationValidator rejects any actionId an AI candidate proposes
 * that isn't found here AND enabled=true (RULE-001/003/012).
 *
 * REVISION NOTE (VIGIX Action Catalog spec): the 6 CONTAINMENT actions
 * below (ACT-BLOCK-SOURCE-IP .. ACT-QUARANTINE-EMAIL) are the authoritative
 * "controlled set of short-term containment actions" per that spec —
 * codes, names, and category renamed/added to match it exactly. Two
 * actions from the previous revision (ACT-005 "Stop Malicious Process",
 * ACT-006 "Quarantine File") had no equivalent in the new spec and are
 * retired — malware/process/hash scenarios now route to Isolate Endpoint
 * instead (see FakeRecommendationAgent.ts's updated iocType mapping).
 *
 * ACT-007 (Collect Evidence, INVESTIGATION) and ACT-008 (Re-hunt IOC,
 * VERIFICATION) are kept UNCHANGED — the new spec is explicitly scoped to
 * "short-term containment actions" only and does not address investigation
 * or verification actions, both of which the Recommendation pipeline
 * still structurally needs (initial investigate step, final re-hunt step).
 *
 * No new Prisma columns were added for this revision — `target`,
 * `applicableIncidents`, `requiredEvidence`, `expectedEffect`,
 * `verification`, and `risk` from the spec are folded into `description`
 * as structured text rather than new schema fields (explicit scope
 * decision — see conversation record).
 */

export interface SeedAction {
  code: string;
  name: string;
  description: string;
  category: "CONTAINMENT" | "INVESTIGATION" | "VERIFICATION";
  impactLevel: "LOW" | "MEDIUM" | "HIGH";
  defaultApprovalRequired: boolean;
}

export const ACTIONS: SeedAction[] = [
  {
    code: "ACT-BLOCK-SOURCE-IP",
    name: "Block Source IP",
    description:
      "Network Containment. Prevent communication from an identified suspicious source IP. " +
      "Target: source IP, network security control. Applicable: Brute Force, Network Attack, " +
      "Malware-like Behavior, Ransomware Simulation. Required evidence: source IP, related event, " +
      "supporting malicious/suspicious evidence. Expected effect: reduce or prevent further " +
      "communication from the identified source. Verification: re-hunt source IP, check whether " +
      "related events continue, check other hosts. Risk: potentially blocking legitimate traffic " +
      "if the source is incorrectly identified.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-DISABLE-ACCOUNT",
    name: "Disable User Account",
    description:
      "Account Containment. Temporarily prevent authentication using a potentially compromised " +
      "account. Target: user account. Applicable: Brute Force, Phishing, Credential Attack. " +
      "Required evidence: account identifier, suspicious authentication or compromise evidence. " +
      "Expected effect: prevent further authentication using the affected account. Verification: " +
      "check authentication events, check for use of other accounts, search related activity.",
    category: "CONTAINMENT",
    impactLevel: "HIGH",
    defaultApprovalRequired: true,
  },
  {
    code: "ACT-ISOLATE-ENDPOINT",
    name: "Isolate Endpoint",
    description:
      "Endpoint Containment. Restrict network connectivity of an affected endpoint. Target: " +
      "endpoint. Applicable: Malware-like Behavior, Ransomware Simulation, Network Attack, " +
      "Phishing with confirmed endpoint compromise. Required evidence: affected endpoint, " +
      "suspicious activity, evidence supporting endpoint compromise. Expected effect: reduce " +
      "communication from the affected endpoint and limit potential spread. Verification: " +
      "re-hunt endpoint, check suspicious process, check network activity, check other endpoints.",
    category: "CONTAINMENT",
    impactLevel: "HIGH",
    defaultApprovalRequired: true,
  },
  {
    code: "ACT-BLOCK-DOMAIN",
    name: "Block Domain",
    description:
      "Network Containment. Prevent communication with a malicious or suspicious domain. Target: " +
      "domain. Applicable: Phishing, Malware-like Behavior, Network Attack. Required evidence: " +
      "domain, related event, supporting IOC/TI evidence. Expected effect: reduce communication " +
      "with the identified domain.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-BLOCK-URL",
    name: "Block URL",
    description:
      "Web Containment. Prevent access to a confirmed malicious URL. Target: URL. Applicable: " +
      "Phishing, Malware-like Behavior. Required evidence: URL, related email/event, supporting " +
      "evidence. Expected effect: reduce access to the identified malicious resource.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-QUARANTINE-EMAIL",
    name: "Quarantine Email",
    description:
      "Email Containment. Remove or quarantine a malicious/suspicious email from user mailboxes. " +
      "Target: email/message id. Applicable: Phishing. Required evidence: message id, sender, " +
      "recipient, malicious indicator. Expected effect: reduce additional user interaction with " +
      "the malicious message.",
    category: "CONTAINMENT",
    impactLevel: "LOW",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-007",
    name: "Collect Evidence",
    description: "Captures forensic evidence (disk image, memory dump, logs) from the affected host for investigation.",
    category: "INVESTIGATION",
    impactLevel: "LOW",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-008",
    name: "Re-hunt IOC",
    description: "Re-runs SIEM/EDR detection for a specific IOC across the environment to confirm containment/eradication and detect recurrence.",
    category: "VERIFICATION",
    impactLevel: "LOW",
    defaultApprovalRequired: false,
  },
];

/** Codes from the previous revision with no equivalent in the new spec —
 * deleted outright so they can never be recommended again. */
export const RETIRED_CODES = ["ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006"];

/**
 * Task 10.3 — Action → action-level Runbook link (actions.runbook_id). Each
 * containment Action has exactly one operational runbook (runbook.seed.ts,
 * RB-<ACTION>). ACT-QUARANTINE-EMAIL, ACT-007 and ACT-008 have no action-level
 * runbook yet, so they stay unlinked (null). Runbooks must be seeded first.
 */
export const ACTION_RUNBOOK_CODES: Record<string, string> = {
  "ACT-BLOCK-SOURCE-IP": "RB-BLOCK-SOURCE-IP",
  "ACT-BLOCK-DOMAIN": "RB-BLOCK-DOMAIN",
  "ACT-BLOCK-URL": "RB-BLOCK-URL",
  "ACT-ISOLATE-ENDPOINT": "RB-ISOLATE-ENDPOINT",
  "ACT-DISABLE-ACCOUNT": "RB-DISABLE-ACCOUNT",
};

export async function seedActions(prisma: PrismaClient, tenantId: string): Promise<void> {
  await prisma.action.deleteMany({ where: { code: { in: RETIRED_CODES } } });

  for (const action of ACTIONS) {
    const runbookCode = ACTION_RUNBOOK_CODES[action.code];
    const runbook = runbookCode ? await prisma.runbook.findUnique({ where: { code: runbookCode } }) : null;
    if (runbookCode && !runbook) throw new Error(`seedActions: runbook ${runbookCode} for ${action.code} not seeded`);
    const runbookId = runbook?.id ?? null;
    await prisma.action.upsert({
      where: { code: action.code },
      update: {
        name: action.name,
        description: action.description,
        category: action.category,
        impactLevel: action.impactLevel,
        defaultApprovalRequired: action.defaultApprovalRequired,
        runbookId,
      },
      create: {
        tenantId,
        code: action.code,
        name: action.name,
        description: action.description,
        category: action.category,
        impactLevel: action.impactLevel,
        defaultApprovalRequired: action.defaultApprovalRequired,
        runbookId,
      },
    });
  }
}
