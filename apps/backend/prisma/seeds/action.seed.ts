import { PrismaClient } from "@prisma/client";
import { ACTION_KNOWLEDGE } from "../../src/domain/knowledge/actionKnowledge";

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

  // Knowledge Expansion for Evaluation (Step 3). New codes — the retired ACT-005 / ACT-006 are NOT reused. Structured
  // knowledge (applicability, required evidence, verification) lives in src/domain/knowledge/actionKnowledge.ts.
  {
    code: "ACT-QUARANTINE-FILE",
    name: "Quarantine File",
    description:
      "Endpoint Containment. Quarantine an identified malicious file on the affected endpoint. Target: file path. " +
      "Applicable: Malware, PowerShell Attack, Suspicious Process Execution. Required evidence: affected endpoint, " +
      "file path, file hash, supporting malicious evidence. Expected effect: prevent execution or further use of the " +
      "identified malicious file. Verification: re-hunt file hash, check file/process recurrence, check endpoint " +
      "activity. Risk: quarantining a legitimate file if it is misidentified.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-KILL-PROCESS",
    name: "Terminate Malicious Process",
    description:
      "Endpoint Containment. Terminate an identified malicious process on the affected endpoint. Target: process. " +
      "Applicable: Malware, PowerShell Attack, Suspicious Process Execution, Privilege Escalation. Required evidence: " +
      "endpoint, process name, PID, command line, supporting malicious evidence. Expected effect: terminate the " +
      "identified malicious process. Verification: confirm the process no longer exists, re-hunt process/hash, check " +
      "recurrence. Risk: terminating a legitimate or critical process if it is misidentified.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-RESET-CREDENTIAL",
    name: "Reset User Credentials",
    description:
      "Account Containment. Invalidate compromised credentials and require new credentials. Target: user account. " +
      "Applicable: Account Compromise, Phishing, Brute Force. Required evidence: account identifier, suspicious authentication " +
      "evidence, evidence of credential compromise. Expected effect: invalidate compromised credentials and require " +
      "new credentials. Verification: check authentication events, check old credential usage, check suspicious " +
      "account activity. Risk: interrupting the user and dependent services.",
    category: "CONTAINMENT",
    impactLevel: "HIGH",
    defaultApprovalRequired: true,
  },
  {
    code: "ACT-REVOKE-SESSION",
    name: "Revoke Active Sessions",
    description:
      "Account Containment. Terminate active sessions associated with the affected account. Target: user account. " +
      "Applicable: Account Compromise, Phishing, Brute Force, Data Exfiltration, Privilege Escalation. Required evidence: account identifier, active/suspicious session " +
      "evidence. Expected effect: terminate active sessions associated with the affected account. Verification: " +
      "check session activity, check authentication events, check recurrence. Risk: signing out the legitimate user.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-BLOCK-HASH",
    name: "Block File Hash",
    description:
      "Endpoint Containment. Block execution of an identified malicious file hash. Target: file hash. Applicable: " +
      "Malware, PowerShell Attack, Suspicious Process Execution, Phishing (attachment), Command & Control (implant). Required evidence: file hash, related event, " +
      "supporting malicious evidence. Expected effect: prevent execution or detection of the identified malicious " +
      "file hash. Verification: re-hunt hash, check recurrence. Risk: blocking a legitimate binary if misidentified.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-BLOCK-DESTINATION-IP",
    name: "Block Destination IP",
    description:
      "Network Containment. Prevent communication to an identified malicious destination IP (C2 / exfiltration). " +
      "Target: destination IP, network security control. Applicable: Command & Control, Data Exfiltration, Malware. " +
      "Required evidence: destination IP, related network event, supporting IOC/CTI evidence. Expected effect: " +
      "prevent communication to the identified destination IP. Verification: re-hunt destination IP, check network " +
      "events, check recurrence. Risk: blocking a shared or legitimate destination if misidentified.",
    category: "CONTAINMENT",
    impactLevel: "MEDIUM",
    defaultApprovalRequired: false,
  },
  // Attack-specific containment procedures (knowledge/playbooks/PB-STC-001/procedures/*/containment.yaml): containment
  // controls no existing Action provided. Structured knowledge lives in src/domain/knowledge/actionKnowledge.ts.
  {
    code: "ACT-RATE-LIMIT-SOURCE",
    name: "Rate-Limit Source",
    description:
      "Network Containment. Throttle repeated authentication attempts or malicious requests from an identified source. " +
      "Target: source IP, authentication service / WAF / reverse proxy. Applicable: Brute Force, SQL Injection. Required " +
      "evidence: source IP, related event, supporting evidence of repeated abuse. Expected effect: repeated attempts from " +
      "the source are throttled or rejected. Verification: re-hunt source IP, check whether related events continue. Risk: " +
      "slowing legitimate users behind the same address (NAT / proxy).",
    category: "CONTAINMENT",
    impactLevel: "LOW",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-BLOCK-SENDER",
    name: "Block Sender",
    description:
      "Email Containment. Block further delivery from an identified malicious sender at the mail gateway. Target: sender " +
      "e-mail address. Applicable: Phishing. Required evidence: sender address, related message event. Expected effect: no " +
      "new message from the sender is delivered. Verification: re-hunt the sender in mail gateway logs. Risk: blocking a " +
      "legitimate (compromised) partner mailbox.",
    category: "CONTAINMENT",
    impactLevel: "LOW",
    defaultApprovalRequired: false,
  },
  {
    code: "ACT-REMOVE-PRIVILEGE",
    name: "Remove Unauthorized Privilege",
    description:
      "Account Containment. Remove a privilege / group membership granted without authorization. Target: user account. " +
      "Applicable: Privilege Escalation. Required evidence: account identifier, privilege change event, confirmation " +
      "that the change was not authorized. Expected effect: the account's privileges return to the approved baseline. " +
      "Verification: check group membership and privileged activity of the account. Risk: removing a legitimate " +
      "administrative privilege if the change was authorized.",
    category: "CONTAINMENT",
    impactLevel: "HIGH",
    defaultApprovalRequired: true,
  },
];

/** Codes from the previous revision with no equivalent in the new spec —
 * deleted outright so they can never be recommended again. */
export const RETIRED_CODES = ["ACT-001", "ACT-002", "ACT-003", "ACT-004", "ACT-005", "ACT-006"];

/**
 * Task 10.3 — Action → action-level Runbook link (actions.runbook_id). Each
 * containment Action has exactly one operational runbook (runbook.seed.ts).
 * Derived from the Action knowledge (actionKnowledge.ts `runbook`) so the link
 * has one source. ACT-007 and ACT-008 (Core Flow phases, never expanded) stay
 * unlinked (null). Runbooks must be seeded first.
 */
export const ACTION_RUNBOOK_CODES: Record<string, string> = Object.fromEntries(
  ACTION_KNOWLEDGE.filter((a) => a.runbook).map((a) => [a.code, a.runbook as string])
);

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
