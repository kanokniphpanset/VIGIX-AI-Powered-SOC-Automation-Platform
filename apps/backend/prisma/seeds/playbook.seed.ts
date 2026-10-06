import { Prisma, PrismaClient } from "@prisma/client";

/**
 * playbook.seed.ts — seeds STC-001 "Short-Term Containment" v1.0 and the
 * incident-level playbooks, the process/lifecycle a Recommendation is generated
 * against (never attack-specific — that belongs to Runbook).
 *
 * Phase 1D revision lifecycle: the seed never writes runtime or revision data of
 * an existing playbook. Per code:
 *   - missing        -> CREATED_DRAFT: playbook row status DRAFT (not selectable),
 *                       no published revision, revision 1 DRAFT holding the
 *                       definition (content.playbookStatus ACTIVE once published),
 *                       created by "system:seed". It goes live only through
 *                       submit -> approve -> publish by humans.
 *   - published      -> PRESERVED_PUBLISHED (nothing written)
 *   - has revisions  -> PRESERVED_DRAFT (nothing written; no duplicate revision)
 *   - no revisions   -> SKIPPED_NO_REVISION (pre-revision row; nothing written)
 *   - other tenant   -> SKIPPED_OTHER_TENANT (code is globally unique)
 * Idempotent: a second run creates nothing.
 *
 * Step titles/order are exact per spec (7 lifecycle stages, generic —
 * Playbook itself never names a specific action or attack type; that
 * belongs to the Action Catalog and Runbook respectively). An earlier
 * revision used shorter synonym titles for steps 2/5/6/7 — corrected here
 * to the spec's exact wording.
 */

export const PLAYBOOK_CODE = "STC-001";

const STEPS: { stepOrder: number; title: string; description: string }[] = [
  { stepOrder: 1, title: "Validate Incident", description: "Confirm affected host, confirm IOC/evidence, confirm incident scope." },
  { stepOrder: 2, title: "Assess Containment Need", description: "Is the threat active? Is the host compromised? Is the threat spreading? Determine containment urgency." },
  { stepOrder: 3, title: "Select Containment Action", description: "Select an approved action from the Action Catalog appropriate to the assessed containment need." },
  { stepOrder: 4, title: "Prepare Response Plan", description: "Assemble target, action, reason, expected result, and risk/impact into a Response Plan awaiting approval per Policy." },
  { stepOrder: 5, title: "Approval / Decision", description: "IR decision (APPROVE / REJECT with a note) on every Response Ticket; Policy only adds the reason tags." },
  { stepOrder: 6, title: "Execute Containment", description: "IR Team manually executes the approved action and records the real-world result." },
  { stepOrder: 7, title: "Verify Containment", description: "Re-hunt Wazuh, check affected host, check IOC recurrence, check spread, determine RESOLVED or NOT_RESOLVED." },
];

/**
 * Task 10.3 — INCIDENT-LEVEL playbooks. STC-001 above is the generic VIGIX Core
 * Flow (the process every incident goes through) and is never repeated inside a
 * Recommendation. The playbooks below are the per-incident-type response
 * STRATEGY: which Action Catalog entries apply to this kind of incident and in
 * what order of concern. A Recommendation must reference exactly the playbook
 * selected deterministically from the incident's MITRE techniques
 * (triggerConditions.mitreTechniques) and may only expand actions listed in
 * triggerConditions.allowedActions. Each Action's operational procedure lives in
 * its action-level Runbook (RB-<ACTION>, runbook.seed.ts) — not here.
 */
export interface SeedIncidentPlaybook {
  code: string;
  name: string;
  description: string;
  incidentType: string;
  mitreTechniques: string[];
  allowedActions: string[];
  steps: { stepOrder: number; title: string; description: string }[];
}

export const INCIDENT_PLAYBOOKS: SeedIncidentPlaybook[] = [
  {
    code: "PB-SSH-BRUTEFORCE",
    name: "SSH Brute Force Response",
    description: "Response strategy for repeated failed SSH authentication from an external source against a host.",
    incidentType: "SSH_BRUTE_FORCE",
    mitreTechniques: ["T1110", "T1110.001"],
    allowedActions: ["ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"],
    steps: [
      { stepOrder: 1, title: "Stop the attacking source", description: "Block the source IP recorded in the authentication evidence (ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 2, title: "Protect the targeted account", description: "Only if evidence shows a successful logon for the targeted account, disable it (ACT-DISABLE-ACCOUNT)." },
    ],
  },
  {
    code: "PB-MALWARE",
    name: "Malware Infection Response",
    description: "Response strategy for a malicious file or implant detected on an endpoint, including its download/C2 infrastructure.",
    incidentType: "MALWARE",
    mitreTechniques: ["T1204.002", "T1105"],
    allowedActions: [
      "ACT-ISOLATE-ENDPOINT",
      "ACT-BLOCK-DOMAIN",
      "ACT-BLOCK-URL",
      "ACT-BLOCK-SOURCE-IP",
      "ACT-KILL-PROCESS",
      "ACT-QUARANTINE-FILE",
      "ACT-BLOCK-HASH",
      "ACT-BLOCK-DESTINATION-IP",
    ],
    steps: [
      { stepOrder: 1, title: "Contain the infected endpoint", description: "Isolate the affected endpoint recorded in the evidence (ACT-ISOLATE-ENDPOINT)." },
      { stepOrder: 2, title: "Cut the delivery / C2 infrastructure", description: "Block the download URL, domain or C2 IP recorded in the evidence (ACT-BLOCK-URL / ACT-BLOCK-DOMAIN / ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 3, title: "Stop and remove the malicious file", description: "Terminate the process started from the file, quarantine the file and block its hash (ACT-KILL-PROCESS / ACT-QUARANTINE-FILE / ACT-BLOCK-HASH)." },
      { stepOrder: 4, title: "Block outbound C2 destinations", description: "Block outbound traffic to the C2 destination IP recorded in the network evidence (ACT-BLOCK-DESTINATION-IP)." },
    ],
  },
  {
    code: "PB-SQL-INJECTION",
    name: "SQL Injection Response",
    description: "Response strategy for SQL injection attempts against a public-facing web application.",
    incidentType: "SQL_INJECTION",
    mitreTechniques: ["T1190"],
    allowedActions: ["ACT-BLOCK-SOURCE-IP"],
    steps: [
      { stepOrder: 1, title: "Stop the attacking source", description: "Block the source IP of the injection requests at the WAF/firewall protecting the web tier (ACT-BLOCK-SOURCE-IP)." },
    ],
  },
  {
    code: "PB-ACCOUNT-COMPROMISE",
    name: "Account Compromise Response",
    description: "Response strategy for suspicious use or manipulation of a valid account.",
    incidentType: "ACCOUNT_COMPROMISE",
    mitreTechniques: ["T1078", "T1098"],
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT", "ACT-RESET-CREDENTIAL", "ACT-REVOKE-SESSION"],
    steps: [
      { stepOrder: 1, title: "Revoke the compromised identity", description: "Disable the account recorded in the evidence (ACT-DISABLE-ACCOUNT)." },
      { stepOrder: 2, title: "Stop the external access source", description: "Block the external source IP of the suspicious logon (ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 3, title: "Contain the affected host if misused", description: "Isolate the host only if evidence shows it was used for further malicious activity (ACT-ISOLATE-ENDPOINT)." },
      { stepOrder: 4, title: "Invalidate the stolen credentials and sessions", description: "Reset the credentials and revoke the active sessions of the account recorded in the authentication evidence (ACT-RESET-CREDENTIAL / ACT-REVOKE-SESSION)." },
    ],
  },
  {
    code: "PB-POWERSHELL",
    name: "Malicious PowerShell Response",
    description: "Response strategy for malicious/obfuscated PowerShell execution, download cradles and PowerShell-based persistence.",
    incidentType: "POWERSHELL",
    mitreTechniques: ["T1059.001", "T1547.001"],
    allowedActions: [
      "ACT-ISOLATE-ENDPOINT",
      "ACT-BLOCK-DOMAIN",
      "ACT-BLOCK-URL",
      "ACT-BLOCK-SOURCE-IP",
      "ACT-DISABLE-ACCOUNT",
      "ACT-KILL-PROCESS",
      "ACT-QUARANTINE-FILE",
      "ACT-BLOCK-HASH",
    ],
    steps: [
      { stepOrder: 1, title: "Contain the executing endpoint", description: "Isolate the endpoint where the PowerShell activity ran (ACT-ISOLATE-ENDPOINT)." },
      { stepOrder: 2, title: "Cut the stager / C2 infrastructure", description: "Block the stager/C2 URL, domain or IP recorded in the evidence (ACT-BLOCK-URL / ACT-BLOCK-DOMAIN / ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 3, title: "Revoke the executing identity if abused", description: "Disable the user account only if evidence shows it was abused (ACT-DISABLE-ACCOUNT)." },
      { stepOrder: 4, title: "Stop the PowerShell process and its payload", description: "Terminate the malicious PowerShell process, quarantine the dropped script / payload and block its hash (ACT-KILL-PROCESS / ACT-QUARANTINE-FILE / ACT-BLOCK-HASH)." },
    ],
  },

  // ---- Knowledge Expansion for Evaluation (Step 4). allowedActions == the Actions applicable to the attack type
  // (domain/knowledge/actionKnowledge.ts); mitreTechniques == domain/knowledge/attackKnowledge.ts. Techniques do not
  // overlap with another playbook, so PlaybookSelector stays unambiguous (test/KnowledgeCatalog.test.ts).
  {
    code: "PB-PHISHING",
    name: "Phishing Response",
    description: "Response strategy for a malicious e-mail (link / attachment) and any credential theft or endpoint compromise it caused.",
    incidentType: "PHISHING",
    mitreTechniques: ["T1566", "T1566.001", "T1566.002"],
    allowedActions: [
      "ACT-QUARANTINE-EMAIL",
      "ACT-BLOCK-URL",
      "ACT-BLOCK-DOMAIN",
      "ACT-RESET-CREDENTIAL",
      "ACT-REVOKE-SESSION",
      "ACT-DISABLE-ACCOUNT",
      "ACT-ISOLATE-ENDPOINT",
    ],
    steps: [
      { stepOrder: 1, title: "Remove the message", description: "Quarantine the malicious message recorded in the evidence (ACT-QUARANTINE-EMAIL)." },
      { stepOrder: 2, title: "Cut the phishing infrastructure", description: "Block the malicious URL / domain recorded in the evidence (ACT-BLOCK-URL / ACT-BLOCK-DOMAIN)." },
      { stepOrder: 3, title: "Protect recipients who interacted", description: "Only when evidence shows a click or credential submission: reset the credentials and revoke the sessions of that account, or disable it (ACT-RESET-CREDENTIAL / ACT-REVOKE-SESSION / ACT-DISABLE-ACCOUNT)." },
      { stepOrder: 4, title: "Contain a compromised endpoint", description: "Only when evidence confirms endpoint compromise (attachment executed): isolate the endpoint (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
  {
    code: "PB-C2",
    name: "Command & Control Response",
    description: "Response strategy for an endpoint communicating with attacker command-and-control infrastructure.",
    incidentType: "COMMAND_AND_CONTROL",
    mitreTechniques: ["T1071", "T1573", "T1571"],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    steps: [
      { stepOrder: 1, title: "Cut the C2 channel", description: "Block the C2 destination IP / domain / URL recorded in the network evidence (ACT-BLOCK-DESTINATION-IP / ACT-BLOCK-DOMAIN / ACT-BLOCK-URL)." },
      { stepOrder: 2, title: "Contain the beaconing endpoint", description: "Isolate the endpoint that communicated with the C2 destination (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
  {
    code: "PB-DATA-EXFIL",
    name: "Data Exfiltration Response",
    description: "Response strategy for data leaving the environment over a C2 channel, an alternative protocol or a web service.",
    incidentType: "DATA_EXFILTRATION",
    mitreTechniques: ["T1041", "T1048", "T1567"],
    allowedActions: ["ACT-BLOCK-DESTINATION-IP", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-ISOLATE-ENDPOINT"],
    steps: [
      { stepOrder: 1, title: "Stop the transfer", description: "Block the exfiltration destination IP / domain / URL recorded in the transfer evidence (ACT-BLOCK-DESTINATION-IP / ACT-BLOCK-DOMAIN / ACT-BLOCK-URL)." },
      { stepOrder: 2, title: "Contain the source endpoint", description: "Isolate the endpoint the data left from (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
  {
    code: "PB-PRIV-ESC",
    name: "Privilege Escalation Response",
    description: "Response strategy for a user or process gaining higher privileges through an exploit or an abused elevation mechanism.",
    incidentType: "PRIVILEGE_ESCALATION",
    mitreTechniques: ["T1068", "T1548"],
    allowedActions: ["ACT-KILL-PROCESS", "ACT-DISABLE-ACCOUNT", "ACT-ISOLATE-ENDPOINT"],
    steps: [
      { stepOrder: 1, title: "Stop the elevated process", description: "Terminate the process running with escalated privileges (ACT-KILL-PROCESS)." },
      { stepOrder: 2, title: "Revoke the abusing identity", description: "Disable the account that escalated its privileges (ACT-DISABLE-ACCOUNT)." },
      { stepOrder: 3, title: "Contain the endpoint", description: "Isolate the endpoint when the escalation succeeded or persists (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
  {
    code: "PB-SUSPICIOUS-PROCESS",
    name: "Suspicious Process Execution Response",
    description: "Response strategy for suspicious execution through a command shell or a signed system binary proxying a payload.",
    incidentType: "SUSPICIOUS_PROCESS_EXECUTION",
    mitreTechniques: ["T1059.003", "T1059.004", "T1218"],
    allowedActions: ["ACT-KILL-PROCESS", "ACT-QUARANTINE-FILE", "ACT-BLOCK-HASH", "ACT-ISOLATE-ENDPOINT"],
    steps: [
      { stepOrder: 1, title: "Stop the suspicious process", description: "Terminate the process recorded in the evidence (ACT-KILL-PROCESS)." },
      { stepOrder: 2, title: "Remove the executed payload", description: "Quarantine the payload file and block its hash (ACT-QUARANTINE-FILE / ACT-BLOCK-HASH)." },
      { stepOrder: 3, title: "Contain the endpoint if compromised", description: "Isolate the endpoint when evidence shows further malicious activity (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
];

export type PlaybookSeedOutcome = "CREATED_DRAFT" | "PRESERVED_PUBLISHED" | "PRESERVED_DRAFT" | "SKIPPED_NO_REVISION" | "SKIPPED_OTHER_TENANT";

export interface PlaybookSeedDefinition {
  code: string;
  name: string;
  description: string;
  triggerConditions: Record<string, unknown>;
  steps: { stepOrder: number; title: string; description: string }[];
}

export const PLAYBOOK_SEED_ACTOR = "system:seed";

async function seedPlaybook(prisma: PrismaClient, tenantId: string, def: PlaybookSeedDefinition): Promise<PlaybookSeedOutcome> {
  return prisma.$transaction(async (tx) => {
    const existing = await tx.playbook.findUnique({ where: { code: def.code }, select: { tenantId: true, publishedRevisionId: true, _count: { select: { revisions: true } } } });
    if (existing) {
      if (existing.tenantId !== tenantId) return "SKIPPED_OTHER_TENANT";
      if (existing.publishedRevisionId) return "PRESERVED_PUBLISHED";
      return existing._count.revisions > 0 ? "PRESERVED_DRAFT" : "SKIPPED_NO_REVISION";
    }
    const steps = [...def.steps].sort((a, b) => a.stepOrder - b.stepOrder);
    const playbook = await tx.playbook.create({
      data: {
        tenantId, code: def.code, name: def.name, description: def.description, version: "1.0", status: "DRAFT",
        triggerConditions: def.triggerConditions as Prisma.InputJsonValue, steps: { create: steps },
      },
    });
    await tx.playbookRevision.create({
      data: {
        tenantId, playbookId: playbook.id, revisionNumber: 1, version: "1.0", status: "DRAFT", createdBy: PLAYBOOK_SEED_ACTOR,
        proposalReason: "Initial seed definition",
        content: {
          code: def.code, name: def.name, description: def.description, triggerConditions: def.triggerConditions, n8nWorkflowId: null,
          playbookStatus: "ACTIVE", version: "1.0", steps: steps.map((st) => ({ stepOrder: st.stepOrder, title: st.title, description: st.description })),
        } as Prisma.InputJsonValue,
      },
    });
    return "CREATED_DRAFT";
  });
}

/** Seeds the given definitions (see the file header for the per-code outcome); returns the outcome per code. */
export async function seedPlaybookDefinitions(prisma: PrismaClient, tenantId: string, defs: PlaybookSeedDefinition[]): Promise<{ code: string; outcome: PlaybookSeedOutcome }[]> {
  const results: { code: string; outcome: PlaybookSeedOutcome }[] = [];
  for (const def of defs) results.push({ code: def.code, outcome: await seedPlaybook(prisma, tenantId, def) });
  return results;
}

/** STC-001 + INCIDENT_PLAYBOOKS as seed definitions (data unchanged). */
export function playbookSeedDefinitions(): PlaybookSeedDefinition[] {
  return [
    {
      code: PLAYBOOK_CODE,
      name: "Short-Term Containment",
      description: "Standard end-to-end process from triage through verification for an incident requiring short-term containment.",
      triggerConditions: {},
      steps: STEPS,
    },
    ...INCIDENT_PLAYBOOKS.map((pb) => ({
      code: pb.code,
      name: pb.name,
      description: pb.description,
      triggerConditions: { scope: "INCIDENT", incidentType: pb.incidentType, mitreTechniques: pb.mitreTechniques, allowedActions: pb.allowedActions },
      steps: pb.steps,
    })),
  ];
}

export async function seedPlaybooks(prisma: PrismaClient, tenantId: string): Promise<{ code: string; outcome: PlaybookSeedOutcome }[]> {
  return seedPlaybookDefinitions(prisma, tenantId, playbookSeedDefinitions());
}
