import { PrismaClient } from "@prisma/client";

/**
 * playbook.seed.ts — seeds STC-001 "Short-Term Containment" v1.0 ACTIVE,
 * the process/lifecycle a Recommendation is generated against (never
 * attack-specific — that belongs to Runbook). Idempotent by `code`: steps
 * are replaced wholesale on every run so re-seeding never duplicates them.
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
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP"],
    steps: [
      { stepOrder: 1, title: "Contain the infected endpoint", description: "Isolate the affected endpoint recorded in the evidence (ACT-ISOLATE-ENDPOINT)." },
      { stepOrder: 2, title: "Cut the delivery / C2 infrastructure", description: "Block the download URL, domain or C2 IP recorded in the evidence (ACT-BLOCK-URL / ACT-BLOCK-DOMAIN / ACT-BLOCK-SOURCE-IP)." },
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
    allowedActions: ["ACT-DISABLE-ACCOUNT", "ACT-BLOCK-SOURCE-IP", "ACT-ISOLATE-ENDPOINT"],
    steps: [
      { stepOrder: 1, title: "Revoke the compromised identity", description: "Disable the account recorded in the evidence (ACT-DISABLE-ACCOUNT)." },
      { stepOrder: 2, title: "Stop the external access source", description: "Block the external source IP of the suspicious logon (ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 3, title: "Contain the affected host if misused", description: "Isolate the host only if evidence shows it was used for further malicious activity (ACT-ISOLATE-ENDPOINT)." },
    ],
  },
  {
    code: "PB-POWERSHELL",
    name: "Malicious PowerShell Response",
    description: "Response strategy for malicious/obfuscated PowerShell execution, download cradles and PowerShell-based persistence.",
    incidentType: "POWERSHELL",
    mitreTechniques: ["T1059.001", "T1547.001"],
    allowedActions: ["ACT-ISOLATE-ENDPOINT", "ACT-BLOCK-DOMAIN", "ACT-BLOCK-URL", "ACT-BLOCK-SOURCE-IP", "ACT-DISABLE-ACCOUNT"],
    steps: [
      { stepOrder: 1, title: "Contain the executing endpoint", description: "Isolate the endpoint where the PowerShell activity ran (ACT-ISOLATE-ENDPOINT)." },
      { stepOrder: 2, title: "Cut the stager / C2 infrastructure", description: "Block the stager/C2 URL, domain or IP recorded in the evidence (ACT-BLOCK-URL / ACT-BLOCK-DOMAIN / ACT-BLOCK-SOURCE-IP)." },
      { stepOrder: 3, title: "Revoke the executing identity if abused", description: "Disable the user account only if evidence shows it was abused (ACT-DISABLE-ACCOUNT)." },
    ],
  },
];

async function upsertPlaybook(
  prisma: PrismaClient,
  tenantId: string,
  data: { code: string; name: string; description: string; triggerConditions: object },
  steps: { stepOrder: number; title: string; description: string }[],
): Promise<void> {
  // Steps are upserted by (playbookId, stepOrder) — re-seeding never duplicates and never deletes rows.
  const playbook = await prisma.playbook.upsert({
    where: { code: data.code },
    update: { name: data.name, description: data.description, version: "1.0", status: "ACTIVE", triggerConditions: data.triggerConditions },
    create: { tenantId, code: data.code, name: data.name, description: data.description, version: "1.0", status: "ACTIVE", triggerConditions: data.triggerConditions },
  });
  for (const step of steps) {
    await prisma.playbookStep.upsert({
      where: { playbookId_stepOrder: { playbookId: playbook.id, stepOrder: step.stepOrder } },
      update: { title: step.title, description: step.description },
      create: { playbookId: playbook.id, ...step },
    });
  }
}

export async function seedPlaybooks(prisma: PrismaClient, tenantId: string): Promise<void> {
  await upsertPlaybook(
    prisma,
    tenantId,
    {
      code: PLAYBOOK_CODE,
      name: "Short-Term Containment",
      description: "Standard end-to-end process from triage through verification for an incident requiring short-term containment.",
      triggerConditions: {},
    },
    STEPS,
  );
  for (const pb of INCIDENT_PLAYBOOKS) {
    await upsertPlaybook(
      prisma,
      tenantId,
      {
        code: pb.code,
        name: pb.name,
        description: pb.description,
        triggerConditions: { scope: "INCIDENT", incidentType: pb.incidentType, mitreTechniques: pb.mitreTechniques, allowedActions: pb.allowedActions },
      },
      pb.steps,
    );
  }
}
