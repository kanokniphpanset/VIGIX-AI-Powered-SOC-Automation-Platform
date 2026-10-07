import { PrismaClient } from "@prisma/client";

/**
 * mitre.seed.ts — MITRE ATT&CK reference techniques (mitre_techniques). Idempotent (upsert by techniqueId).
 * Every technique an incident-level playbook triggers on (playbook.seed.ts mitreTechniques) must be listed here —
 * test/KnowledgeCatalog.test.ts enforces it. Names / tactics follow ATT&CK Enterprise.
 */
export interface SeedMitreTechnique {
  techniqueId: string;
  name: string;
  tactic: string;
}

export const MITRE_TECHNIQUES: SeedMitreTechnique[] = [
  { techniqueId: "T1566", name: "Phishing", tactic: "Initial Access" },
  { techniqueId: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { techniqueId: "T1078", name: "Valid Accounts", tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access" },
  { techniqueId: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  // Techniques exercised by the 10-case mock attack suite (resources/mock-attacks/)
  { techniqueId: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { techniqueId: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
  { techniqueId: "T1204.002", name: "Malicious File", tactic: "Execution" },
  { techniqueId: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  { techniqueId: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { techniqueId: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  { techniqueId: "T1098", name: "Account Manipulation", tactic: "Persistence, Privilege Escalation" },
  { techniqueId: "T1059.001", name: "PowerShell", tactic: "Execution" },
  { techniqueId: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence, Privilege Escalation" },
  // Knowledge Expansion for Evaluation — techniques of the added attack types (PB-PHISHING, PB-C2, PB-DATA-EXFIL,
  // PB-PRIV-ESC, PB-SUSPICIOUS-PROCESS).
  { techniqueId: "T1566.001", name: "Spearphishing Attachment", tactic: "Initial Access" },
  { techniqueId: "T1566.002", name: "Spearphishing Link", tactic: "Initial Access" },
  { techniqueId: "T1071", name: "Application Layer Protocol", tactic: "Command and Control" },
  // Sub-technique the MITRE agent emits for C2 (mitre_agent/technique_mapper.py COMMAND_AND_CONTROL -> T1071.001,
  // and any Wazuh rule whose rule.mitre.id is the sub-technique). It matches PB-C2 (which lists the parent T1071)
  // through PlaybookSelector's sub-technique prefix rule; without it in the catalog the mapping is dropped as
  // "not_in_catalog" and no C2 playbook is ever selected.
  { techniqueId: "T1071.001", name: "Web Protocols", tactic: "Command and Control" },
  { techniqueId: "T1573", name: "Encrypted Channel", tactic: "Command and Control" },
  { techniqueId: "T1571", name: "Non-Standard Port", tactic: "Command and Control" },
  { techniqueId: "T1041", name: "Exfiltration Over C2 Channel", tactic: "Exfiltration" },
  { techniqueId: "T1048", name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  { techniqueId: "T1567", name: "Exfiltration Over Web Service", tactic: "Exfiltration" },
  { techniqueId: "T1548", name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation, Defense Evasion" },
  { techniqueId: "T1059.003", name: "Windows Command Shell", tactic: "Execution" },
  { techniqueId: "T1059.004", name: "Unix Shell", tactic: "Execution" },
  { techniqueId: "T1218", name: "System Binary Proxy Execution", tactic: "Defense Evasion" },
];

export async function seedMitreTechniques(prisma: PrismaClient): Promise<void> {
  for (const t of MITRE_TECHNIQUES) {
    await prisma.mitreTechnique.upsert({
      where: { techniqueId: t.techniqueId },
      update: { name: t.name, tactic: t.tactic },
      create: t,
    });
  }
}
