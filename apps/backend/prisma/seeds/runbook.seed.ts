import { PrismaClient, Prisma } from "@prisma/client";

/**
 * runbook.seed.ts — the Runbook Catalog: attack-specific technical
 * procedures (RB-*). Runbooks are what may legitimately encode
 * attack-specific detail — Policy never does (see policy.seed.ts's own
 * note). `procedure` is the authoritative, human-authored step list; AI
 * may reference a Runbook's id/steps but never invent or rewrite them.
 *
 * NOTE (honesty flag for the final report): exact step wording below is
 * this implementation's own representative content for the required
 * RB-BRUTEFORCE-001 / RB-MALWARE-001 / RB-RANSOMWARE-001 / RB-PHISHING-001
 * / RB-NETWORK-001 codes — the original spec prose was not available
 * verbatim when this seed was written. The Malware runbook uses exactly 9
 * procedure steps as specified.
 */

export interface SeedRunbook {
  code: string;
  name: string;
  description: string;
  trigger: string;
  objective: string;
  preconditions: string[];
  procedure: string[];
  decisionPoints: string[];
  expectedResult: string;
  escalation: string;
  verificationCriteria: string[];
}

export const RUNBOOKS: SeedRunbook[] = [
  {
    code: "RB-BRUTEFORCE-001",
    name: "Brute Force Authentication Response",
    description: "Technical procedure for repeated failed authentication attempts against a single account or host.",
    trigger: "Multiple failed authentication events against the same account/source within a short window.",
    objective: "Stop the brute-force attempt and confirm whether any attempt succeeded.",
    preconditions: ["Source IP and target account identified from SIEM evidence."],
    procedure: [
      "Confirm the failed-login pattern in Wazuh/SIEM (count, source IP, target account, time window).",
      "Check for any successful authentication from the same source IP or immediately following the failed attempts.",
      "Block the source IP at the firewall/WAF (ACT-BLOCK-SOURCE-IP).",
      "Force a password reset on the targeted account (manual — no automated action defined yet).",
      "Review the account's recent activity for signs of prior compromise.",
      "Document findings and evidence references in the incident record.",
    ],
    decisionPoints: ["If a successful login is found among the failed attempts, escalate to Account Compromise handling."],
    expectedResult: "Source IP blocked, targeted account credential rotated, no successful unauthorized authentication confirmed.",
    escalation: "Flag it in the IR decision note if the targeted account has elevated/administrative privileges.",
    verificationCriteria: ["No further failed/successful authentication attempts from the blocked source IP in Wazuh re-hunt."],
  },
  {
    code: "RB-MALWARE-001",
    name: "Malware Infection Response",
    description: "Technical procedure for a confirmed or suspected malware infection on an endpoint.",
    trigger: "EDR/AV detection or SIEM correlation indicating malicious executable activity on a host.",
    objective: "Contain the infection, confirm the malware family, eradicate it, and verify the host is clean.",
    preconditions: ["Affected host identified.", "Detection evidence (EDR/AV alert or IOC match) available."],
    procedure: [
      "Identify the affected host and confirm the detection evidence (EDR/AV alert, hash, IOC match).",
      "Isolate the affected host from the network (ACT-ISOLATE-ENDPOINT).",
      "Collect a forensic disk image and memory dump of the host for analysis (ACT-007).",
      "Identify the malware family using AV/EDR signatures, sandbox detonation, or threat intelligence lookup.",
      "Eradicate the malware: remove the malicious binary/persistence mechanism, or reimage the host if eradication cannot be confirmed.",
      "Patch or remediate the vulnerability/entry vector that allowed the infection.",
      "Restore affected files/configuration from a known-clean backup where applicable.",
      "Monitor the host closely after restoration for recurrence of the same indicators.",
      "Re-hunt the host in Wazuh/EDR to confirm no remaining malicious indicators (ACT-008).",
    ],
    decisionPoints: ["If eradication cannot be verified with confidence, reimage the host instead of continuing in-place remediation."],
    expectedResult: "Host is free of the identified malware, entry vector remediated, re-hunt evidence confirms containment.",
    escalation: "IR must record its approval note before reimaging production/critical-tier assets.",
    verificationCriteria: [
      "Wazuh/EDR re-hunt returns no detection for the identified malware family/IOC on the host.",
      "No new alerts correlated to the same IOC set within the monitoring window.",
    ],
  },
  {
    code: "RB-RANSOMWARE-001",
    name: "Ransomware Response",
    description: "Technical procedure for a confirmed or suspected ransomware event.",
    trigger: "Mass file encryption activity, ransom note detection, or EDR ransomware-behavior alert.",
    objective: "Stop encryption spread, contain affected systems, and begin recovery from clean backups.",
    preconditions: ["At least one affected host identified.", "Scope of encryption activity not yet fully known."],
    procedure: [
      "Isolate all hosts showing encryption activity or ransomware-behavior alerts from the network (ACT-ISOLATE-ENDPOINT).",
      "Identify the ransomware family and encryption scope via EDR telemetry and file-share audit logs.",
      "Disable any compromised accounts used to propagate the ransomware (ACT-DISABLE-ACCOUNT).",
      "Collect forensic evidence (disk image, memory dump) from a representative affected host before remediation (ACT-007).",
      "Confirm the integrity and recency of available clean backups before any restoration.",
      "Eradicate the ransomware from affected hosts (reimage recommended over in-place removal).",
      "Restore data from clean, verified backups.",
      "Re-hunt all previously affected hosts in Wazuh/EDR to confirm no remaining ransomware activity (ACT-008).",
    ],
    decisionPoints: [
      "If backup integrity cannot be confirmed clean, do not restore until a separate forensic verification of the backup completes.",
    ],
    expectedResult: "Spread halted, affected hosts reimaged/cleaned, data restored from verified clean backups.",
    escalation: "IR approval (with a decision note) required before any restoration or reimaging of production systems.",
    verificationCriteria: [
      "Wazuh/EDR re-hunt across all previously affected hosts returns no ransomware indicators.",
      "No new file-encryption activity observed in the monitoring window after restoration.",
    ],
  },
  {
    code: "RB-PHISHING-001",
    name: "Phishing Email Response",
    description: "Technical procedure for a reported or detected phishing email.",
    trigger: "User-reported phishing email or SIEM/email-gateway detection of a phishing campaign.",
    objective: "Contain the campaign, identify affected recipients, and confirm no credential compromise resulted.",
    preconditions: ["Phishing email sample or message-id available."],
    procedure: [
      "Retrieve the phishing email sample and extract indicators (sender, links, attachments, headers).",
      "Block the malicious sender domain and any embedded malicious URLs/domains (ACT-BLOCK-DOMAIN).",
      "Search mail logs for all recipients of the same campaign.",
      "Purge the email from all recipient mailboxes where it has not been opened/actioned.",
      "For recipients who clicked a link or opened an attachment, force a password reset (manual — no automated action defined yet).",
      "Review authentication logs for the affected recipients for signs of successful account compromise.",
    ],
    decisionPoints: ["If any recipient's credentials were submitted to a phishing page, escalate to Account Compromise / Brute Force handling for that account."],
    expectedResult: "Campaign indicators blocked, email purged from mailboxes, no confirmed credential compromise remaining.",
    escalation: "Flag it in the IR decision note if executive or privileged accounts were targeted.",
    verificationCriteria: ["No further delivery of the same campaign indicators observed in mail gateway logs."],
  },
  {
    code: "RB-NETWORK-001",
    name: "Anomalous Network Activity Response",
    description: "Technical procedure for suspicious network traffic (e.g. C2 beaconing, data exfiltration patterns, port scanning).",
    trigger: "Network IDS/SIEM detection of anomalous outbound traffic, beaconing, or scanning behavior.",
    objective: "Confirm the nature of the traffic, contain the source, and verify no further anomalous activity.",
    preconditions: ["Source host and destination IP/domain identified from network telemetry."],
    procedure: [
      "Confirm the anomalous traffic pattern in network telemetry (destination, volume, frequency, protocol).",
      "Cross-check the destination IP/domain against threat intelligence for a malicious verdict.",
      "Block the malicious destination IP and/or domain (ACT-BLOCK-SOURCE-IP, ACT-BLOCK-DOMAIN).",
      "Isolate the source host if the traffic pattern indicates active C2 or exfiltration (ACT-ISOLATE-ENDPOINT).",
      "Collect a memory dump from the source host to identify the responsible process (ACT-007).",
      "Re-hunt the source host and network segment in Wazuh to confirm the anomalous traffic has stopped (ACT-008).",
    ],
    decisionPoints: ["If the traffic pattern is consistent with data exfiltration, treat as high priority regardless of the originating alert severity."],
    expectedResult: "Malicious destination blocked, source host contained, anomalous traffic confirmed stopped.",
    escalation: "Flag it in the IR decision note if exfiltration of regulated or customer data is suspected.",
    verificationCriteria: ["Wazuh re-hunt and network telemetry show no recurrence of the anomalous traffic pattern."],
  },

  // ---------------------------------------------------------------------------------------------
  // ACTION-LEVEL runbooks (Task 10.3): the operational procedure for ONE Action Catalog entry,
  // linked via actions.runbook_id. The RB-*-001 entries above are incident-level knowledge and stay
  // as they are. Content is derived only from each Action's own catalog text (target, required
  // evidence, expected effect, verification, risk — action.seed.ts), the attack-level steps above
  // that invoke the action, and apps/knowledge/playbooks/PB-STC-001 containment `appliesWhen`.
  // Tool-agnostic on purpose: no vendor commands are invented.
  // ---------------------------------------------------------------------------------------------
  {
    code: "RB-BLOCK-SOURCE-IP",
    name: "Block Source IP",
    description: "Action-level procedure for ACT-BLOCK-SOURCE-IP: deny traffic from a confirmed malicious source IP at a network security control.",
    trigger: "A source IP recorded in incident evidence is confirmed malicious or has no legitimate business reason to reach the affected host/service.",
    objective: "Prevent further communication from the identified source IP to the affected host/service.",
    preconditions: ["The source IP is present in the incident evidence / IOC record.", "The affected host/service is identified in the evidence."],
    procedure: [
      "Confirm the source IP against the incident evidence and IOC record, and that it has no legitimate business reason to reach the affected host/service.",
      "Identify the network security control (perimeter firewall or WAF) that enforces traffic from this source toward the affected host/service.",
      "Apply a deny rule for the source IP on that control, scoped to the affected host/service named in the evidence.",
      "Confirm the deny rule is active on the control.",
      "Confirm new connection attempts from the source IP to the affected host/service are rejected.",
      "Record the rule identifier, scope and time applied in the execution result.",
    ],
    decisionPoints: ["If the source IP could be shared by legitimate users (e.g. a proxy or NAT address), narrow the rule scope rather than blocking the address everywhere."],
    expectedResult: "Traffic from the source IP no longer reaches the affected host/service.",
    escalation: "Escalate to IR_TEAM if activity from the source continues after the rule is active or appears on other hosts.",
    verificationCriteria: ["Connection attempts from the blocked source IP to the affected host/service are rejected."],
  },
  {
    code: "RB-BLOCK-DOMAIN",
    name: "Block Domain",
    description: "Action-level procedure for ACT-BLOCK-DOMAIN: prevent communication with a malicious or suspicious domain.",
    trigger: "A domain recorded in incident evidence is linked to the malicious activity (related event and supporting IOC/TI evidence).",
    objective: "Prevent hosts from resolving or communicating with the identified domain.",
    preconditions: ["The domain is present in the incident evidence / IOC record."],
    procedure: [
      "Confirm the domain against the incident evidence and IOC record, including the event that links it to the affected host.",
      "Add the domain to the block list of the DNS or web-proxy control used by the affected host.",
      "Confirm the block entry is active on that control.",
      "Confirm name resolution or connection attempts to the domain from the affected host are blocked.",
      "Record the control, block entry and time applied in the execution result.",
    ],
    decisionPoints: ["If the domain is a shared or legitimate service domain, block the specific malicious URL instead (ACT-BLOCK-URL)."],
    expectedResult: "Hosts can no longer resolve or reach the blocked domain.",
    escalation: "Escalate to IR_TEAM if other hosts are found contacting the domain.",
    verificationCriteria: ["Resolution/connection attempts to the blocked domain fail from the affected host."],
  },
  {
    code: "RB-BLOCK-URL",
    name: "Block URL",
    description: "Action-level procedure for ACT-BLOCK-URL: prevent access to a confirmed malicious URL.",
    trigger: "A URL recorded in incident evidence is confirmed malicious (related event and supporting evidence).",
    objective: "Prevent access to the identified malicious resource.",
    preconditions: ["The URL is present in the incident evidence / IOC record."],
    procedure: [
      "Confirm the URL against the incident evidence and IOC record, including the event that links it to the affected host.",
      "Add the URL to the block list of the web-proxy / web-filter control used by the affected hosts.",
      "Confirm the block entry is active on that control.",
      "Confirm requests to the URL from the affected host are blocked.",
      "Record the control, block entry and time applied in the execution result.",
    ],
    decisionPoints: ["If several URLs share the same malicious domain, consider blocking the domain instead (ACT-BLOCK-DOMAIN)."],
    expectedResult: "Requests to the malicious URL are blocked.",
    escalation: "Escalate to IR_TEAM if other hosts are found requesting the URL.",
    verificationCriteria: ["Requests to the blocked URL fail from the affected host."],
  },
  {
    code: "RB-ISOLATE-ENDPOINT",
    name: "Isolate Endpoint",
    description: "Action-level procedure for ACT-ISOLATE-ENDPOINT: restrict network connectivity of an affected endpoint.",
    trigger: "Evidence supports compromise of the affected endpoint (suspicious process, network activity or confirmed malware).",
    objective: "Reduce communication from the affected endpoint and limit potential spread.",
    preconditions: ["The affected endpoint is identified in the incident evidence.", "Evidence supports endpoint compromise."],
    procedure: [
      "Confirm the affected endpoint (hostname / IP) and the evidence supporting its compromise.",
      "Apply network isolation to the endpoint through the endpoint or network control, keeping analyst management access if the control supports it.",
      "Confirm the endpoint can no longer reach other hosts or external destinations.",
      "Confirm the suspicious process or network activity recorded in the evidence has stopped.",
      "Record the isolation method and time applied in the execution result.",
    ],
    decisionPoints: ["Isolation interrupts the endpoint's business function; coordinate with the asset owner for critical assets (Policy decides approval)."],
    expectedResult: "The endpoint has no outbound or lateral network activity except management access.",
    escalation: "Escalate to IR_TEAM if the same indicators appear on other endpoints.",
    verificationCriteria: ["The isolated endpoint shows no outbound or lateral network activity except management access."],
  },
  {
    code: "RB-DISABLE-ACCOUNT",
    name: "Disable User Account",
    description: "Action-level procedure for ACT-DISABLE-ACCOUNT: temporarily prevent authentication with a potentially compromised account.",
    trigger: "Compromise of the account recorded in the evidence is confirmed or strongly suspected (suspicious authentication or compromise evidence).",
    objective: "Prevent further authentication using the affected account.",
    preconditions: ["The account identifier is present in the incident evidence."],
    procedure: [
      "Confirm the account identifier and the suspicious authentication or compromise evidence recorded for it.",
      "Disable the account in the identity provider / directory that authenticates it.",
      "Terminate the account's active sessions where the identity system supports it.",
      "Confirm authentication attempts with the account now fail.",
      "Record the disable time and method in the execution result.",
    ],
    decisionPoints: ["If the account is a service or shared account, confirm the business impact with its owner before disabling (Policy decides approval)."],
    expectedResult: "The account can no longer authenticate.",
    escalation: "Escalate to IR_TEAM if other accounts show related suspicious activity.",
    verificationCriteria: ["Authentication attempts with the disabled account fail."],
  },
];

export async function seedRunbooks(prisma: PrismaClient, tenantId: string): Promise<void> {
  for (const rb of RUNBOOKS) {
    await prisma.runbook.upsert({
      where: { code: rb.code },
      update: {
        name: rb.name,
        description: rb.description,
        trigger: rb.trigger,
        objective: rb.objective,
        preconditions: rb.preconditions as Prisma.InputJsonValue,
        procedure: rb.procedure as Prisma.InputJsonValue,
        decisionPoints: rb.decisionPoints as Prisma.InputJsonValue,
        expectedResult: rb.expectedResult,
        escalation: rb.escalation,
        verificationCriteria: rb.verificationCriteria as Prisma.InputJsonValue,
      },
      create: {
        tenantId,
        code: rb.code,
        name: rb.name,
        description: rb.description,
        trigger: rb.trigger,
        objective: rb.objective,
        preconditions: rb.preconditions as Prisma.InputJsonValue,
        procedure: rb.procedure as Prisma.InputJsonValue,
        decisionPoints: rb.decisionPoints as Prisma.InputJsonValue,
        expectedResult: rb.expectedResult,
        escalation: rb.escalation,
        verificationCriteria: rb.verificationCriteria as Prisma.InputJsonValue,
      },
    });
  }
}
