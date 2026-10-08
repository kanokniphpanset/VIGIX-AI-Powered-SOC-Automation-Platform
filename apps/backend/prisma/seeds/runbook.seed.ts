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
  /** Knowledge Expansion runbooks: the Action(s) this runbook operates (the Action row links back via runbook_id). */
  relatedActions?: string[];
  /** Evidence IR needs before executing — stored as "Required evidence: ..." preconditions. */
  requiredEvidence?: string[];
  /** When the Action did not work — stored as a "Failure condition: ..." decision point (IR re-assesses; never an automatic retry). */
  failureCondition?: string;
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
      "Block the malicious sender domain and any embedded malicious URLs/domains (ACT-BLOCK-DOMAIN / ACT-BLOCK-URL).",
      "Search mail logs for all recipients of the same campaign.",
      "Purge the email from all recipient mailboxes where it has not been opened/actioned (ACT-QUARANTINE-EMAIL).",
      "For recipients who clicked a link or submitted credentials, reset their credentials and revoke their active sessions (ACT-RESET-CREDENTIAL, ACT-REVOKE-SESSION).",
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
      "Block the malicious destination IP and/or domain (ACT-BLOCK-DESTINATION-IP, ACT-BLOCK-DOMAIN).",
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

  // ---------------------------------------------------------------------------------------------
  // Knowledge Expansion for Evaluation (Step 5): action-level runbooks for the new Actions. Same rules as above —
  // tool-agnostic, derived from each Action's knowledge (domain/knowledge/actionKnowledge.ts), no vendor commands.
  // RB-BLOCK-HASH and RB-QUARANTINE-EMAIL are not in the spec list but are required: RecommendationValidator only
  // expands an Action that has an ACTIVE action-level runbook, so without them ACT-BLOCK-HASH / ACT-QUARANTINE-EMAIL
  // could never be recommended. RB-C2-CONTAINMENT is the action-level runbook of ACT-BLOCK-DESTINATION-IP.
  // ---------------------------------------------------------------------------------------------
  {
    code: "RB-QUARANTINE-FILE",
    name: "Quarantine File",
    description: "Action-level procedure for ACT-QUARANTINE-FILE: quarantine a malicious file on the affected endpoint.",
    trigger: "A file recorded in the incident evidence (path and hash) is confirmed malicious on the affected endpoint.",
    objective: "Prevent execution or further use of the identified malicious file.",
    preconditions: ["The affected endpoint is identified in the incident evidence.", "The file path and file hash are recorded in the incident evidence / IOC record."],
    procedure: [
      "Confirm the file path and file hash against the incident evidence and IOC record for the affected endpoint.",
      "Confirm no process started from the file is still running (terminate it first with ACT-KILL-PROCESS).",
      "Quarantine the file at the recorded path through the endpoint protection control on the affected endpoint.",
      "Confirm the file is no longer present at the recorded path and is held in quarantine.",
      "Record the control, the quarantine identifier and the time applied in the execution result.",
    ],
    decisionPoints: ["If the file is a legitimate system or business file, do not quarantine it; escalate to IR_TEAM for a remediation decision."],
    expectedResult: "The file is quarantined and can no longer be executed from the endpoint.",
    escalation: "Escalate to IR_TEAM if the same hash appears on other endpoints or the file reappears.",
    verificationCriteria: ["Re-hunt of the file hash returns no new detection on the endpoint.", "No process starts from the quarantined file path."],
    relatedActions: ["ACT-QUARANTINE-FILE"],
    requiredEvidence: ["Affected endpoint", "File path", "File hash", "Supporting malicious evidence (detection or threat-intelligence verdict)"],
    failureCondition: "The file cannot be quarantined, reappears at the recorded path, or the same hash is detected again on the endpoint.",
  },
  {
    code: "RB-KILL-MALICIOUS-PROCESS",
    name: "Terminate Malicious Process",
    description: "Action-level procedure for ACT-KILL-PROCESS: terminate a malicious process on the affected endpoint.",
    trigger: "A process recorded in the incident evidence (name and command line) is confirmed malicious on the affected endpoint.",
    objective: "Terminate the identified malicious process on the affected endpoint.",
    preconditions: ["The affected endpoint is identified in the incident evidence.", "The process and its command line are recorded in the incident evidence / IOC record."],
    procedure: [
      "Confirm the process name and command line against the incident evidence for the affected endpoint.",
      "Identify the current PID of the matching process on the endpoint and confirm its command line matches the recorded one.",
      "Terminate the process and its child processes through the endpoint protection control.",
      "Confirm no process with the recorded command line is running on the endpoint.",
      "Record the PID, the control used and the time applied in the execution result.",
    ],
    decisionPoints: ["If the process is a critical system process, do not terminate it; escalate to IR_TEAM (endpoint isolation may be the safer containment)."],
    expectedResult: "The malicious process is no longer running on the endpoint.",
    escalation: "Escalate to IR_TEAM if the process restarts (persistence) or appears on other endpoints.",
    verificationCriteria: ["The process no longer exists on the endpoint.", "Re-hunt of the process and command line shows no recurrence."],
    relatedActions: ["ACT-KILL-PROCESS"],
    requiredEvidence: ["Affected endpoint", "Process name", "PID (confirmed on the endpoint at execution time)", "Command line", "Supporting malicious evidence"],
    failureCondition: "The process restarts, a new process with the same command line appears, or the process cannot be terminated.",
  },
  {
    code: "RB-RESET-CREDENTIAL",
    name: "Reset User Credentials",
    description: "Action-level procedure for ACT-RESET-CREDENTIAL: invalidate the compromised credentials of an account.",
    trigger: "Evidence shows the credentials of the recorded account are compromised (suspicious successful authentication, credentials submitted to a phishing page).",
    objective: "Invalidate the compromised credentials and require new credentials for the account.",
    preconditions: ["The account identifier is present in the incident evidence.", "Suspicious authentication evidence for the account is recorded."],
    procedure: [
      "Confirm the account identifier and the authentication evidence recorded for it.",
      "Reset the account password in the identity provider / directory that authenticates it.",
      "Require new credentials at the next sign-in and remove MFA factors the attacker may have registered.",
      "Confirm authentication with the previous credentials now fails.",
      "Record the reset time and method in the execution result.",
    ],
    decisionPoints: ["If the account is a service or shared account, coordinate the credential change with its owner so dependent services are updated."],
    expectedResult: "The compromised credentials no longer authenticate.",
    escalation: "Escalate to IR_TEAM if suspicious activity continues after the reset (disabling the account, ACT-DISABLE-ACCOUNT, may be needed).",
    verificationCriteria: ["Authentication events show no successful use of the previous credentials.", "No new suspicious logon for the account after the reset."],
    relatedActions: ["ACT-RESET-CREDENTIAL"],
    requiredEvidence: ["Account identifier", "Suspicious authentication evidence", "Evidence of credential compromise"],
    failureCondition: "The previous credentials still authenticate, or suspicious logons for the account continue after the reset.",
  },
  {
    code: "RB-REVOKE-SESSION",
    name: "Revoke Active Sessions",
    description: "Action-level procedure for ACT-REVOKE-SESSION: terminate the active sessions of an affected account.",
    trigger: "An active or suspicious session of the account recorded in the evidence is linked to the malicious activity.",
    objective: "Terminate the active sessions associated with the affected account.",
    preconditions: ["The account identifier is present in the incident evidence.", "An active or suspicious session of the account is recorded."],
    procedure: [
      "Confirm the account identifier and the session evidence recorded for it.",
      "Revoke the active sessions and refresh tokens of the account in the identity provider.",
      "Terminate the interactive and remote sessions of the account on the hosts named in the evidence.",
      "Confirm no active session of the account remains.",
      "Record the revoked sessions and the time applied in the execution result.",
    ],
    decisionPoints: ["If the credentials are also compromised, pair this action with a credential reset (ACT-RESET-CREDENTIAL) so the sessions cannot be re-established."],
    expectedResult: "The account has no active session.",
    escalation: "Escalate to IR_TEAM if a session is re-established or other accounts show related activity.",
    verificationCriteria: ["No active session of the account remains.", "Authentication events show no new session from the suspicious source."],
    relatedActions: ["ACT-REVOKE-SESSION"],
    requiredEvidence: ["Account identifier", "Active / suspicious session evidence"],
    failureCondition: "A session of the account is still active or is re-established with the same credentials.",
  },
  {
    code: "RB-BLOCK-HASH",
    name: "Block File Hash",
    description: "Action-level procedure for ACT-BLOCK-HASH: prevent execution of files with a malicious hash.",
    trigger: "A file hash recorded in the incident evidence is confirmed malicious (related event and supporting evidence).",
    objective: "Prevent execution of files with the identified malicious hash.",
    preconditions: ["The file hash is present in the incident evidence / IOC record."],
    procedure: [
      "Confirm the file hash against the incident evidence and IOC record, including the event that links it to the affected endpoint.",
      "Add the hash to the block list of the endpoint protection control.",
      "Confirm the block entry is active on that control.",
      "Confirm an attempt to run a file with the hash is blocked.",
      "Record the control, the block entry and the time applied in the execution result.",
    ],
    decisionPoints: ["If the hash belongs to a legitimate signed binary, do not block it; escalate to IR_TEAM."],
    expectedResult: "Files with the blocked hash can no longer execute.",
    escalation: "Escalate to IR_TEAM if the hash is found on other endpoints.",
    verificationCriteria: ["Re-hunt of the hash returns no new execution.", "No recurrence of the hash on any endpoint."],
    relatedActions: ["ACT-BLOCK-HASH"],
    requiredEvidence: ["File hash", "Related event", "Supporting malicious evidence"],
    failureCondition: "Files with the hash still execute, or the hash is detected again after the block.",
  },
  {
    code: "RB-C2-CONTAINMENT",
    name: "C2 Containment — Block Destination IP",
    description: "Action-level procedure for ACT-BLOCK-DESTINATION-IP: deny outbound traffic to a malicious destination (C2 or exfiltration endpoint).",
    trigger: "An outbound destination IP recorded in the incident evidence is linked to C2 or exfiltration activity (related network event and supporting IOC/CTI evidence).",
    objective: "Prevent communication from the environment to the identified destination IP.",
    preconditions: ["The destination IP is present in the incident evidence / IOC record.", "The affected endpoint that contacted it is identified in the evidence."],
    procedure: [
      "Confirm the destination IP against the incident evidence and IOC record, including the network event that links it to the affected endpoint.",
      "Confirm the supporting IOC / threat-intelligence evidence that the destination is malicious.",
      "Apply an outbound deny rule for the destination IP on the perimeter firewall / egress control.",
      "Confirm the deny rule is active on that control.",
      "Confirm new outbound connections from the affected endpoint to the destination IP are rejected.",
      "Record the rule identifier, scope and time applied in the execution result.",
    ],
    decisionPoints: ["If the destination is a shared hosting / CDN address, narrow the rule or block the domain instead (ACT-BLOCK-DOMAIN)."],
    expectedResult: "Outbound traffic to the destination IP is blocked.",
    escalation: "Escalate to IR_TEAM if other endpoints contact the destination or the beaconing moves to a new destination.",
    verificationCriteria: ["Re-hunt of the destination IP shows no new outbound connection.", "Network events show no recurrence of the beaconing / transfer pattern."],
    relatedActions: ["ACT-BLOCK-DESTINATION-IP"],
    requiredEvidence: ["Destination IP", "Related network event", "Supporting IOC / CTI evidence"],
    failureCondition: "Outbound connections to the destination continue, or the endpoint switches to a new destination (fallback C2).",
  },
  {
    code: "RB-QUARANTINE-EMAIL",
    name: "Quarantine Email",
    description: "Action-level procedure for ACT-QUARANTINE-EMAIL: remove a malicious message from user mailboxes.",
    trigger: "A message recorded in the incident evidence (sender / recipients) is confirmed malicious.",
    objective: "Remove the malicious message from user mailboxes so users cannot interact with it.",
    preconditions: ["The message sender or identifier is present in the incident evidence / IOC record."],
    procedure: [
      "Confirm the message (sender, subject, recipients) against the incident evidence and IOC record.",
      "Search the mail system for every delivered copy of the same message.",
      "Move every copy of the message into quarantine through the mail security control.",
      "Confirm the message is no longer present in recipient mailboxes.",
      "Record the control, the number of copies quarantined and the time applied in the execution result.",
    ],
    decisionPoints: ["If recipients already clicked the link or opened the attachment, escalate to IR_TEAM for account / endpoint containment."],
    expectedResult: "No recipient mailbox holds the malicious message.",
    escalation: "Escalate to IR_TEAM if the same campaign is delivered again.",
    verificationCriteria: ["No copy of the message remains in recipient mailboxes.", "The mail gateway shows no new delivery of the same campaign."],
    relatedActions: ["ACT-QUARANTINE-EMAIL"],
    requiredEvidence: ["Message identifier / sender", "Recipient", "Malicious indicator"],
    failureCondition: "Copies of the message remain in mailboxes or the same campaign is delivered again.",
  },
  // Attack-specific containment procedures: action-level runbooks for the Actions added for them (action.seed.ts).
  {
    code: "RB-RATE-LIMIT-SOURCE",
    name: "Rate-Limit Source",
    description: "Action-level procedure for ACT-RATE-LIMIT-SOURCE: throttle repeated authentication attempts or malicious requests from one source.",
    trigger: "A source IP recorded in incident evidence keeps sending repeated authentication attempts or malicious requests.",
    objective: "Throttle or reject repeated attempts from the identified source while the incident is investigated.",
    preconditions: ["The source IP is present in the incident evidence / IOC record.", "The affected service (authentication service or web application) is identified in the evidence."],
    procedure: [
      "Confirm the source IP and the repeated attempts recorded for it against the incident evidence.",
      "Identify the control in front of the affected service that can limit request or login rates (authentication service, WAF or reverse proxy).",
      "Apply a rate limit or temporary lockout threshold for the source IP on that control, scoped to the affected service.",
      "Confirm the limit is active on the control.",
      "Confirm repeated attempts from the source IP are throttled or rejected.",
      "Record the control, threshold, scope and time applied in the execution result.",
    ],
    decisionPoints: ["If the source IP is shared by legitimate users (NAT / proxy), prefer a per-account lockout threshold over a source-wide limit."],
    expectedResult: "Repeated attempts from the source are throttled or rejected.",
    escalation: "Escalate to IR_TEAM if the attempts continue at the same rate or move to a new source.",
    verificationCriteria: ["Re-hunt of the source IP shows the attempts stopped or fell below the limit."],
    relatedActions: ["ACT-RATE-LIMIT-SOURCE"],
    requiredEvidence: ["Source IP", "Repeated attempt events", "Affected service"],
    failureCondition: "The attempt rate from the source is unchanged after the limit is active.",
  },
  {
    code: "RB-BLOCK-SENDER",
    name: "Block Sender",
    description: "Action-level procedure for ACT-BLOCK-SENDER: stop further delivery from a confirmed malicious sender.",
    trigger: "A sender address recorded in the incident evidence is confirmed malicious.",
    objective: "Prevent further delivery of messages from the identified sender.",
    preconditions: ["The sender address is present in the incident evidence / IOC record."],
    procedure: [
      "Confirm the sender address against the incident evidence and IOC record.",
      "Confirm the sender is not a legitimate partner mailbox that was compromised (coordinate with its owner instead).",
      "Add the sender address to the block list of the mail security control.",
      "Confirm the block entry is active.",
      "Record the control, the entry and the time applied in the execution result.",
    ],
    decisionPoints: ["If the sender is a compromised partner mailbox, block only the campaign indicators and notify the partner."],
    expectedResult: "New messages from the sender are not delivered.",
    escalation: "Escalate to IR_TEAM if the same campaign arrives from a different sender.",
    verificationCriteria: ["The mail gateway shows no new delivery from the blocked sender."],
    relatedActions: ["ACT-BLOCK-SENDER"],
    requiredEvidence: ["Sender address", "Related message event"],
    failureCondition: "Messages from the sender are still delivered after the block is active.",
  },
  {
    code: "RB-REMOVE-PRIVILEGE",
    name: "Remove Unauthorized Privilege",
    description: "Action-level procedure for ACT-REMOVE-PRIVILEGE: return an account's privileges to the approved baseline.",
    trigger: "A privilege / group membership recorded in the incident evidence was granted without authorization.",
    objective: "Remove the unauthorized privilege so the account cannot perform privileged actions.",
    preconditions: ["The account identifier and the privilege change event are present in the incident evidence.", "Change management records no approved change for the privilege."],
    procedure: [
      "Confirm the account, the privilege granted and the change event against the incident evidence.",
      "Confirm with change management that the privilege change was not approved.",
      "Remove the unauthorized privilege / group membership from the account in the directory or system that granted it.",
      "Confirm the account's privileges match the approved baseline.",
      "Record the privilege removed and the time applied in the execution result.",
    ],
    decisionPoints: ["If the change turns out to be authorized, do not remove it; record the change reference and close the step."],
    expectedResult: "The account holds only its approved privileges.",
    escalation: "Escalate to IR_TEAM if the privilege is granted again or other accounts received privileges.",
    verificationCriteria: ["Group membership of the account matches the approved baseline.", "No privileged activity by the account after the removal."],
    relatedActions: ["ACT-REMOVE-PRIVILEGE"],
    requiredEvidence: ["Account identifier", "Privilege change event", "Change management confirmation"],
    failureCondition: "The privilege is still present or is granted again after the removal.",
  },
];

/** Structured knowledge fields folded into the existing Runbook columns (no schema change). */
export function persistedPreconditions(rb: SeedRunbook): string[] {
  return [...rb.preconditions, ...(rb.requiredEvidence ?? []).map((e) => `Required evidence: ${e}`)];
}
export function persistedDecisionPoints(rb: SeedRunbook): string[] {
  return [...rb.decisionPoints, ...(rb.failureCondition ? [`Failure condition: ${rb.failureCondition}`] : [])];
}

export async function seedRunbooks(prisma: PrismaClient, tenantId: string): Promise<void> {
  for (const rb of RUNBOOKS) {
    await prisma.runbook.upsert({
      where: { code: rb.code },
      update: {
        name: rb.name,
        description: rb.description,
        trigger: rb.trigger,
        objective: rb.objective,
        preconditions: persistedPreconditions(rb) as Prisma.InputJsonValue,
        procedure: rb.procedure as Prisma.InputJsonValue,
        decisionPoints: persistedDecisionPoints(rb) as Prisma.InputJsonValue,
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
        preconditions: persistedPreconditions(rb) as Prisma.InputJsonValue,
        procedure: rb.procedure as Prisma.InputJsonValue,
        decisionPoints: persistedDecisionPoints(rb) as Prisma.InputJsonValue,
        expectedResult: rb.expectedResult,
        escalation: rb.escalation,
        verificationCriteria: rb.verificationCriteria as Prisma.InputJsonValue,
      },
    });
  }
}
