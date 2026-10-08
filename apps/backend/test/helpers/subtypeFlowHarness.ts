import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fixtureCatalog } from "./hc1Provenance";
import { GenerateRecommendationUseCase, SubtypeIntegration } from "../../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { RecommendationContextBuilder } from "../../src/application/recommendation/services/RecommendationContextBuilder";
import { RecommendationValidator } from "../../src/infrastructure/recommendation-validation/RecommendationValidator";
import { FakeRecommendationAgent } from "../../src/infrastructure/ai/FakeRecommendationAgent";
import { IRecommendationContextRepository, RehuntContextRow } from "../../src/application/recommendation/ports/IRecommendationContextRepository";
import { IRecommendationAgentPort } from "../../src/application/recommendation/ports/IRecommendationAgentPort";
import { CreateRecommendationData, IRecommendationRepository } from "../../src/domain/recommendation/repositories/IRecommendationRepository";
import { IRecommendationAuditRepository, RecommendationAuditRecord } from "../../src/domain/recommendation/repositories/IRecommendationAuditRepository";
import { IActionRepository } from "../../src/domain/action/repositories/IActionRepository";
import { IRunbookRepository } from "../../src/domain/runbook/repositories/IRunbookRepository";
import { IPlaybookRepository } from "../../src/domain/playbook/repositories/IPlaybookRepository";
import { Runbook } from "../../src/domain/runbook/entities/Runbook.entity";
import { Playbook } from "../../src/domain/playbook/entities/Playbook.entity";
import { AuditLogger } from "../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { ACTIONS, ACTION_RUNBOOK_CODES } from "../../prisma/seeds/action.seed";
import { RUNBOOKS } from "../../prisma/seeds/runbook.seed";
import { INCIDENT_PLAYBOOKS } from "../../prisma/seeds/playbook.seed";
import { subtypeCatalog } from "../../prisma/seeds/subtype.seed";
import { SubtypeKnowledgeLoader } from "../../src/infrastructure/knowledge/SubtypeKnowledgeLoader";
import { SubtypeMode, SubtypeRecommendationService } from "../../src/application/subtype/SubtypeRecommendationService";
import { ISubtypeNarrator } from "../../src/application/subtype/SubtypeStepMapper";
import { SubtypeEvidenceRow } from "../../src/application/subtype/factBuilder";
import { TicketRecord } from "../../src/domain/subtype/actionState";

/**
 * Harness: the REAL GenerateRecommendationUseCase + RecommendationContextBuilder + RecommendationValidator (legacy path) + subtype
 * service over in-memory repositories (no database, no network, no LLM). Catalog rows = the legacy seeds + the rows
 * prisma/seeds/subtype.seed.ts would add. Used for the integration tests.
 */
export const TENANT = "tenant-1";
export const INCIDENT = "incident-1";
export const TITLE = "sshd: brute force trying to get access to the system. Authentication failed.";

export const ORG_SSH = `enforcement_points:\n  - {host: attack-endpoint, service: "SSH (22/TCP)", enforcement_point: "perimeter firewall FW-EDGE-1"}\n`;
export function orgLoader(yaml: string): SubtypeKnowledgeLoader {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "org-")), "org.yaml");
  fs.writeFileSync(f, yaml);
  return new SubtypeKnowledgeLoader(undefined, f);
}

export function harness(o: {
  rows: SubtypeEvidenceRow[]; mode?: SubtypeMode; loader?: SubtypeKnowledgeLoader; tickets?: TicketRecord[]; rehunt?: RehuntContextRow | null; investigationNumber?: number; nextNumber?: number;
  seedSubtypeCatalog?: boolean; criticality?: string; narrator?: ISubtypeNarrator; auditFails?: boolean; withSubtype?: boolean; legacyIocs?: unknown[]; previousSteps?: { recommendationNumber: number; investigationNumber: number; actionCode: string; target: string }[];
}) {
  const loader = o.loader ?? new SubtypeKnowledgeLoader();
  const kb = loader.load();
  const catalog = kb.status === "VALID" ? subtypeCatalog(kb) : { actions: [], runbooks: [] };
  const legacyActions = ACTIONS.map((a) => ({ ...a, id: `action-${a.code}`, enabled: true, runbookId: ACTION_RUNBOOK_CODES[a.code] ? `runbook-${ACTION_RUNBOOK_CODES[a.code]}` : null }));
  const subtypeActions = o.seedSubtypeCatalog === false ? [] : catalog.actions.map((a) => ({ ...a, id: `action-${a.code}`, enabled: true, runbookId: `runbook-${a.runbookCode}`, tenantId: TENANT }));
  const actions = [...legacyActions, ...subtypeActions];
  const runbooks = [
    ...RUNBOOKS.map((r) => Runbook.create({ ...r, id: `runbook-${r.code}`, tenantId: TENANT, version: "1.0", status: "ACTIVE", createdAt: new Date(), updatedAt: new Date() })),
    ...(o.seedSubtypeCatalog === false ? [] : catalog.runbooks.map((r) => Runbook.create({ ...r, id: `runbook-${r.code}`, tenantId: TENANT, status: "ACTIVE", createdAt: new Date(), updatedAt: new Date() }))),
  ];
  const playbooks = [
    Playbook.create({ id: "pb-stc", tenantId: TENANT, code: "STC-001", name: "Short-Term Containment", description: null, version: "1.0", status: "ACTIVE", steps: [], triggerConditions: {} }),
    ...INCIDENT_PLAYBOOKS.map((p) => Playbook.create({ id: `pb-${p.code}`, tenantId: TENANT, code: p.code, name: p.name, description: p.description, version: "1.0", status: "ACTIVE", steps: p.steps.map((s) => ({ ...s, id: `${p.code}-${s.stepOrder}` })), triggerConditions: { scope: "INCIDENT", incidentType: p.incidentType, mitreTechniques: p.mitreTechniques, allowedActions: p.allowedActions } })),
  ];
  const actionRepository = { findAll: async () => actions, findById: async (id: string) => actions.find((a) => a.id === id) ?? null, findByCodes: async (codes: string[]) => actions.filter((a) => codes.includes(a.code)) } as unknown as IActionRepository;
  const runbookRepository = { findAll: async () => runbooks, findById: async (id: string) => runbooks.find((r) => r.id === id) ?? null, findByCodes: async (codes: string[]) => runbooks.filter((r) => codes.includes(r.code)) } as unknown as IRunbookRepository;
  const playbookRepository = { findAll: async () => playbooks } as unknown as IPlaybookRepository;
  const policyService = { evaluate: async () => ({ policy: { responsibleRole: "IR_TEAM", approvalRequired: false, approvalRole: null, reviewRequired: false, reviewRole: null, matchedRules: ["RULE-A01"] } }) } as never;

  const contextRepo: IRecommendationContextRepository = {
    getIncidentContext: async () => ({ incidentId: INCIDENT, investigationNumber: o.investigationNumber ?? 1, title: TITLE, status: "investigating", priority: "medium", alertSeverity: "medium" }),
    getIocs: async () => (o.legacyIocs as never) ?? [{ iocType: "IPV4", iocValue: "172.19.0.3", networkRole: "source", source: "aggregated", reputationScore: null }, { iocType: "USERNAME", iocValue: "git", source: "ALERT", reputationScore: null }],
    getMitreMappings: async () => [{ techniqueId: "T1110", tactic: "Credential Access", confidence: 0.85 }],
    getEvidence: async () => [{ type: "WAZUH_ALERT", source: "WAZUH", origin: "SYSTEM", title: TITLE, timestamp: new Date("2026-10-08T01:00:00Z"), host: "attack-endpoint", ruleId: "5712", iocValues: ["172.19.0.3", "git"] }],
    getLatestAiAnalysis: async () => null,
    getPreviousRecommendationSteps: async () => o.previousSteps ?? [],
    getRehuntContext: async () => o.rehunt ?? null,
    getSubtypeEvidence: async () => o.rows,
    getTicketHistory: async () => o.tickets ?? [],
  };
  const builder = new RecommendationContextBuilder(contextRepo, actionRepository, runbookRepository, playbookRepository, policyService, undefined, undefined, undefined, { read: async () => fixtureCatalog(playbooks) });

  const created: CreateRecommendationData[] = [];
  const superseded: string[] = [];
  const logged: { action: string; metadata?: Record<string, any> }[] = [];
  const audits: RecommendationAuditRecord[] = [];
  const recommendationRepository = {
    getNextRecommendationNumber: async () => o.nextNumber ?? 1,
    create: async (data: CreateRecommendationData) => { created.push(data); return { id: `rec-${created.length}`, ...data, snapshotId: "snap-1", steps: data.steps.map((s, i) => ({ ...s, id: `step-${i + 1}` })) }; },
    supersedePrevious: async (_i: string, _t: string, keep: string) => void superseded.push(keep),
  } as unknown as IRecommendationRepository;
  const auditLogger = { record: async (e: { action: string; metadata?: Record<string, any> }) => void logged.push(e) } as unknown as AuditLogger;
  const auditRepo: IRecommendationAuditRepository = {
    save: async (r) => { if (o.auditFails) throw new Error("recommendation_audits table does not exist"); audits.push(r); },
    findByRecommendation: async () => null,
  };
  const agent: IRecommendationAgentPort = { generate: jest.fn((ctx) => new FakeRecommendationAgent().generate(ctx)) };
  const subtype: SubtypeIntegration | undefined = o.withSubtype === false ? undefined : {
    service: new SubtypeRecommendationService(loader, contextRepo, { resolve: () => ({ criticality: o.criticality ?? "MEDIUM" }) }, () => o.mode ?? "shadow"),
    audits: auditRepo, actions: actionRepository, runbooks: runbookRepository, narrator: o.narrator,
  };
  const useCase = new GenerateRecommendationUseCase(builder, agent, "FakeRecommendationAgent/v1.0.0", new RecommendationValidator(actionRepository, runbookRepository), recommendationRepository, auditLogger, undefined, subtype);
  return { useCase, run: () => useCase.execute({ incidentId: INCIDENT, tenantId: TENANT }), created, superseded, logged, audits, agent, actions };
}

export const allowUnreviewed = async <T>(fn: () => Promise<T>): Promise<T> => {
  process.env.SUBTYPE_ALLOW_UNREVIEWED = "true";
  try { return await fn(); } finally { delete process.env.SUBTYPE_ALLOW_UNREVIEWED; }
};
