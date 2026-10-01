/**
 * common.ts — shared helpers of the ADDITIONAL evaluation (baseline, consistency, negative/reject path).
 * Everything here runs against the cloned database (`soar_addl_eval`, name must end in `_eval`), never against the
 * frozen `soar_eval` or the development `soar_platform`. Production parity: the recommendation context builder gets
 * the SOC response setup and the ACTION_COMPLIANCE policies exactly as container.ts wires them.
 */
import * as fs from "node:fs";
import * as path from "node:path";
import https from "node:https";
import { createHash } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { PrismaRecommendationContextRepository } from "../../../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma";
import { PrismaActionRepository } from "../../../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { PrismaRunbookRepository } from "../../../src/infrastructure/database/postgres/repositories/RunbookRepository.prisma";
import { PrismaPlaybookRepository } from "../../../src/infrastructure/database/postgres/repositories/PlaybookRepository.prisma";
import { PrismaIncidentRepository } from "../../../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma";
import { PrismaApprovalRepository } from "../../../src/infrastructure/database/postgres/repositories/ApprovalRepository.prisma";
import { PrismaPolicyRepository } from "../../../src/infrastructure/database/postgres/repositories/PolicyRepository.prisma";
import { PrismaIncidentResponseSetupStore } from "../../../src/infrastructure/database/postgres/repositories/IncidentResponseSetupStore.prisma";
import { AuditLogger } from "../../../src/infrastructure/database/postgres/repositories/AuditLogger";
import { PolicyEvaluator } from "../../../src/infrastructure/policy-engine/PolicyEvaluator";
import { ApprovalService } from "../../../src/application/approval/services/ApprovalService";
import { ResourceAssetCriticalityProvider } from "../../../src/infrastructure/assets/ResourceAssetCriticalityProvider";
import { RecommendationContextBuilder } from "../../../src/application/recommendation/services/RecommendationContextBuilder";
import { IncidentResponseSetupService } from "../../../src/application/incident/services/IncidentResponseSetupService";
import { RecommendationValidator } from "../../../src/infrastructure/recommendation-validation/RecommendationValidator";
import { LlmRecommendationAgent } from "../../../src/infrastructure/ai/LlmRecommendationAgent";
import { GenerateRecommendationUseCase } from "../../../src/application/recommendation/use-cases/GenerateRecommendation.usecase";
import { INotificationDispatcherPort } from "../../../src/application/notification/ports/INotificationDispatcherPort";
import { RecommendationContextDto } from "../../../src/application/recommendation/dto/RecommendationContextDto";

export const TENANT = "00000000-0000-0000-0000-000000000001";
export const ROOT = path.resolve(__dirname, "..", "..", "..", "..", "..");
export const RES = path.join(ROOT, "results");
// FINAL evaluation re-uses these scripts through environment variables; defaults keep the additional-evaluation behaviour.
export const ADD = process.env.EVAL_OUT_ROOT ? path.resolve(process.env.EVAL_OUT_ROOT) : path.join(RES, "additional-evaluation");
export const DATA = path.join(ADD, "data");
export const r2 = (x: number) => Math.round(x * 100) / 100;
export const sha = (s: string) => createHash("sha256").update(s).digest("hex");

export function stats(xs: (number | null)[]) {
  const v = xs.filter((x): x is number => typeof x === "number" && Number.isFinite(x)).sort((a, b) => a - b);
  if (!v.length) return { n: 0, mean: null, median: null, min: null, max: null, sd: null };
  const mean = v.reduce((a, b) => a + b, 0) / v.length;
  const median = v.length % 2 ? v[(v.length - 1) / 2] : (v[v.length / 2 - 1] + v[v.length / 2]) / 2;
  const sd = v.length > 1 ? Math.sqrt(v.reduce((a, b) => a + (b - mean) ** 2, 0) / (v.length - 1)) : 0;
  return { n: v.length, mean: r2(mean), median: r2(median), min: v[0], max: v[v.length - 1], sd: r2(sd) };
}

/** Refuses to run unless the connection is the cloned evaluation database. */
export function assertAdditionalDb(): string {
  const name = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);
  const expected = process.env.EVAL_ADD_DB ?? "soar_addl_eval";
  if (name !== expected || !name.endsWith("_eval") || name === "soar_eval") throw new Error(`refusing to run: connected to '${name}', expected the dedicated database '${expected}' (frozen soar_eval / soar_platform must never be touched)`);
  if (process.env.REHUNT_PROVIDER !== "wazuh") throw new Error("REHUNT_PROVIDER must be wazuh");
  return name;
}

export function frozenRun(label: string) {
  return JSON.parse(fs.readFileSync(path.join(RES, "runs", label, "run.json"), "utf8"));
}
export const CLEAN_LABEL = process.env.EVAL_SOURCE_RUN ?? "clean-v2-real-wazuh-20260930";
export const INTERVENTION_LABEL = process.env.EVAL_SOURCE_RUN ?? "intervention-v2-real-wazuh-20260930";

/** Wazuh Indexer read by document id (same evidence source VIGIX ingested). */
export function indexerAlertById(docId: string): Promise<any> {
  const base = new URL(process.env.WAZUH_INDEXER_URL ?? "https://localhost:9200");
  const payload = JSON.stringify({ size: 1, query: { ids: { values: [docId] } } });
  const auth = Buffer.from(`${process.env.WAZUH_INDEXER_USERNAME}:${process.env.WAZUH_INDEXER_PASSWORD}`).toString("base64");
  return new Promise((resolve, reject) => {
    const req = https.request({ method: "POST", hostname: base.hostname, port: base.port || 443, path: "/wazuh-alerts-4.x-*/_search", headers: { Authorization: `Basic ${auth}`, "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) },
      ca: process.env.WAZUH_INDEXER_CA_PATH ? fs.readFileSync(process.env.WAZUH_INDEXER_CA_PATH) : undefined, servername: process.env.WAZUH_INDEXER_TLS_SERVERNAME || undefined, timeout: 20000 },
      (res) => { const c: Buffer[] = []; res.on("data", (d: Buffer) => c.push(d)); res.on("end", () => { try { resolve(JSON.parse(Buffer.concat(c).toString("utf8"))?.hits?.hits?.[0]?._source ?? null); } catch (e) { reject(e); } }); });
    req.on("error", reject); req.write(payload); req.end();
  });
}

/** In-memory recommendation store: the use case runs unchanged but persists NOTHING (no DB write, no supersede). */
export function memoryRecommendationRepo() {
  const created: any[] = [];
  return {
    created,
    repo: {
      findById: async () => null, findByIncidentAndNumber: async () => null, findAllByIncident: async () => [],
      getNextRecommendationNumber: async () => 1,
      create: async (data: any) => { const rec = { ...data, id: `mem-${created.length + 1}` }; created.push(rec); return rec; },
      updateStatus: async () => { throw new Error("not used"); }, supersedePrevious: async () => undefined,
    } as any,
  };
}

/** Audit logger that only remembers what the use case would have written (failure reasons + violations). */
export function capturingAudit() {
  const records: any[] = [];
  return { records, logger: { record: async (r: any) => { records.push(r); } } as unknown as AuditLogger };
}

/**
 * Builds the production-parity recommendation pipeline. `firstRound: true` hides the incident's earlier
 * recommendations from the context (previousSteps = []) — the condition the ORIGINAL first-round generation ran in.
 * Without it, the validator's NO_NEW_STEP rule (a repeat of an earlier action+target pair is rejected) would make a
 * repeated run on an incident that already has a recommendation impossible by design, not by AI instability.
 */
export function buildPipeline(prisma: PrismaClient, aiUrl: string, opts: { firstRound: boolean }) {
  const noNotify = { emit: async () => undefined } as unknown as INotificationDispatcherPort;
  const realCtx = new PrismaRecommendationContextRepository(prisma);
  const ctxRepo: any = opts.firstRound
    ? new Proxy(realCtx as any, { get: (t, p) => (p === "getPreviousRecommendationSteps" ? async () => [] : typeof t[p] === "function" ? t[p].bind(t) : t[p]) })
    : realCtx;
  const actions = new PrismaActionRepository(prisma);
  const runbooks = new PrismaRunbookRepository(prisma);
  const playbooks = new PrismaPlaybookRepository(prisma);
  const incidents = new PrismaIncidentRepository(prisma);
  const audit = new AuditLogger(prisma);
  const policy = new PolicyEvaluator(new PrismaPolicyRepository(prisma));
  const approvals = new PrismaApprovalRepository(prisma);
  const approvalService = new ApprovalService(realCtx, actions, policy, approvals, audit, noNotify, "http://localhost", new ResourceAssetCriticalityProvider());
  const setup = new IncidentResponseSetupService(new PrismaIncidentResponseSetupStore(prisma), ctxRepo, incidents, playbooks, actions, policy, audit);
  const builder = new RecommendationContextBuilder(ctxRepo, actions, runbooks, playbooks, approvalService, undefined, { resolve: (i: string, t: string) => setup.resolve(i, t) }, policy);
  const validator = new RecommendationValidator(actions, runbooks);
  const agent = new LlmRecommendationAgent(aiUrl);
  // record every raw AI candidate (positive controls for the negative scenarios are taken from these)
  const raw: any[] = [];
  const recordingAgent = { generate: async (ctx: RecommendationContextDto, correction?: string | null) => { const c = await (agent as any).generate(ctx, correction); raw.push({ correction: !!correction, candidate: c }); return c; } } as any;
  const mem = memoryRecommendationRepo();
  const cap = capturingAudit();
  const generate = new GenerateRecommendationUseCase(builder, recordingAgent, "LlmRecommendationAgent/v2.0.0 (additional-eval, non-persisting)", validator, mem.repo, cap.logger);
  return { builder, validator, agent, generate, created: mem.created, audits: cap.records, raw, policy, actions, playbooks, incidents, approvals, approvalService, audit, noNotify };
}

export async function preflightAdditional(): Promise<{ db: string; orchestrator: string }> {
  const db = assertAdditionalDb();
  let orchestrator = "";
  try { orchestrator = await (await fetch(`${process.env.AI_ORCHESTRATOR_URL}/health`)).text(); } catch (e) { orchestrator = String((e as Error).message); }
  if (!/"status":"ok"/.test(orchestrator)) throw new Error(`AI orchestrator not healthy at ${process.env.AI_ORCHESTRATOR_URL}: ${orchestrator}`);
  return { db, orchestrator: process.env.AI_ORCHESTRATOR_URL ?? "" };
}
