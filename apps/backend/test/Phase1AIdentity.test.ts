import express from "express";
import jwt from "jsonwebtoken";
import { Server } from "node:http";
import { AddressInfo } from "node:net";
import { authenticate, authenticatedTenant, signToken, signServiceToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildApprovalRoutes } from "../src/presentation/http/routes/approval.routes";
import { buildWebhookRoutes } from "../src/presentation/http/routes/webhook.routes";
import { OrchestratorCallbackController } from "../src/presentation/http/webhooks/orchestrator-callback.webhook";
import { buildKnowledgeRoutes } from "../src/presentation/http/routes/knowledge.routes";
import { KnowledgeSearchController } from "../src/presentation/http/controllers/KnowledgeSearchController";
import { RecommendationController } from "../src/presentation/http/controllers/RecommendationController";
import { buildRecommendationRoutes } from "../src/presentation/http/routes/recommendation.routes";
import { Result } from "../src/shared/result/Result";
import { ApprovalController } from "../src/presentation/http/controllers/ApprovalController";
import { ResponseController } from "../src/presentation/http/controllers/ResponseController";
import { ActionController } from "../src/presentation/http/controllers/ActionController";
import { RunbookController } from "../src/presentation/http/controllers/RunbookController";
import { PlaybookController } from "../src/presentation/http/controllers/PlaybookController";
import { VerificationController } from "../src/presentation/http/controllers/VerificationController";
import { DashboardController } from "../src/presentation/http/controllers/DashboardController";
import { buildResponseRoutes } from "../src/presentation/http/routes/response.routes";
import { buildActionRoutes } from "../src/presentation/http/routes/action.routes";
import { buildRunbookRoutes } from "../src/presentation/http/routes/runbook.routes";
import { buildPlaybookRoutes } from "../src/presentation/http/routes/playbook.routes";
import { buildVerificationRoutes } from "../src/presentation/http/routes/verification.routes";
import { buildDashboardRoutes } from "../src/presentation/http/routes/dashboard.routes";

// Real HTTP, fake persistence only. This suite never constructs PrismaClient or contacts an external service.
jest.setTimeout(30000);
let server: Server;
let base: string;
const audits: unknown[] = [];
const reads = jest.fn(async ({ id, tenantId }: { id: string; tenantId: string }) =>
  tenantId === "tenant-A" && id === "own" ? Result.ok({ toJSON: () => ({ id }) }) : Result.fail("NOT_FOUND"));
const search = jest.fn(async () => []);
const approval = jest.fn((_req, res) => res.json({ reached: true }));
const decide = jest.fn(async (input: { approvalId: string; tenantId: string }) =>
  input.approvalId === "a" && input.tenantId === "tenant-A" ? Result.ok({ toJSON: () => ({ reached: true }) }) : Result.fail("NOT_FOUND"));
const summary = jest.fn(async () => Result.ok({ scoped: true }));
const callback = new OrchestratorCallbackController({ record: async (event: unknown) => { audits.push(event); } } as never, {
  findOwnedJob: async ({ executionId, incidentId, tenantId }) => executionId === "job-A" && incidentId === "incident-A" && tenantId === "tenant-A",
});
const human = signToken({ id: "human-A", tenantId: "tenant-A", role: "IR_TEAM" });
const service = signServiceToken({ id: "service:orchestrator", tenantId: "tenant-A", scopes: ["orchestrator:callback", "knowledge:search"], jobIds: ["job-A"] });
const call = (path: string, token?: string, body?: object, method = body ? "POST" : "GET") => fetch(base + path, {
  method, headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
  body: body ? JSON.stringify(body) : undefined,
});
beforeAll(async () => {
  const app = express(); app.use(express.json());
  app.post("/context", authenticate, (req, res) => res.json({ tenantId: authenticatedTenant(req), actor: req.user!.id, principalType: req.principal!.principalType }));
  app.post("/mutation/:id", authenticate, (req, res) => {
    if (req.params.id !== "own" || authenticatedTenant(req) !== "tenant-A") return void res.status(404).json({ error: "NOT_FOUND" });
    res.json({ actor: req.user!.id, tenant: authenticatedTenant(req) });
  });
  app.use("/recommendations", buildRecommendationRoutes(new RecommendationController({} as never, { execute: reads } as never, {} as never, {} as never, {} as never)));
  app.use("/approvals", buildApprovalRoutes(new ApprovalController({} as never, { execute: decide } as never, { execute: reads } as never, {} as never)));
  app.use("/responses", buildResponseRoutes(new ResponseController({} as never, {} as never, {} as never, {} as never, { execute: reads } as never, {} as never)));
  app.use("/actions", buildActionRoutes(new ActionController({} as never, {} as never, {} as never, {} as never, { execute: reads } as never, {} as never)));
  app.use("/runbooks", buildRunbookRoutes(new RunbookController({} as never, {} as never, { execute: reads } as never, {} as never)));
  app.use("/playbooks", buildPlaybookRoutes(new PlaybookController({} as never, {} as never, { execute: reads } as never, {} as never)));
  app.use("/verifications", buildVerificationRoutes(new VerificationController({} as never, { execute: reads } as never, {} as never, {} as never, {} as never, {} as never)));
  app.use("/dashboard", buildDashboardRoutes(new DashboardController({ execute: summary } as never)));
  app.use("/webhooks", buildWebhookRoutes({ handle: approval } as never, callback));
  app.use("/knowledge", buildKnowledgeRoutes(new KnowledgeSearchController({ search } as never)));
  server = app.listen(0); await new Promise<void>(resolve => server.once("listening", resolve));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>(resolve => server.close(() => resolve())));
beforeEach(() => { audits.length = 0; jest.clearAllMocks(); });

test("query/body tenant and actor cannot override authenticated human", async () => {
  const response = await call("/context?tenantId=tenant-B", human, { tenantId: "tenant-B", actor: "victim", role: "admin", principalType: "SERVICE" });
  expect(await response.json()).toEqual({ tenantId: "tenant-A", actor: "human-A", principalType: "HUMAN" });
});
test("protected Recommendation reads require authentication and scoped object access", async () => {
  expect((await call("/recommendations/own")).status).toBe(401);
  expect((await call("/recommendations/foreign?tenantId=tenant-B", human)).status).toBe(404);
  expect(reads).toHaveBeenCalledWith({ id: "foreign", tenantId: "tenant-A" });
  expect((await call("/recommendations/own?tenantId=tenant-B", human)).status).toBe(200);
});
test("cross-tenant mutation is denied and actor remains authenticated", async () => {
  expect((await call("/mutation/foreign?tenantId=tenant-B", human, { tenantId: "tenant-B" })).status).toBe(404);
  expect(await (await call("/mutation/own", human, { actor: "victim" })).json()).toEqual({ actor: "human-A", tenant: "tenant-A" });
});
test("service cannot approve or impersonate a human", async () => {
  expect((await call("/approvals/a/approve", service, { comment: "approve", role: "IR_TEAM" })).status).toBe(403);
  expect((await call("/context", service, { principalType: "HUMAN" })).status).toBe(403);
  expect(decide).not.toHaveBeenCalled();
  expect((await call("/approvals/a/approve", human, { comment: "human" })).status).toBe(200);
  expect(decide).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-A", decidedBy: "human-A", decidedByRole: "IR_TEAM" }));
});

test.each(["responses", "actions", "runbooks", "playbooks", "verifications", "approvals"])("%s authenticates and forwards trusted tenant on real controller reads", async (surface) => {
  expect((await call(`/${surface}/own`)).status).toBe(401);
  expect((await call(`/${surface}/foreign?tenantId=tenant-B`, human)).status).toBe(404);
  expect(reads).toHaveBeenLastCalledWith({ id: "foreign", tenantId: "tenant-A" });
  expect((await call(`/${surface}/own?tenantId=tenant-B`, human)).status).toBe(200);
});

test("real approval mutation rejects foreign resource and caller identity injection", async () => {
  expect((await call("/approvals/foreign/approve?tenantId=tenant-B", human, { comment: "review" })).status).toBe(404);
  expect(decide).toHaveBeenLastCalledWith(expect.objectContaining({ tenantId: "tenant-A", decidedBy: "human-A" }));
  decide.mockClear();
  expect((await call("/approvals/a/approve", human, { comment: "review", tenantId: "tenant-B", decidedBy: "victim" })).status).toBe(400);
  expect(decide).not.toHaveBeenCalled();
});

test("Dashboard authentication and tenant binding", async () => {
  expect((await call("/dashboard/summary")).status).toBe(401);
  expect((await call("/dashboard/summary?tenantId=tenant-B", human)).status).toBe(200);
  expect(summary).toHaveBeenCalledWith(expect.objectContaining({ tenantId: "tenant-A" }));
});

test("service needs scope and JWT without tenant cannot trigger default fallback", async () => {
  const noScope = signServiceToken({ id: "service:limited", tenantId: "tenant-A", scopes: [], jobIds: ["job-A"] });
  expect((await call("/knowledge/search", noScope, { embedding: [0.1] })).status).toBe(403);
  expect((await call("/webhooks/orchestrator/callback", noScope, payload)).status).toBe(403);
  const noTenant = jwt.sign({ id: "human-A", role: "IR_TEAM" }, process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-in-production", { expiresIn: "1h" });
  expect((await call("/responses/own", noTenant)).status).toBe(401);
});
test("service claims with a human role are rejected", async () => {
  const token = jwt.sign({ id: "service:bad", tenantId: "tenant-A", role: "IR_TEAM", principalType: "SERVICE", scopes: [], jobIds: [] }, process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-in-production", { expiresIn: "1h", audience: "vigix-service", issuer: "vigix" });
  expect((await call("/approvals/a/approve", token, { comment: "bad" })).status).toBe(401);
});
test("search requires authentication and server tenant overrides caller filters", async () => {
  const body = { embedding: [0.1], topK: 1, filters: { tenantId: ["tenant-B"] } };
  expect((await call("/knowledge/search", undefined, body)).status).toBe(401);
  expect((await call("/knowledge/search", service, body)).status).toBe(200);
  expect(search).toHaveBeenCalledWith({ ...body, filters: { tenantId: ["tenant-A"] } });
});
const payload = { executionId: "job-A", incidentId: "incident-A", decision: "auto_response" };
test("anonymous/forged/human callbacks denied", async () => {
  expect((await call("/webhooks/orchestrator/callback", undefined, payload)).status).toBe(401);
  expect((await call("/webhooks/orchestrator/callback", "forged", payload)).status).toBe(401);
  expect((await call("/webhooks/orchestrator/callback", human, payload)).status).toBe(403);
  expect(audits).toEqual([]);
});
test("wrong tenant, ungranted job, and mismatching incident denied", async () => {
  const other = signServiceToken({ id: "service:orchestrator", tenantId: "tenant-B", scopes: ["orchestrator:callback"], jobIds: ["job-A"] });
  expect((await call("/webhooks/orchestrator/callback", other, payload)).status).toBe(403);
  expect((await call("/webhooks/orchestrator/callback", service, { ...payload, executionId: "job-B" })).status).toBe(403);
  expect((await call("/webhooks/orchestrator/callback", service, { ...payload, incidentId: "incident-B" })).status).toBe(403);
  expect(audits).toEqual([]);
});
test("valid service callback is advisory and cannot override identity", async () => {
  const response = await call("/webhooks/orchestrator/callback?tenantId=tenant-B", service, { ...payload, tenantId: "tenant-B", actor: "human-victim" });
  expect(response.status).toBe(200);
  expect(await response.json()).toEqual({ acknowledged: true, playbookTriggered: false });
  expect(audits).toEqual([expect.objectContaining({ tenantId: "tenant-A", actor: "service:orchestrator", metadata: expect.objectContaining({ principalType: "SERVICE", executionId: "job-A", advisoryOnly: true }) })]);
});
