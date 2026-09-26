import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildPolicyRoutes } from "../src/presentation/http/routes/policy.routes";
import { PolicyController } from "../src/presentation/http/controllers/PolicyController";
import { DeletePolicyUseCase } from "../src/application/policy/use-cases/DeletePolicy.usecase";

/**
 * Knowledge → Policies: SOC, IR_TEAM and admin may delete a policy (X). A reason is required; the audit keeps the
 * actor, the reason and a full copy of the deleted policy so it can be recreated. Other roles get 403.
 * Real routes + JWT middleware + controller + use case; in-memory repository and audit.
 */

type Row = { id: string; tenantId: string; code: string; name: string; rules: unknown[] };
const rows = new Map<string, Row>();
const audits: { actor: string; action: string; policyId: string; metadata?: Record<string, unknown> }[] = [];
const repo = {
  findById: async (id: string, tenantId: string) => {
    const r = rows.get(id);
    return r && r.tenantId === tenantId ? { ...r, toJSON: () => ({ ...r }) } : null;
  },
  delete: async (id: string) => void rows.delete(id),
};
const controller = new PolicyController(
  {} as never, {} as never, {} as never, {} as never, {} as never, {} as never,
  new DeletePolicyUseCase(repo as never, { record: async (a: never) => void audits.push(a) } as never),
);

let server: Server;
let base = "";
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/policies", buildPolicyRoutes(controller, { evaluate: () => undefined } as never));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => {
  rows.clear();
  rows.set("p1", { id: "p1", tenantId: "tenant-A", code: "RULE-TEST", name: "Test rule", rules: [{ condition: { field: "severity", operator: "eq", value: "HIGH" } }] });
  audits.length = 0;
});

const del = async (id: string, body: unknown, role?: string, tenantId = "tenant-A") => {
  const res = await fetch(`${base}/api/policies/${id}`, {
    method: "DELETE",
    headers: { "content-type": "application/json", ...(role ? { authorization: `Bearer ${signToken({ id: `u-${role}`, tenantId, role })}` } : {}) },
    body: JSON.stringify(body),
  });
  return { status: res.status, body: (await res.json().catch(() => null)) as Record<string, unknown> };
};

it.each(["SOC", "IR_TEAM", "admin"])("%s deletes with a reason; DELETE_POLICY audited with actor, reason and a copy of the policy", async (role) => {
  const r = await del("p1", { reason: "Duplicate of RULE-I03" }, role);
  expect(r).toEqual({ status: 200, body: { deleted: true, id: "p1", code: "RULE-TEST" } });
  expect(rows.has("p1")).toBe(false);
  expect(audits).toEqual([
    expect.objectContaining({
      action: "DELETE_POLICY",
      actor: `u-${role}`,
      policyId: "p1",
      metadata: expect.objectContaining({ code: "RULE-TEST", reason: "Duplicate of RULE-I03", snapshot: expect.objectContaining({ code: "RULE-TEST", rules: expect.any(Array) }) }),
    }),
  ]);
});

it.each(["MANAGER", "VIEWER"])("%s -> 403, nothing deleted", async (role) => {
  expect((await del("p1", { reason: "x" }, role)).status).toBe(403);
  expect(rows.has("p1")).toBe(true);
  expect(audits).toEqual([]);
});

it("without a token -> 401", async () => {
  expect((await del("p1", { reason: "x" })).status).toBe(401);
  expect(rows.has("p1")).toBe(true);
});

it.each([[{}], [{ reason: "   " }]])("no reason (%j) -> 400, nothing deleted", async (body) => {
  expect((await del("p1", body, "SOC")).status).toBe(400);
  expect(rows.has("p1")).toBe(true);
});

it("unknown policy, or another tenant's -> 404", async () => {
  expect((await del("nope", { reason: "x" }, "SOC")).status).toBe(404);
  expect((await del("p1", { reason: "x" }, "SOC", "tenant-B")).status).toBe(404);
  expect(rows.has("p1")).toBe(true);
});
