import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildPolicyRoutes } from "../src/presentation/http/routes/policy.routes";
import { PolicyController } from "../src/presentation/http/controllers/PolicyController";
import { PolicyEvaluationController } from "../src/presentation/http/controllers/PolicyEvaluationController";

// Policy rules are organizational security configuration. Regression for the E2E finding (2026-09-26):
// GET /api/policies and POST /api/policies/evaluate answered 200 without any token, and the tenant came from ?tenantId=.
// Real routes + real JWT middleware + real controllers; only the use cases are fakes that record the tenant they got.

const seen: { list: string[]; get: string[]; evaluate: string[] } = { list: [], get: [], evaluate: [] };
const ok = <T>(value: T) => ({ isSuccess: true, isFailure: false, value });
const policy = (id: string) => ({ toJSON: () => ({ id, code: "RULE-I03" }) }); // controllers serialize the entity
const policyController = new PolicyController(
  {} as never,
  {} as never,
  {} as never,
  {} as never,
  { execute: async (i: { id: string; tenantId: string }) => (seen.get.push(i.tenantId), ok(policy(i.id))) } as never,
  { execute: async (i: { tenantId: string }) => (seen.list.push(i.tenantId), [policy("p1")]) } as never
);
const evaluationController = new PolicyEvaluationController({
  execute: async (i: { tenantId: string }) => (seen.evaluate.push(i.tenantId), { priority: "P1", matchedPolicies: ["RULE-I03"] }),
} as never);

let server: Server;
let base = "";
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/policies", buildPolicyRoutes(policyController, evaluationController));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const token = (role: string, tenantId = "tenant-A") => signToken({ id: `u-${role}`, tenantId, role });
const READS: [string, string, unknown][] = [
  ["GET", "/api/policies", undefined],
  ["GET", "/api/policies/p1", undefined],
  ["POST", "/api/policies/evaluate", { severity: "HIGH" }],
];
const call = (method: string, path: string, body: unknown, auth?: string) =>
  fetch(`${base}${path}`, { method, headers: { "content-type": "application/json", ...(auth ? { authorization: auth } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) });

describe("Policy API authentication", () => {
  it.each(READS)("%s %s without a token -> 401", async (method, path, body) => {
    const res = await call(method, path, body);
    expect(res.status).toBe(401);
  });

  it.each(READS)("%s %s with an invalid token -> 401", async (method, path, body) => {
    expect((await call(method, path, body, "Bearer not-a-jwt")).status).toBe(401);
  });

  it.each(READS.flatMap(([m, p, b]) => ["SOC", "IR_TEAM", "admin"].map((role) => [m, p, b, role] as const)))(
    "%s %s as %s -> 200",
    async (method, path, body, role) => {
      expect((await call(method, path, body, `Bearer ${token(role)}`)).status).toBe(200);
    }
  );

  it.each(READS.flatMap(([m, p, b]) => ["MANAGER", "VIEWER"].map((role) => [m, p, b, role] as const)))(
    "%s %s as %s (not an operational role) -> 403",
    async (method, path, body, role) => {
      expect((await call(method, path, body, `Bearer ${token(role)}`)).status).toBe(403);
    }
  );

  it("mutations stay admin-only (SOC -> 403)", async () => {
    expect((await call("POST", "/api/policies", {}, `Bearer ${token("SOC")}`)).status).toBe(403);
    expect((await call("PATCH", "/api/policies/p1/disable", {}, `Bearer ${token("IR_TEAM")}`)).status).toBe(403);
  });

  it("the tenant comes from the JWT, never from ?tenantId=", async () => {
    seen.list.length = seen.get.length = seen.evaluate.length = 0;
    const auth = `Bearer ${token("SOC", "tenant-A")}`;
    await call("GET", "/api/policies?tenantId=tenant-B", undefined, auth);
    await call("GET", "/api/policies/p1?tenantId=tenant-B", undefined, auth);
    await call("POST", "/api/policies/evaluate?tenantId=tenant-B", { severity: "HIGH" }, auth);
    expect(seen).toEqual({ list: ["tenant-A"], get: ["tenant-A"], evaluate: ["tenant-A"] });
  });
});
