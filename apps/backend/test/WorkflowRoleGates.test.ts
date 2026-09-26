import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildResponseRoutes } from "../src/presentation/http/routes/response.routes";
import { buildIncidentVerificationRoutes } from "../src/presentation/http/routes/verification.routes";

/**
 * Route-level RBAC for workflow EXECUTION: only IR_TEAM may start / complete / fail a response, run a re-hunt or
 * record a manual verification. SOC, a retired MANAGER token and admin (a system role) are rejected at the route — not just by
 * hiding a button. Controllers are stubs: the test proves the gate, not the use case.
 */
const ok = (_req: express.Request, res: express.Response) => res.status(200).json({ reached: true });
const responseController = { list: ok, create: ok, getById: ok, start: ok, complete: ok, fail: ok } as never;
const verificationController = { create: ok, rehunt: ok, list: ok, listByIncident: ok, getById: ok, rehuntHealth: ok, listAll: ok } as never;

// Real HTTP round trips on an ephemeral port: allow for a loaded machine during the full parallel run.
jest.setTimeout(30_000);
let server: Server;
let base = "";
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/responses", buildResponseRoutes(responseController));
  app.use("/api/incidents/:incidentId/verifications", buildIncidentVerificationRoutes(verificationController));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const as = (role: string) => ({ authorization: `Bearer ${signToken({ id: `u-${role}`, tenantId: "t1", role })}`, "content-type": "application/json" });
const post = (path: string, role: string) => fetch(`${base}${path}`, { method: "POST", headers: as(role), body: "{}" }).then((r) => r.status);

const EXECUTION_ROUTES = ["/api/responses/r1/start", "/api/responses/r1/complete", "/api/responses/r1/fail", "/api/incidents/i1/verifications/rehunt", "/api/incidents/i1/verifications"];

describe("workflow execution routes", () => {
  it.each(EXECUTION_ROUTES)("IR_TEAM may call %s", async (path) => {
    expect(await post(path, "IR_TEAM")).toBe(200);
  });

  it.each(EXECUTION_ROUTES.flatMap((p) => ["SOC", "MANAGER", "admin"].map((role) => [p, role])))("%s rejects %s with 403", async (path, role) => {
    expect(await post(path, role)).toBe(403);
  });

  it("an unauthenticated call is 401", async () => {
    const status = await fetch(`${base}/api/incidents/i1/verifications/rehunt`, { method: "POST" }).then((r) => r.status);
    expect(status).toBe(401);
  });

  it("creating a Response Ticket (Send to IR) is SOC work: IR_TEAM, admin and a retired MANAGER token are refused", async () => {
    expect(await post("/api/responses", "SOC")).toBe(200);
    expect(await post("/api/responses", "IR_TEAM")).toBe(403);
    expect(await post("/api/responses", "admin")).toBe(403);
    expect(await post("/api/responses", "MANAGER")).toBe(403);
  });
});
