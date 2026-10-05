import express from "express";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildActionRoutes } from "../src/presentation/http/routes/action.routes";
import { ActionController } from "../src/presentation/http/controllers/ActionController";
import { CreateActionUseCase } from "../src/application/action/use-cases/CreateAction.usecase";

/**
 * Knowledge → Actions → Add: SOC / IR_TEAM / admin may add an action (audited as CREATE_ACTION with the actor);
 * editing / enabling / disabling stays admin-only. Real routes + JWT middleware + controller + create use case.
 */
type Row = { id: string; code: string; tenantId: string; [k: string]: unknown };
const rows: Row[] = [];
const audits: { actor: string; action: string; entityId: string; metadata?: Record<string, unknown> }[] = [];
const repo = {
  findByCode: async (code: string, tenantId: string) => rows.find((r) => r.code === code && r.tenantId === tenantId) ?? null,
  create: async (d: Omit<Row, "id">) => {
    const row = { ...d, id: `act-${rows.length + 1}` } as Row;
    rows.push(row);
    return { id: row.id, toJSON: () => row };
  },
};
const controller = new ActionController(
  new CreateActionUseCase(repo as never, { record: async (a) => void audits.push(a) }),
  {} as never, {} as never, {} as never, {} as never, {} as never
);

let server: Server;
let base = "";
beforeAll(async () => {
  const app = express();
  app.use(express.json());
  app.use("/api/actions", buildActionRoutes(controller));
  server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));
beforeEach(() => { rows.length = 0; audits.length = 0; });

const call = (method: string, path: string, body: unknown, role?: string) =>
  fetch(`${base}/api/actions${path}`, {
    method,
    headers: { "content-type": "application/json", ...(role ? { authorization: `Bearer ${signToken({ id: `u-${role}`, tenantId: "t", role })}` } : {}) },
    body: JSON.stringify(body),
  });
const NEW = { code: "ACT-ISOLATE-HOST-TEST", name: "Isolate host", description: "Network-isolate the host", category: "CONTAINMENT", impactLevel: "HIGH", defaultApprovalRequired: true };

describe("Action create — Knowledge → Actions → Add", () => {
  it.each(["SOC", "IR_TEAM", "admin"])("%s can add an action; CREATE_ACTION audited with that user", async (role) => {
    const res = await call("POST", "/", NEW, role);
    expect(res.status).toBe(201);
    expect(await res.json()).toMatchObject({ code: NEW.code, category: "CONTAINMENT", impactLevel: "HIGH", defaultApprovalRequired: true });
    expect(audits).toEqual([expect.objectContaining({ action: "CREATE_ACTION", actor: `u-${role}`, entityId: "act-1" })]);
  });
  it.each(["MANAGER", "VIEWER"])("%s -> 403, nothing created", async (role) => {
    expect((await call("POST", "/", NEW, role)).status).toBe(403);
    expect(rows).toEqual([]);
  });
  it("without a token -> 401", async () => {
    expect((await call("POST", "/", NEW)).status).toBe(401);
  });
  it("duplicate code -> 409, not audited twice", async () => {
    await call("POST", "/", NEW, "SOC");
    expect((await call("POST", "/", NEW, "SOC")).status).toBe(409);
    expect(audits).toHaveLength(1);
  });
  it("invalid category -> 400", async () => {
    expect((await call("POST", "/", { ...NEW, category: "OTHER" }, "SOC")).status).toBe(400);
  });
  it("editing / enabling / disabling stays admin-only", async () => {
    expect((await call("PUT", "/act-1", { name: "x" }, "SOC")).status).toBe(403);
    expect((await call("PATCH", "/act-1/disable", {}, "IR_TEAM")).status).toBe(403);
  });
});
