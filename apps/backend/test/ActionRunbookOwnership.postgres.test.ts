import express from "express";
import { randomUUID } from "node:crypto";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { PrismaClient } from "@prisma/client";
import { PrismaActionRepository } from "../src/infrastructure/database/postgres/repositories/ActionRepository.prisma";
import { ActionRunbookRelationshipError } from "../src/domain/action/repositories/IActionRepository";
import { CreateActionUseCase } from "../src/application/action/use-cases/CreateAction.usecase";
import { UpdateActionUseCase } from "../src/application/action/use-cases/UpdateAction.usecase";
import { EnableActionUseCase } from "../src/application/action/use-cases/EnableAction.usecase";
import { DisableActionUseCase } from "../src/application/action/use-cases/DisableAction.usecase";
import { GetActionUseCase } from "../src/application/action/use-cases/GetAction.usecase";
import { ListActionsUseCase } from "../src/application/action/use-cases/ListActions.usecase";
import { ActionController } from "../src/presentation/http/controllers/ActionController";
import { buildActionRoutes } from "../src/presentation/http/routes/action.routes";
import { signToken, signServiceToken } from "../src/presentation/http/middlewares/auth.middleware";

const url = process.env.ACTION_RUNBOOK_TEST_DATABASE_URL;
const suite = url ? describe : describe.skip;
jest.setTimeout(30000);

suite("P0.1 Action → Runbook ownership, real PostgreSQL and HTTP", () => {
  let db: PrismaClient;
  let repository: PrismaActionRepository;
  let server: Server;
  let base: string;
  let tenantA: string;
  let tenantB: string;
  let runbookA: string;
  let runbookA2: string;
  let runbookB: string;
  let token: string;

  beforeAll(async () => {
    if (!url || !/^vigix_(phase1d_test_fresh|p01_test_[a-z0-9_]+)$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Explicit dedicated test DB required; runtime fallback forbidden");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    tenantA = (await db.tenant.create({ data: { name: `P01Action A ${randomUUID()}` } })).id;
    tenantB = (await db.tenant.create({ data: { name: `P01Action B ${randomUUID()}` } })).id;
    const runbook = async (tenantId: string) => (await db.runbook.create({ data: {
      tenantId, code: `P01-RB-${randomUUID()}`, name: "Test runbook", procedure: ["Test step"],
    } })).id;
    runbookA = await runbook(tenantA); runbookA2 = await runbook(tenantA); runbookB = await runbook(tenantB);
    repository = new PrismaActionRepository(db);
    const controller = new ActionController(new CreateActionUseCase(repository), new UpdateActionUseCase(repository),
      new EnableActionUseCase(repository), new DisableActionUseCase(repository), new GetActionUseCase(repository), new ListActionsUseCase(repository));
    const app = express(); app.use(express.json()); app.use("/api/actions", buildActionRoutes(controller));
    server = app.listen(0); await new Promise<void>(resolve => server.once("listening", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/actions`;
    token = signToken({ id: "p01-test-admin", tenantId: tenantA, role: "admin" });
  });
  afterAll(async () => {
    if (server) { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); }
    await db?.$disconnect(); // Retain synthetic fixtures; no reset or cleanup DELETE.
  });
  const body = (runbookId: string | null = runbookA) => ({ code: `P01-ACT-${randomUUID().toUpperCase()}`, name: "Test action", category: "CONTAINMENT", impactLevel: "HIGH", runbookId });
  /** The only create body SOC / IR_TEAM may send: HIGH impact and approval required. */
  const strictBody = (runbookId: string | null = runbookA) => ({ ...body(runbookId), defaultApprovalRequired: true });
  const roleToken = (role: string) => signToken({ id: `human-${role}`, tenantId: tenantA, role });
  async function call(method: string, path: string, data: object, auth = token, extraHeaders: Record<string, string> = {}) {
    const response = await fetch(base + path, { method, signal: AbortSignal.timeout(10000), headers: {
      "content-type": "application/json", authorization: `Bearer ${auth}`, ...extraHeaders,
    }, body: JSON.stringify(data) });
    return { status: response.status, body: await response.json() as Record<string, unknown> };
  }
  async function fixture() {
    const result = await call("POST", "", body()); expect(result.status).toBe(201);
    return String(result.body.id);
  }
  async function state() {
    return {
      actions: await db.action.findMany({ where: { tenantId: { in: [tenantA, tenantB] } }, orderBy: { id: "asc" } }),
      runbooks: await db.runbook.findMany({ where: { tenantId: { in: [tenantA, tenantB] } }, orderBy: { id: "asc" } }),
      audit: await db.auditLog.findMany({ where: { tenantId: { in: [tenantA, tenantB] } }, orderBy: { id: "asc" } }),
    };
  }
  test("same-tenant create returns 201 and stores the relationship", async () => {
    const result = await call("POST", "", body()); expect(result.status).toBe(201);
    expect(await db.action.findUniqueOrThrow({ where: { id: String(result.body.id) } })).toMatchObject({ tenantId: tenantA, runbookId: runbookA });
  });
  test("same-tenant update returns 200", async () => {
    const id = await fixture(); const result = await call("PUT", `/${id}`, { runbookId: runbookA2, name: "Updated" });
    expect(result.status).toBe(200);
    expect(await db.action.findUniqueOrThrow({ where: { id } })).toMatchObject({ runbookId: runbookA2, name: "Updated" });
  });
  test.each(["create", "update"])("cross-tenant %s returns 409 with no partial write or tenant B side effect", async operation => {
    const id = operation === "update" ? await fixture() : null; const before = await state();
    const result = await call(operation === "create" ? "POST" : "PUT", id ? `/${id}` : "", operation === "create" ? body(runbookB) : { runbookId: runbookB, name: "Must not change", impactLevel: "LOW" });
    expect(result).toEqual({ status: 409, body: { error: "ACTION_RUNBOOK_TENANT_MISMATCH" } });
    expect(await state()).toEqual(before);
    if (id) expect((await db.action.findUniqueOrThrow({ where: { id } })).runbookId).toBe(runbookA);
  });
  test.each(["create", "update"])("missing Runbook %s returns semantic 404 without mutation", async operation => {
    const id = operation === "update" ? await fixture() : null; const before = await state();
    const result = await call(operation === "create" ? "POST" : "PUT", id ? `/${id}` : "", operation === "create" ? body(randomUUID()) : { runbookId: randomUUID(), name: "Must not change" });
    expect(result).toEqual({ status: 404, body: { error: "RUNBOOK_NOT_FOUND" } }); expect(await state()).toEqual(before);
  });
  test("null create remains supported", async () => {
    const result = await call("POST", "", body(null)); expect(result.status).toBe(201); expect(result.body.runbookId).toBeNull();
  });
  test("null update detaches the Runbook", async () => {
    const id = await fixture(); expect((await call("PUT", `/${id}`, { runbookId: null })).status).toBe(200);
    expect((await db.action.findUniqueOrThrow({ where: { id } })).runbookId).toBeNull();
  });
  test("omitted update preserves existing relationship", async () => {
    const id = await fixture(); expect((await call("PUT", `/${id}`, { description: "Partial update" })).status).toBe(200);
    expect(await db.action.findUniqueOrThrow({ where: { id } })).toMatchObject({ runbookId: runbookA, description: "Partial update" });
  });
  test("omitted create keeps its null default", async () => {
    const { runbookId: _omitted, ...data } = body(); const result = await call("POST", "", data);
    expect(result.status).toBe(201); expect(result.body.runbookId).toBeNull();
  });
  test.each(["create", "update"])("query/header tenant cannot override authenticated principal on %s", async operation => {
    const id = operation === "update" ? await fixture() : null; const before = await state();
    expect(await call(id ? "PUT" : "POST", `${id ? `/${id}` : ""}?tenantId=${tenantB}`, id ? { runbookId: runbookB } : body(runbookB), token, { "x-tenant-id": tenantB })).toEqual({ status: 409, body: { error: "ACTION_RUNBOOK_TENANT_MISMATCH" } });
    expect(await state()).toEqual(before);
  });
  test.each(["create", "update"])("body tenant override is rejected by the existing strict DTO on %s", async operation => {
    const id = operation === "update" ? await fixture() : null; const before = await state();
    expect((await call(id ? "PUT" : "POST", id ? `/${id}` : "", { ...(id ? {} : body(runbookB)), tenantId: tenantB, runbookId: runbookB })).status).toBe(400);
    expect(await state()).toEqual(before);
  });
  test("missing Action retains ACTION_NOT_FOUND", async () => {
    expect(await call("PUT", `/${randomUUID()}`, { runbookId: runbookA })).toEqual({ status: 404, body: { error: "ACTION_NOT_FOUND" } });
  });
  test("duplicate code retains existing 409", async () => {
    const data = body(); expect((await call("POST", "", data)).status).toBe(201);
    expect(await call("POST", "", data)).toEqual({ status: 409, body: { error: "DUPLICATE_CODE" } });
  });
  test("foreign Action remains inaccessible even with a same-tenant Runbook", async () => {
    const id = await fixture(); const before = await state(); const other = signToken({ id: "p01-admin-B", tenantId: tenantB, role: "admin" });
    expect(await call("PUT", `/${id}`, { runbookId: runbookB }, other)).toEqual({ status: 404, body: { error: "ACTION_NOT_FOUND" } }); expect(await state()).toEqual(before);
  });
  test("service and viewer mutations retain role restrictions", async () => {
    const id = await fixture(); const before = await state();
    for (const auth of [signToken({ id: "viewer-A", tenantId: tenantA, role: "VIEWER" }), signServiceToken({ id: "service:p01", tenantId: tenantA, scopes: [], jobIds: [] })]) {
      expect((await call("PUT", `/${id}`, { runbookId: runbookA2 }, auth)).status).toBe(403);
    } expect(await state()).toEqual(before);
  });
  test.each(["SOC", "IR_TEAM"])("%s can create/edit but cannot cross tenants or toggle activation", async (role) => {
    const auth = roleToken(role);
    const created = await call("POST", "", strictBody(), auth);
    expect(created.status).toBe(201);
    const id = created.body.id;
    expect((await call("PUT", `/${id}`, { runbookId: runbookA2 }, auth)).status).toBe(200);
    const before = await state();
    expect(await call("PUT", `/${id}?tenantId=${tenantB}`, { runbookId: runbookB }, auth, { "x-tenant-id": tenantB })).toEqual({ status: 409, body: { error: "ACTION_RUNBOOK_TENANT_MISMATCH" } });
    expect(await call("POST", "", strictBody(runbookB), auth)).toEqual({ status: 409, body: { error: "ACTION_RUNBOOK_TENANT_MISMATCH" } });
    const foreign = signToken({ id: `foreign-${role}`, tenantId: tenantB, role });
    expect((await call("PUT", `/${id}`, { name: "Forbidden" }, foreign)).status).toBe(404);
    expect((await call("PATCH", `/${id}/disable`, {}, auth)).status).toBe(403);
    expect(await state()).toEqual(before);
  });
  test("repository callers receive typed errors for both write paths", async () => {
    const id = await fixture(); const before = await state();
    for (const [runbookId, code] of [[runbookB, "ACTION_RUNBOOK_TENANT_MISMATCH"], [randomUUID(), "RUNBOOK_NOT_FOUND"]]) {
      for (const write of [() => repository.create({ ...body(runbookId), tenantId: tenantA, description: null, category: "CONTAINMENT", impactLevel: "HIGH", defaultApprovalRequired: false }), () => repository.update(id, tenantA, { runbookId })]) {
        await expect(write()).rejects.toBeInstanceOf(ActionRunbookRelationshipError);
        await expect(write()).rejects.toMatchObject({ code });
      }
    } expect(await state()).toEqual(before);
  });

  describe("governance fields (impactLevel / defaultApprovalRequired feed the approval policy)", () => {
    const FORBIDDEN = { status: 403, body: { error: "ACTION_GOVERNANCE_FIELD_FORBIDDEN" } };
    const stored = (id: unknown) => db.action.findUniqueOrThrow({ where: { id: String(id) } });

    test.each(["SOC", "IR_TEAM"])("%s creates with HIGH + approval required -> 201, stored as sent", async (role) => {
      const result = await call("POST", "", strictBody(), roleToken(role));
      expect(result.status).toBe(201);
      expect(await stored(result.body.id)).toMatchObject({ impactLevel: "HIGH", defaultApprovalRequired: true, tenantId: tenantA });
    });

    test.each([
      ["SOC", "LOW", true], ["SOC", "MEDIUM", true], ["SOC", "HIGH", false],
      ["IR_TEAM", "LOW", true], ["IR_TEAM", "MEDIUM", true], ["IR_TEAM", "HIGH", false],
    ] as const)("%s create with impactLevel=%s, defaultApprovalRequired=%s -> 403, nothing written", async (role, impactLevel, defaultApprovalRequired) => {
      const before = await state();
      const data = { ...body(), impactLevel, defaultApprovalRequired };
      expect(await call("POST", "", data, roleToken(role))).toEqual(FORBIDDEN);
      expect(await state()).toEqual(before);
      expect(await db.action.count({ where: { code: data.code } })).toBe(0);
    });

    test.each(["SOC", "IR_TEAM"])("%s create omitting defaultApprovalRequired gets the DTO default false -> 403 (never stored lower)", async (role) => {
      const before = await state();
      expect(await call("POST", "", body(), roleToken(role))).toEqual(FORBIDDEN);
      expect(await state()).toEqual(before);
    });

    test.each(["SOC", "IR_TEAM"])("%s create omitting impactLevel -> 400 VALIDATION_ERROR (required field)", async (role) => {
      const { impactLevel: _omitted, ...data } = strictBody();
      const before = await state();
      expect((await call("POST", "", data, roleToken(role))).status).toBe(400);
      expect(await state()).toEqual(before);
    });

    test.each([["LOW", false], ["MEDIUM", true], ["MEDIUM", false]] as const)("admin create with impactLevel=%s, defaultApprovalRequired=%s -> 201 as sent", async (impactLevel, defaultApprovalRequired) => {
      const result = await call("POST", "", { ...body(), impactLevel, defaultApprovalRequired });
      expect(result.status).toBe(201);
      expect(await stored(result.body.id)).toMatchObject({ impactLevel, defaultApprovalRequired });
    });

    test.each(["SOC", "IR_TEAM"])("%s update cannot change impactLevel or defaultApprovalRequired (no partial write)", async (role) => {
      const created = await call("POST", "", strictBody(), roleToken(role));
      const id = created.body.id;
      const before = await state();
      for (const change of [{ impactLevel: "LOW" }, { impactLevel: "MEDIUM" }, { defaultApprovalRequired: false }, { name: "Renamed", impactLevel: "LOW" }]) {
        expect(await call("PUT", `/${id}`, change, roleToken(role))).toEqual(FORBIDDEN);
      }
      expect(await state()).toEqual(before);
      expect(await stored(id)).toMatchObject({ impactLevel: "HIGH", defaultApprovalRequired: true, name: "Test action" });
    });

    test.each(["SOC", "IR_TEAM"])("%s update of name / description / runbookId -> 200; resending the current governance values is not a change", async (role) => {
      const id = (await call("POST", "", strictBody(), roleToken(role))).body.id;
      expect((await call("PUT", `/${id}`, { name: "Renamed", description: "Edited", runbookId: runbookA2 }, roleToken(role))).status).toBe(200);
      expect((await call("PUT", `/${id}`, { name: "Again", impactLevel: "HIGH", defaultApprovalRequired: true }, roleToken(role))).status).toBe(200);
      expect(await stored(id)).toMatchObject({ name: "Again", description: "Edited", runbookId: runbookA2, impactLevel: "HIGH", defaultApprovalRequired: true });
    });

    test.each(["SOC", "IR_TEAM"])("%s cannot change governance fields of an admin-created LOW action either", async (role) => {
      const id = (await call("POST", "", { ...body(), impactLevel: "LOW", defaultApprovalRequired: false })).body.id;
      const before = await state();
      expect(await call("PUT", `/${id}`, { impactLevel: "HIGH" }, roleToken(role))).toEqual(FORBIDDEN);
      expect(await call("PUT", `/${id}`, { defaultApprovalRequired: true }, roleToken(role))).toEqual(FORBIDDEN);
      expect(await state()).toEqual(before);
    });

    test("admin update can change both governance fields", async () => {
      const id = (await call("POST", "", strictBody(), roleToken("SOC"))).body.id;
      expect((await call("PUT", `/${id}`, { impactLevel: "LOW", defaultApprovalRequired: false })).status).toBe(200);
      expect(await stored(id)).toMatchObject({ impactLevel: "LOW", defaultApprovalRequired: false });
      expect((await call("PUT", `/${id}`, { impactLevel: "MEDIUM", defaultApprovalRequired: true })).status).toBe(200);
      expect(await stored(id)).toMatchObject({ impactLevel: "MEDIUM", defaultApprovalRequired: true });
    });
  });
});
