import express from "express";
import bcrypt from "bcryptjs";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import { signServiceToken, signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildAuthRoutes } from "../src/presentation/http/routes/auth.routes";
import { AuthController } from "../src/presentation/http/controllers/AuthController";
import { LoginUseCase } from "../src/application/identity/use-cases/Login.usecase";
import { ChangePasswordUseCase } from "../src/application/identity/use-cases/ChangePassword.usecase";
import { PrismaAuthRepository } from "../src/infrastructure/database/postgres/repositories/AuthRepository.prisma";

/**
 * Self-service password change over the real routes (JWT middleware + controller + use cases + bcrypt). The main suite
 * uses an in-memory credential store with the same methods as PrismaAuthRepository; the PostgreSQL suite (opt-in)
 * checks that the real repository commits the hash and the PASSWORD_CHANGED audit together.
 */

const TENANT_A = "tenant-A";
const TENANT_B = "tenant-B";
const OLD_PASSWORD = "Old-Passw0rd-2026";
const NEW_PASSWORD = "New-Passw0rd-2026!";

type StoredUser = { id: string; tenantId: string; email: string; role: string; passwordHash: string };
type AuditEntry = { tenantId: string; actor: string; action: string; entity: string; entityId: string; metadata: Record<string, unknown> };

class MemoryAuth {
  users = new Map<string, StoredUser>();
  audit: AuditEntry[] = [];
  async findByEmail(email: string) {
    const u = [...this.users.values()].find((x) => x.email === email);
    return u ? { id: u.id, tenantId: u.tenantId, role: u.role, passwordHash: u.passwordHash } : null;
  }
  async findCredentialById(id: string, tenantId: string) {
    const u = this.users.get(id);
    return u && u.tenantId === tenantId ? { id: u.id, tenantId: u.tenantId, email: u.email, passwordHash: u.passwordHash } : null;
  }
  async updatePasswordHash(id: string, tenantId: string, passwordHash: string) {
    const u = this.users.get(id);
    if (!u || u.tenantId !== tenantId) throw new Error("Password update did not match exactly one user");
    u.passwordHash = passwordHash;
    this.audit.push({ tenantId, actor: id, action: "PASSWORD_CHANGED", entity: "User", entityId: id, metadata: { selfService: true } });
  }
}

async function startApp(repo: unknown) {
  const controller = new AuthController(new LoginUseCase(repo as PrismaAuthRepository), new ChangePasswordUseCase(repo as PrismaAuthRepository));
  const app = express();
  app.use(express.json());
  app.use("/api/auth", buildAuthRoutes(controller));
  const server = app.listen(0);
  await new Promise<void>((r) => server.once("listening", () => r()));
  return { server, base: `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/auth` };
}

async function post(base: string, path: string, body: unknown, authorization?: string) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(authorization ? { authorization } : {}) },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, text, body: (text ? JSON.parse(text) : null) as Record<string, unknown> | null };
}

const change = (overrides: Record<string, unknown> = {}) => ({ currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD, confirmPassword: NEW_PASSWORD, ...overrides });

describe("Change password (self-service) over HTTP", () => {
  let repo: MemoryAuth;
  let server: Server;
  let base: string;
  const logs: string[] = [];
  let spies: jest.SpyInstance[] = [];

  const addUser = async (role: string, tenantId = TENANT_A, password = OLD_PASSWORD) => {
    const u: StoredUser = { id: randomUUID(), tenantId, email: `${role.toLowerCase()}-${randomUUID().slice(0, 6)}@vigix.test`, role, passwordHash: await bcrypt.hash(password, 4) };
    repo.users.set(u.id, u);
    return u;
  };
  const bearer = (u: StoredUser) => `Bearer ${signToken({ id: u.id, tenantId: u.tenantId, role: u.role })}`;

  beforeAll(async () => {
    repo = new MemoryAuth();
    ({ server, base } = await startApp(repo));
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));
  beforeEach(() => {
    logs.length = 0;
    repo.audit.length = 0;
    spies = (["log", "info", "warn", "error", "debug"] as const).map((m) =>
      jest.spyOn(console, m).mockImplementation((...args: unknown[]) => { logs.push(args.map((a) => (a instanceof Error ? `${a.message} ${a.stack}` : typeof a === "string" ? a : JSON.stringify(a))).join(" ")); }));
  });
  afterEach(() => {
    spies.forEach((s) => s.mockRestore());
    // Nothing from the request body — and no password in any form — ever reaches the logs.
    for (const line of logs) for (const secret of [OLD_PASSWORD, NEW_PASSWORD, "Wrong-Passw0rd-2026"]) expect(line).not.toContain(secret);
  });

  test("success: 200 { changed, reauthRequired }, the hash changes, old password no longer logs in, new one does", async () => {
    const user = await addUser("SOC");
    const before = user.passwordHash;
    const res = await post(base, "/change-password", change(), bearer(user));
    expect(res).toMatchObject({ status: 200, body: { changed: true, reauthRequired: true } });
    expect(Object.keys(res.body!).sort()).toEqual(["changed", "reauthRequired"]);
    for (const secret of [OLD_PASSWORD, NEW_PASSWORD, before, user.passwordHash]) expect(res.text).not.toContain(secret);

    expect(user.passwordHash).not.toBe(before);
    expect(await bcrypt.compare(NEW_PASSWORD, user.passwordHash)).toBe(true);
    expect((await post(base, "/login", { email: user.email, password: OLD_PASSWORD })).status).toBe(401);
    expect((await post(base, "/login", { email: user.email, password: NEW_PASSWORD })).status).toBe(200);
  });

  test("audit PASSWORD_CHANGED is recorded for the user, without any password or hash", async () => {
    const user = await addUser("IR_TEAM");
    expect((await post(base, "/change-password", change(), bearer(user))).status).toBe(200);
    expect(repo.audit).toEqual([{ tenantId: TENANT_A, actor: user.id, action: "PASSWORD_CHANGED", entity: "User", entityId: user.id, metadata: { selfService: true } }]);
    const serialized = JSON.stringify(repo.audit);
    for (const secret of [OLD_PASSWORD, NEW_PASSWORD, user.passwordHash]) expect(serialized).not.toContain(secret);
  });

  test.each(["SOC", "IR_TEAM", "admin", "VIEWER"])("%s can change their own password", async (role) => {
    const user = await addUser(role);
    expect((await post(base, "/change-password", change(), bearer(user))).status).toBe(200);
    expect(await bcrypt.compare(NEW_PASSWORD, user.passwordHash)).toBe(true);
  });

  test.each([["userId"], ["email"], ["tenantId"], ["role"], ["token"]])("an identity field (%s) in the body -> 400, no password changes anywhere", async (field) => {
    const user = await addUser("SOC");
    const victim = await addUser("admin");
    const victimHash = victim.passwordHash;
    const ownHash = user.passwordHash;
    const value = field === "userId" ? victim.id : field === "email" ? victim.email : field === "tenantId" ? TENANT_B : field === "role" ? "admin" : "forged";
    const res = await post(base, "/change-password", change({ [field]: value }), bearer(user));
    expect(res).toMatchObject({ status: 400, body: { error: "VALIDATION_ERROR" } });
    expect(victim.passwordHash).toBe(victimHash);
    expect(user.passwordHash).toBe(ownHash);
    expect(repo.audit).toEqual([]);
  });

  test("wrong current password -> 400 CURRENT_PASSWORD_INCORRECT (never 401), nothing changes", async () => {
    const user = await addUser("SOC");
    const hash = user.passwordHash;
    const res = await post(base, "/change-password", change({ currentPassword: "Wrong-Passw0rd-2026" }), bearer(user));
    expect(res).toEqual({ status: 400, text: expect.any(String), body: { error: "CURRENT_PASSWORD_INCORRECT" } });
    expect(user.passwordHash).toBe(hash);
    expect(repo.audit).toEqual([]);
  });

  test("confirmation mismatch -> 400 PASSWORD_CONFIRMATION_MISMATCH (checked by the backend)", async () => {
    const user = await addUser("SOC");
    const hash = user.passwordHash;
    expect(await post(base, "/change-password", change({ confirmPassword: `${NEW_PASSWORD}x` }), bearer(user)))
      .toMatchObject({ status: 400, body: { error: "PASSWORD_CONFIRMATION_MISMATCH" } });
    expect(user.passwordHash).toBe(hash);
  });

  test.each([
    ["shorter than 12 bytes", "Sh0rt!pass", ["MIN_BYTES"]],
    ["longer than 72 bytes", `Aa1!${"x".repeat(69)}`, ["MAX_BYTES"]],
    ["72 bytes counted in UTF-8, not characters (28 characters = 78 bytes)", `Aa1${"ก".repeat(25)}`, ["MAX_BYTES"]],
    ["only two character types", "lowercaseonly123", ["CHARACTER_TYPES"]],
  ])("policy: %s -> 400 PASSWORD_POLICY_VIOLATION", async (_label, password, rules) => {
    const user = await addUser("SOC");
    const hash = user.passwordHash;
    expect(await post(base, "/change-password", change({ newPassword: password, confirmPassword: password }), bearer(user)))
      .toEqual({ status: 400, text: expect.any(String), body: { error: "PASSWORD_POLICY_VIOLATION", rules } });
    expect(user.passwordHash).toBe(hash);
  });

  test("exactly 12 and exactly 72 bytes are accepted", async () => {
    for (const password of ["Abcdef1!ghij", `Aa1!${"x".repeat(68)}`]) {
      const user = await addUser("SOC");
      expect(Buffer.byteLength(password)).toBeGreaterThanOrEqual(12);
      expect((await post(base, "/change-password", change({ newPassword: password, confirmPassword: password }), bearer(user))).status).toBe(200);
    }
  });

  test("password equal to the user's email -> 400 PASSWORD_POLICY_VIOLATION SAME_AS_EMAIL", async () => {
    const user = await addUser("SOC");
    user.email = "Analyst.One2026@vigix.test";
    const hash = user.passwordHash;
    const password = "analyst.one2026@VIGIX.test";
    expect(await post(base, "/change-password", change({ newPassword: password, confirmPassword: password }), bearer(user)))
      .toMatchObject({ status: 400, body: { error: "PASSWORD_POLICY_VIOLATION", rules: ["SAME_AS_EMAIL"] } });
    expect(user.passwordHash).toBe(hash);
  });

  test("new password equal to the current one -> 400 PASSWORD_UNCHANGED", async () => {
    const user = await addUser("SOC");
    const hash = user.passwordHash;
    expect(await post(base, "/change-password", change({ newPassword: OLD_PASSWORD, confirmPassword: OLD_PASSWORD }), bearer(user)))
      .toMatchObject({ status: 400, body: { error: "PASSWORD_UNCHANGED" } });
    expect(user.passwordHash).toBe(hash);
  });

  test("missing fields -> 400 VALIDATION_ERROR", async () => {
    const user = await addUser("SOC");
    for (const body of [{}, { currentPassword: OLD_PASSWORD, newPassword: NEW_PASSWORD }, { ...change(), currentPassword: "" }]) {
      expect((await post(base, "/change-password", body, bearer(user))).body).toMatchObject({ error: "VALIDATION_ERROR" });
    }
  });

  test("no JWT -> 401; service token -> 403 HUMAN_PRINCIPAL_REQUIRED; nothing changes", async () => {
    const user = await addUser("SOC");
    const hash = user.passwordHash;
    expect((await post(base, "/change-password", change())).status).toBe(401);
    const service = `Bearer ${signServiceToken({ id: "service:ai-orchestrator", tenantId: TENANT_A, scopes: ["orchestrator:callback"], jobIds: [] })}`;
    expect(await post(base, "/change-password", change(), service)).toMatchObject({ status: 403, body: { error: "HUMAN_PRINCIPAL_REQUIRED" } });
    expect(user.passwordHash).toBe(hash);
    expect(repo.audit).toEqual([]);
  });

  test("cross-tenant identity: a token of tenant B carrying tenant A's user id -> 404, the user's password is unchanged", async () => {
    const user = await addUser("SOC", TENANT_A);
    const hash = user.passwordHash;
    const forged = `Bearer ${signToken({ id: user.id, tenantId: TENANT_B, role: "admin" })}`;
    expect(await post(base, "/change-password", change(), forged)).toMatchObject({ status: 404, body: { error: "NOT_FOUND" } });
    expect(user.passwordHash).toBe(hash);
    expect(repo.audit).toEqual([]);
  });
});

const url = process.env.AUTH_TEST_DATABASE_URL;
const pgSuite = url ? describe : describe.skip;

pgSuite("Change password on real PostgreSQL (PrismaAuthRepository + AuditLogger)", () => {
  let db: PrismaClient;
  let server: Server;
  let base: string;
  let tenantId: string;

  beforeAll(async () => {
    if (!url || !/^vigix_[a-z0-9_]*test[a-z0-9_]*$/.test(new URL(url).pathname.slice(1))) {
      throw new Error("Dedicated test database required; runtime/production targets are forbidden");
    }
    db = new PrismaClient({ datasources: { db: { url } } });
    tenantId = (await db.tenant.create({ data: { name: `ChangePassword test ${randomUUID()}` } })).id;
    ({ server, base } = await startApp(new PrismaAuthRepository(db)));
  });
  afterAll(async () => {
    await new Promise<void>((r) => (server ? server.close(() => r()) : r()));
    await db?.$disconnect(); // Synthetic fixtures are kept; no cleanup DELETE.
  });

  const createUser = async (role = "SOC") => db.user.create({ data: { tenantId, email: `cp-${randomUUID()}@vigix.test`, role, passwordHash: await bcrypt.hash(OLD_PASSWORD, 4) } });

  test("hash and PASSWORD_CHANGED audit are committed together; the audit carries no password or hash", async () => {
    const user = await createUser();
    const res = await post(base, "/change-password", change(), `Bearer ${signToken({ id: user.id, tenantId, role: user.role })}`);
    expect(res).toMatchObject({ status: 200, body: { changed: true, reauthRequired: true } });
    const stored = await db.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(stored.passwordHash).not.toBe(user.passwordHash);
    expect(await bcrypt.compare(NEW_PASSWORD, stored.passwordHash)).toBe(true);
    const audit = await db.auditLog.findMany({ where: { tenantId, entityId: user.id } });
    expect(audit).toEqual([expect.objectContaining({ actor: user.id, action: "PASSWORD_CHANGED", entity: "User", metadata: { selfService: true } })]);
    for (const secret of [OLD_PASSWORD, NEW_PASSWORD, user.passwordHash, stored.passwordHash]) expect(JSON.stringify(audit)).not.toContain(secret);
    expect((await post(base, "/login", { email: user.email, password: OLD_PASSWORD })).status).toBe(401);
    expect((await post(base, "/login", { email: user.email, password: NEW_PASSWORD })).status).toBe(200);
  });

  test("a failing audit write rolls the password change back", async () => {
    const user = await createUser();
    // Same real transaction, except that the audit insert fails.
    const failingAudit = new Proxy(db, {
      get(target, property, receiver) {
        if (property !== "$transaction") return Reflect.get(target, property, receiver);
        return (work: (tx: unknown) => Promise<unknown>) => target.$transaction((tx) => work(new Proxy(tx, {
          get: (t, p, r) => (p === "auditLog" ? { create: async () => { throw new Error("audit store unavailable"); } } : Reflect.get(t, p, r)),
        })));
      },
    });
    const repo = new PrismaAuthRepository(failingAudit);
    await expect(repo.updatePasswordHash(user.id, tenantId, await bcrypt.hash(NEW_PASSWORD, 4))).rejects.toThrow("audit store unavailable");
    const stored = await db.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(stored.passwordHash).toBe(user.passwordHash);
    expect(await db.auditLog.count({ where: { tenantId, entityId: user.id } })).toBe(0);
  });
});
