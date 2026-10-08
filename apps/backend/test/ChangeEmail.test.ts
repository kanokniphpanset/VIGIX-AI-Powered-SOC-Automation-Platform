import express from "express";
import bcrypt from "bcryptjs";
import { AddressInfo } from "node:net";
import { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { signServiceToken, signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { buildAuthRoutes } from "../src/presentation/http/routes/auth.routes";
import { AuthController } from "../src/presentation/http/controllers/AuthController";
import { LoginUseCase } from "../src/application/identity/use-cases/Login.usecase";
import { ChangeEmailUseCase } from "../src/application/identity/use-cases/ChangeEmail.usecase";
import { PrismaAuthRepository } from "../src/infrastructure/database/postgres/repositories/AuthRepository.prisma";

/**
 * Self-service email change over the real routes (JWT middleware + controller + use case + bcrypt), with an in-memory
 * credential store that has the same methods as PrismaAuthRepository.
 */

const TENANT_A = "tenant-A";
const TENANT_B = "tenant-B";
const PASSWORD = "Curr3nt-Passw0rd!";

type StoredUser = { id: string; tenantId: string; email: string; role: string; passwordHash: string };
type AuditEntry = { tenantId: string; actor: string; action: string; entity: string; entityId: string; metadata: Record<string, unknown> };

class MemoryAuth {
  users = new Map<string, StoredUser>();
  audit: AuditEntry[] = [];
  raceTaken = false;
  async findByEmail(email: string) {
    const u = [...this.users.values()].find((x) => x.email === email);
    return u ? { id: u.id, tenantId: u.tenantId, role: u.role, passwordHash: u.passwordHash } : null;
  }
  async findCredentialById(id: string, tenantId: string) {
    const u = this.users.get(id);
    return u && u.tenantId === tenantId ? { id: u.id, tenantId: u.tenantId, email: u.email, passwordHash: u.passwordHash } : null;
  }
  async emailInUse(email: string, exceptUserId: string) {
    return [...this.users.values()].some((u) => u.id !== exceptUserId && u.email.toLowerCase() === email.toLowerCase());
  }
  async updateEmail(id: string, tenantId: string, email: string, previousEmail: string): Promise<"OK" | "EMAIL_TAKEN"> {
    if (this.raceTaken) return "EMAIL_TAKEN";
    const u = this.users.get(id);
    if (!u || u.tenantId !== tenantId) throw new Error("Email update did not match exactly one user");
    u.email = email;
    this.audit.push({ tenantId, actor: id, action: "EMAIL_CHANGED", entity: "User", entityId: id, metadata: { selfService: true, previousEmail, email } });
    return "OK";
  }
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

describe("Change email (self-service) over HTTP", () => {
  let repo: MemoryAuth;
  let server: Server;
  let base: string;

  const addUser = async (role = "SOC", tenantId = TENANT_A, email?: string) => {
    const u: StoredUser = { id: randomUUID(), tenantId, email: email ?? `${role.toLowerCase()}-${randomUUID().slice(0, 6)}@vigix.test`, role, passwordHash: await bcrypt.hash(PASSWORD, 4) };
    repo.users.set(u.id, u);
    return u;
  };
  const bearer = (u: StoredUser) => `Bearer ${signToken({ id: u.id, tenantId: u.tenantId, role: u.role })}`;
  const fresh = () => `new-${randomUUID().slice(0, 8)}@vigix.test`;

  beforeAll(async () => {
    repo = new MemoryAuth();
    const controller = new AuthController(new LoginUseCase(repo as unknown as PrismaAuthRepository), undefined, new ChangeEmailUseCase(repo));
    const app = express();
    app.use(express.json());
    app.use("/api/auth", buildAuthRoutes(controller));
    server = app.listen(0);
    await new Promise<void>((r) => server.once("listening", () => r()));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/api/auth`;
  });
  afterAll(() => new Promise<void>((r) => server.close(() => r())));
  beforeEach(() => {
    repo.audit.length = 0;
    repo.raceTaken = false;
  });

  test("success: 200 { changed, email } (normalised), login works with the new email and no longer with the old one", async () => {
    const user = await addUser();
    const old = user.email;
    const target = fresh();
    const res = await post(base, "/change-email", { newEmail: `  ${target.toUpperCase()} `, currentPassword: PASSWORD }, bearer(user));
    expect(res).toMatchObject({ status: 200, body: { changed: true, email: target } });
    expect(res.text).not.toContain(PASSWORD);
    expect(user.email).toBe(target);
    expect((await post(base, "/login", { email: target, password: PASSWORD })).status).toBe(200);
    expect((await post(base, "/login", { email: old, password: PASSWORD })).status).toBe(401);
  });

  test("audit EMAIL_CHANGED records previous and new email, never the password", async () => {
    const user = await addUser("IR_TEAM");
    const old = user.email;
    const target = fresh();
    expect((await post(base, "/change-email", { newEmail: target, currentPassword: PASSWORD }, bearer(user))).status).toBe(200);
    expect(repo.audit).toEqual([{ tenantId: TENANT_A, actor: user.id, action: "EMAIL_CHANGED", entity: "User", entityId: user.id, metadata: { selfService: true, previousEmail: old, email: target } }]);
    expect(JSON.stringify(repo.audit)).not.toContain(PASSWORD);
  });

  test("wrong current password -> 400 CURRENT_PASSWORD_INCORRECT (not 401), nothing changes", async () => {
    const user = await addUser();
    const old = user.email;
    const res = await post(base, "/change-email", { newEmail: fresh(), currentPassword: "Wrong-Passw0rd!" }, bearer(user));
    expect(res).toMatchObject({ status: 400, body: { error: "CURRENT_PASSWORD_INCORRECT" } });
    expect(user.email).toBe(old);
    expect(repo.audit).toEqual([]);
  });

  test("an email another user has (any case, any tenant) -> 409 EMAIL_TAKEN", async () => {
    const other = await addUser("admin", TENANT_B);
    const user = await addUser();
    const old = user.email;
    const res = await post(base, "/change-email", { newEmail: other.email.toUpperCase(), currentPassword: PASSWORD }, bearer(user));
    expect(res).toMatchObject({ status: 409, body: { error: "EMAIL_TAKEN" } });
    expect(user.email).toBe(old);
    expect(other.email).not.toBe(old);
  });

  test("a concurrent change that wins the unique index -> 409 EMAIL_TAKEN", async () => {
    const user = await addUser();
    repo.raceTaken = true;
    expect(await post(base, "/change-email", { newEmail: fresh(), currentPassword: PASSWORD }, bearer(user))).toMatchObject({ status: 409, body: { error: "EMAIL_TAKEN" } });
  });

  test("the same email (ignoring case/spaces) -> 400 EMAIL_UNCHANGED", async () => {
    const user = await addUser();
    expect(await post(base, "/change-email", { newEmail: ` ${user.email.toUpperCase()}`, currentPassword: PASSWORD }, bearer(user))).toMatchObject({ status: 400, body: { error: "EMAIL_UNCHANGED" } });
  });

  test.each([["not-an-email"], [""], [`${"a".repeat(250)}@x.io`]])("invalid email %p -> 400 VALIDATION_ERROR", async (newEmail) => {
    const user = await addUser();
    expect((await post(base, "/change-email", { newEmail, currentPassword: PASSWORD }, bearer(user))).body).toMatchObject({ error: "VALIDATION_ERROR" });
  });

  test.each([["userId"], ["email"], ["tenantId"], ["role"]])("an identity field (%s) in the body -> 400, no email changes anywhere", async (field) => {
    const user = await addUser();
    const victim = await addUser("admin");
    const [own, theirs] = [user.email, victim.email];
    const value = field === "userId" ? victim.id : field === "email" ? victim.email : field === "tenantId" ? TENANT_B : "admin";
    const res = await post(base, "/change-email", { newEmail: fresh(), currentPassword: PASSWORD, [field]: value }, bearer(user));
    expect(res).toMatchObject({ status: 400, body: { error: "VALIDATION_ERROR" } });
    expect([user.email, victim.email]).toEqual([own, theirs]);
  });

  test("no token -> 401; a service token -> 403 HUMAN_PRINCIPAL_REQUIRED", async () => {
    expect((await post(base, "/change-email", { newEmail: fresh(), currentPassword: PASSWORD })).status).toBe(401);
    const res = await post(base, "/change-email", { newEmail: fresh(), currentPassword: PASSWORD }, `Bearer ${signServiceToken({ id: "service:ai-orchestrator", tenantId: TENANT_A, scopes: ["orchestrator:callback"], jobIds: [] })}`);
    expect(res).toMatchObject({ status: 403, body: { error: "HUMAN_PRINCIPAL_REQUIRED" } });
    expect(repo.audit).toEqual([]);
  });
});
