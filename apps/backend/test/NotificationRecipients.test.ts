import { INotificationRecipientRepository, NotificationRecipientRecord } from "../src/domain/notification/repositories/INotificationRecipientRepository";
import { RoleEmailDirectory } from "../src/application/notification/services/RoleEmailDirectory";
import {
  ListNotificationRecipientsUseCase,
  UpdateNotificationRecipientUseCase,
  maskEmail,
} from "../src/application/settings/use-cases/NotificationRecipients.usecases";
import { MultiChannelNotificationDispatcher } from "../src/infrastructure/notification/MultiChannelNotificationDispatcher";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { NotificationEvent } from "../src/application/notification/events/NotificationEvent";
import { buildSettingsRoutes, canEditNotificationRecipients } from "../src/presentation/http/routes/settings.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";
import { SettingsController } from "../src/presentation/http/controllers/SettingsController";

const T = "tenant-1";

class MemoryRecipients implements INotificationRecipientRepository {
  rows = new Map<string, NotificationRecipientRecord>();
  fail = false;
  async findAll(tenantId: string) {
    return [...this.rows.entries()].filter(([k]) => k.startsWith(`${tenantId}:`)).map(([, v]) => v);
  }
  async findByRole(tenantId: string, role: string) {
    if (this.fail) throw new Error("db down");
    return this.rows.get(`${tenantId}:${role}`) ?? null;
  }
  async upsert(tenantId: string, role: string, email: string, updatedBy: string) {
    const r = { role, email, updatedBy, updatedAt: new Date("2026-09-24T00:00:00Z") };
    this.rows.set(`${tenantId}:${role}`, r);
    return r;
  }
  async remove(tenantId: string, role: string) {
    this.rows.delete(`${tenantId}:${role}`);
  }
}

const serverDefaults = { SOC: "soc@server.test", IR_TEAM: "ir@server.test" }; // ADMIN has no server default
const audit = () => {
  const calls: unknown[] = [];
  return { logger: { record: async (e: unknown) => void calls.push(e) } as unknown as AuditLogger, calls };
};

describe("RoleEmailDirectory", () => {
  test("Settings value wins over the server default", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert(T, "SOC", "soc-lead@corp.test", "admin-1");
    expect(await new RoleEmailDirectory(repo, serverDefaults).resolve(T, "SOC")).toEqual({ email: "soc-lead@corp.test", source: "settings" });
  });
  test("no Settings value falls back to the server default; none at all is 'none'", async () => {
    const d = new RoleEmailDirectory(new MemoryRecipients(), serverDefaults);
    expect(await d.resolve(T, "IR_TEAM")).toEqual({ email: "ir@server.test", source: "server" });
    expect(await d.resolve(T, "ADMIN")).toEqual({ email: null, source: "none" });
  });
  test("Settings are per tenant", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert("other-tenant", "SOC", "x@other.test", "admin-2");
    expect((await new RoleEmailDirectory(repo, serverDefaults).resolve(T, "SOC")).email).toBe("soc@server.test");
  });
  test("a Settings read failure never stops notifications — it falls back to the server default", async () => {
    const repo = new MemoryRecipients();
    repo.fail = true;
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    expect(await new RoleEmailDirectory(repo, serverDefaults).resolve(T, "SOC")).toEqual({ email: "soc@server.test", source: "server" });
    spy.mockRestore();
  });
});

describe("Notification recipient use cases", () => {
  test("list shows every role with its source; non-editors only see masked addresses and never the server value", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert(T, "IR_TEAM", "ir-lead@corp.test", "admin-1");
    const list = new ListNotificationRecipientsUseCase(repo, new RoleEmailDirectory(repo, serverDefaults));
    const admin = await list.execute({ tenantId: T, viewerCanEdit: true });
    expect(admin.map((r) => [r.role, r.email, r.source, r.masked])).toEqual([
      ["SOC", "soc@server.test", "server", false],
      ["IR_TEAM", "ir-lead@corp.test", "settings", false],
      // Spec: ADMIN is a notification recipient role too (system administration contact). No Manager role exists.
      ["ADMIN", null, "none", false],
    ]);
    const soc = await list.execute({ tenantId: T, viewerCanEdit: false });
    expect(soc.map((r) => r.email)).toEqual(["s***@server.test", "i***@corp.test", null]);
    expect(soc.every((r) => !r.email || r.masked)).toBe(true);
  });

  test("update validates role and email, normalises, persists and audits old → new", async () => {
    const repo = new MemoryRecipients();
    const { logger, calls } = audit();
    const update = new UpdateNotificationRecipientUseCase(repo, logger);
    // ADMIN became a valid recipient role (spec); an unknown role is still rejected.
    expect((await update.execute({ tenantId: T, role: "ROOT", email: "a@b.test", updatedBy: "u" })).error).toBe("INVALID_ROLE");
    // The Manager role was removed: it is no longer a recipient role.
    expect((await update.execute({ tenantId: T, role: "MANAGER", email: "boss@corp.test", updatedBy: "u" })).error).toBe("INVALID_ROLE");
    expect((await update.execute({ tenantId: T, role: "SOC", email: "not-an-email", updatedBy: "u" })).error).toBe("INVALID_EMAIL");
    expect((await update.execute({ tenantId: T, role: "SOC", email: "a@b.test\r\nBcc: x@evil.test", updatedBy: "u" })).error).toBe("INVALID_EMAIL");
    expect(calls).toHaveLength(0);

    const ok = await update.execute({ tenantId: T, role: "IR_TEAM", email: "  IR-Lead@Corp.Test ", updatedBy: "admin-1" });
    expect(ok.value).toEqual({ role: "IR_TEAM", email: "ir-lead@corp.test" });
    expect((await repo.findByRole(T, "IR_TEAM"))?.email).toBe("ir-lead@corp.test");
    expect(calls[0]).toMatchObject({ action: "NOTIFICATION_RECIPIENT_UPDATED", actor: "admin-1", entityId: "IR_TEAM", metadata: { previousEmail: null, newEmail: "ir-lead@corp.test" } });
  });

  test("clearing (null or blank) removes the Settings value, reverting to the server default, and is audited", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert(T, "SOC", "soc-lead@corp.test", "admin-1");
    const { logger, calls } = audit();
    await new UpdateNotificationRecipientUseCase(repo, logger).execute({ tenantId: T, role: "SOC", email: null, updatedBy: "admin-1" });
    expect(await repo.findByRole(T, "SOC")).toBeNull();
    expect((await new RoleEmailDirectory(repo, serverDefaults).resolve(T, "SOC")).email).toBe("soc@server.test");
    expect(calls[0]).toMatchObject({ action: "NOTIFICATION_RECIPIENT_CLEARED", metadata: { previousEmail: "soc-lead@corp.test", newEmail: null } });
  });

  test("maskEmail hides the local part", () => {
    expect(maskEmail("kanok@corp.test")).toBe("k***@corp.test");
    expect(maskEmail("broken")).toBe("***");
  });
});

describe("MultiChannelNotificationDispatcher uses the resolved role email", () => {
  const event = (roles: ("SOC" | "IR_TEAM" | "ADMIN")[]): NotificationEvent =>
    ({ eventType: "RESPONSE_COMPLETED", eventId: "evt-1", timestamp: "2026-09-24T00:00:00Z", tenantId: T,
      recipient: { roles, channels: ["email"] }, incident: { id: "inc-1" }, ticket: { id: "t-1", action: null }, links: { ticket: "http://vigix.test/tickets/t-1" } } as unknown as NotificationEvent);
  const setup = (repo: MemoryRecipients) => {
    const sent: string[] = [];
    const email = { isConfigured: () => true, send: async (m: { recipient: string }) => (sent.push(m.recipient), { status: "SENT" as const }) };
    const off = { isConfigured: () => false, send: async () => ({ status: "FAILED" as const }) };
    const deliveries = { findByEventId: async () => [], create: async () => ({ id: "d-1" }), updateStatus: async () => ({}) };
    const d = new MultiChannelNotificationDispatcher(email as never, off as never, off as never, deliveries as never, new RoleEmailDirectory(repo, serverDefaults));
    return { d, sent };
  };

  test("sends to the Settings address when set, the server default otherwise, and skips a role with neither", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert(T, "SOC", "soc-lead@corp.test", "admin-1");
    const { d, sent } = setup(repo);
    await d.emit(event(["SOC", "IR_TEAM", "ADMIN"]));
    expect(sent).toEqual(["soc-lead@corp.test", "ir@server.test"]);
  });

  test("a change in Settings applies to the next notification without a restart", async () => {
    const repo = new MemoryRecipients();
    const { d, sent } = setup(repo);
    await d.emit(event(["SOC"]));
    await repo.upsert(T, "SOC", "new-soc@corp.test", "admin-1");
    await d.emit({ ...event(["SOC"]), eventId: "evt-2" });
    expect(sent).toEqual(["soc@server.test", "new-soc@corp.test"]);
  });
});

describe("Who may edit notification recipients (route gate)", () => {
  const calls: string[] = [];
  const router = buildSettingsRoutes({
    notificationRecipients: async (_req: unknown, res: { status: (n: number) => { json: (b: unknown) => void } }) => (calls.push("get"), res.status(200).json({})),
    updateNotificationRecipient: async (_req: unknown, res: { status: (n: number) => { json: (b: unknown) => void } }) => (calls.push("put"), res.status(200).json({})),
  } as unknown as SettingsController) as unknown as { stack: { route?: { methods: Record<string, boolean>; stack: { handle: (...a: unknown[]) => unknown }[] } }[] };

  async function call(method: "get" | "put", role: string | null): Promise<number> {
    const layer = router.stack.find((l) => l.route?.methods[method])!;
    const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `u-${role}`, tenantId: T, role })}` : undefined), params: { role: "SOC" }, body: {} };
    let status = 200;
    const res = { status: (s: number) => ((status = s), res), json: () => res };
    for (const { handle } of layer.route!.stack) {
      let next = false;
      await handle(req, res, () => void (next = true));
      if (!next) break;
    }
    return status;
  }

  test("SOC, IR_TEAM and admin may change recipients; a retired MANAGER token and anonymous may not", async () => {
    calls.length = 0;
    expect(await call("put", "SOC")).toBe(200);
    expect(await call("put", "IR_TEAM")).toBe(200);
    expect(await call("put", "admin")).toBe(200);
    expect(await call("put", "MANAGER")).toBe(403);
    expect(await call("put", null)).toBe(401);
    expect(calls).toEqual(["put", "put", "put"]);
  });

  test("editors see full addresses; other signed-in roles see masked ones", () => {
    expect(["SOC", "IR_TEAM", "admin"].map(canEditNotificationRecipients)).toEqual([true, true, true]);
    expect(["MANAGER", undefined].map(canEditNotificationRecipients)).toEqual([false, false]);
  });
});
