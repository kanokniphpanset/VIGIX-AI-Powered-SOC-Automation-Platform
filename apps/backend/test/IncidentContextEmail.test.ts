import { IrEmailService } from "../src/application/notification/services/IrEmailService";
import { IRoleEmailResolver } from "../src/application/notification/services/RoleEmailDirectory";
import {
  IncidentContextEmailUseCase,
  IncidentEmailContext,
  buildContextEmail,
} from "../src/application/notification/use-cases/IncidentContextEmail.usecase";
import { EmailNotificationAdapter } from "../src/infrastructure/notification/EmailNotificationAdapter";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { buildIncidentEmailRoutes } from "../src/presentation/http/routes/incident-email.routes";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";

// No real email is sent: nodemailer-shaped fake transporter + in-memory deliveries.
const T = "00000000-0000-0000-0000-000000000001";
const INC = "33333333-3333-4333-8333-333333333333";
const ADDR: Record<string, string> = { SOC: "soc@corp.test", IR_TEAM: "ir@corp.test", ADMIN: "ops@corp.test" };

const ctx: IncidentEmailContext = {
  id: INC, title: "sshd: brute force", status: "investigating", priority: "critical", investigationNumber: 2, openedAt: "2026-09-25T00:00:00.000Z",
  severity: "CRITICAL", responsibleRole: "SOC", aiSummary: "Repeated failed SSH logins from 203.0.113.9.", mitre: ["T1110"],
  iocs: [{ type: "IPV4", value: "203.0.113.9" }],
  recommendation: { number: 2, status: "VALIDATED", summary: "Block 203.0.113.9." },
  tickets: [{ id: "t1", action: "Block Source IP", target: "203.0.113.9", status: "PENDING_IR_DECISION", executorRole: "IR_TEAM",
    approvals: [{ role: "IR_TEAM", stepOrder: 1, status: "pending", decidedAt: null }], verification: null }],
};

function harness(opts: { missing?: string } = {}) {
  const sends: { to: string; subject: string; text: string }[] = [];
  const adapter = new EmailNotificationAdapter({ sendMail: async (m: { to: string; subject: string; text: string }) => (sends.push(m), { messageId: "m1" }) } as never, "vigix@corp.test", "smtp-pass");
  const resolver: IRoleEmailResolver = { resolve: async (_t, role) => (role === opts.missing ? { email: null, source: "none" } : { email: ADDR[role], source: "settings" }) };
  const deliveries: Record<string, unknown>[] = [];
  const deliveryRepo = {
    findByEventId: async (eventId: string) => deliveries.map((d, i) => ({ ...d, id: `d-${i + 1}` }) as Record<string, unknown>).filter((d) => d.eventId === eventId) as never[],
    create: async (d: Record<string, unknown>) => (deliveries.push({ ...d }), { id: `d-${deliveries.length}` }),
    updateStatus: async (id: string, u: Record<string, unknown>) => (Object.assign(deliveries[Number(id.slice(2)) - 1], u), {}),
    findById: async () => null,
  };
  const audits: { action: string; metadata: Record<string, unknown> }[] = [];
  const audit = { record: async (e: never) => void audits.push(e) } as unknown as AuditLogger;
  const service = new IrEmailService(adapter, resolver, deliveryRepo as never, audit);
  const uc = new IncidentContextEmailUseCase({ read: async (_t, id) => (id === INC ? ctx : null) }, service, audit, "http://vigix.test");
  return { uc, sends, deliveries, audits };
}

const KEY = "9b2c1e4a-1111-4222-8333-444455556666";

describe("Role-context incident email", () => {
  test("content follows the SENDER's role (SOC investigation / IR response with the IR decision)", () => {
    const soc = buildContextEmail(ctx, "INVESTIGATION", null, "http://x");
    expect(soc.subject).toMatch(/^\[VIGIX\] Investigation update: INC-33333333/);
    expect(soc.body).toContain("INVESTIGATION CONTEXT (SOC)");
    expect(soc.body).toContain("IPV4 203.0.113.9");
    expect(soc.body).toContain("Severity: CRITICAL");
    expect(soc.body).not.toMatch(/risk/i);
    const ir = buildContextEmail(ctx, "RESPONSE", null, "http://x");
    expect(ir.body).toContain("RESPONSE CONTEXT (IR)");
    expect(ir.body).toContain("Block Source IP → 203.0.113.9: PENDING_IR_DECISION (executor IR_TEAM) · IR decision pending");
    const note = buildContextEmail(ctx, "RESPONSE", "Please review today", "http://x");
    expect(note.body).toContain("Note from sender: Please review today");
    for (const e of [soc, ir, note]) {
      expect(e.body).toContain("It does not approve, execute or close anything.");
      expect(e.body).not.toMatch(/manager/i);
    }
  });

  test("never invents facts: missing owner / AI / tickets are stated as missing", () => {
    const bare = { ...ctx, aiSummary: null, responsibleRole: null, iocs: [], mitre: [], recommendation: null, tickets: [] };
    expect(buildContextEmail(bare, "INVESTIGATION", null, "x").body).toMatch(/Severity: CRITICAL[\s\S]*not assigned yet[\s\S]*no AI analysis stored yet[\s\S]*none mapped[\s\S]*none recorded[\s\S]*none yet/);
    expect(buildContextEmail(bare, "RESPONSE", null, "x").body).toContain("No response ticket exists for this incident yet.");
  });

  test("SOC (investigation context) emails IR_TEAM at its configured address; delivery + EMAIL_SENT audit; recipient masked", async () => {
    const h = harness();
    const r = await h.uc.send({ tenantId: T, incidentId: INC, actor: "u-soc", senderRole: "SOC", recipientRole: "IR_TEAM", note: null, idempotencyKey: KEY });
    expect(r.value).toMatchObject({ status: "SENT", recipientRole: "IR_TEAM", recipient: "i***@corp.test", context: "INVESTIGATION", duplicate: false });
    expect(h.sends[0].to).toBe("ir@corp.test");
    expect(h.deliveries[0]).toMatchObject({ eventType: "INCIDENT_CONTEXT_EMAIL", recipientRole: "IR_TEAM", status: "SENT" });
    expect(h.audits.map((a) => a.action)).toEqual(["INCIDENT_CONTEXT_EMAIL", "EMAIL_SENT"]);
    expect(JSON.stringify(h.audits)).not.toContain("ir@corp.test");
    expect(JSON.stringify(h.audits)).not.toContain("smtp-pass");
  });

  test("duplicate click (same idempotency key) sends once and audits once", async () => {
    const h = harness();
    await h.uc.send({ tenantId: T, incidentId: INC, actor: "u", senderRole: "SOC", recipientRole: "ADMIN", note: null, idempotencyKey: KEY });
    const again = await h.uc.send({ tenantId: T, incidentId: INC, actor: "u", senderRole: "SOC", recipientRole: "ADMIN", note: null, idempotencyKey: KEY });
    expect(again.value).toMatchObject({ status: "SENT", duplicate: true });
    expect(h.sends).toHaveLength(1);
    expect(h.audits.filter((a) => a.action === "EMAIL_SENT")).toHaveLength(1);
  });

  test("recipient role without an address -> NOT_SENT RECIPIENT_NOT_CONFIGURED + EMAIL_SEND_FAILED audit", async () => {
    const h = harness({ missing: "ADMIN" });
    const r = await h.uc.send({ tenantId: T, incidentId: INC, actor: "u", senderRole: "IR_TEAM", recipientRole: "ADMIN", note: null, idempotencyKey: KEY });
    expect(r.value).toMatchObject({ status: "NOT_SENT", error: "RECIPIENT_NOT_CONFIGURED" });
    expect(h.sends).toHaveLength(0);
    expect(h.audits.map((a) => a.action)).toContain("EMAIL_SEND_FAILED");
  });

  test("unknown incident / invalid recipient role / unknown sender role are refused", async () => {
    const h = harness();
    expect((await h.uc.preview({ tenantId: T, incidentId: "nope", senderRole: "SOC", recipientRole: "IR_TEAM", note: null })).error).toBe("INCIDENT_NOT_FOUND");
    expect((await h.uc.preview({ tenantId: T, incidentId: INC, senderRole: "SOC", recipientRole: "CEO", note: null })).error).toBe("INVALID_RECIPIENT_ROLE");
    expect((await h.uc.preview({ tenantId: T, incidentId: INC, senderRole: "AI", recipientRole: "IR_TEAM", note: null })).error).toBe("SENDER_ROLE_NOT_ALLOWED");
    // The Manager role was removed: neither a recipient nor a sender any more.
    expect((await h.uc.preview({ tenantId: T, incidentId: INC, senderRole: "SOC", recipientRole: "MANAGER", note: null })).error).toBe("INVALID_RECIPIENT_ROLE");
    expect((await h.uc.preview({ tenantId: T, incidentId: INC, senderRole: "MANAGER", recipientRole: "IR_TEAM", note: null })).error).toBe("SENDER_ROLE_NOT_ALLOWED");
  });

  describe("route", () => {
    type Layer = { route?: { path: string; methods: Record<string, boolean>; stack: { handle: (...a: unknown[]) => unknown }[] } };
    async function post(role: string | null, body: Record<string, unknown>) {
      const h = harness();
      const router = buildIncidentEmailRoutes(h.uc) as unknown as { stack: Layer[] };
      const layer = router.stack.find((l) => l.route?.methods.post)!;
      const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `u-${role}`, tenantId: T, role })}` : undefined), params: { incidentId: INC }, body, query: {} };
      let status = 200;
      const res = { headersSent: false, status: (s: number) => ((status = s), res), json: () => res };
      for (const { handle } of layer.route!.stack) {
        let next = false;
        await handle(req, res, () => void (next = true));
        if (!next) break;
      }
      return { status, sends: h.sends };
    }

    test("every workspace role may send; a retired MANAGER token and anonymous may not; a client-supplied address is rejected", async () => {
      for (const role of ["SOC", "IR_TEAM", "admin"]) expect((await post(role, { recipientRole: "SOC", idempotencyKey: KEY })).status).toBe(200);
      expect((await post("MANAGER", { recipientRole: "SOC", idempotencyKey: KEY })).status).toBe(403);
      expect((await post(null, { recipientRole: "SOC", idempotencyKey: KEY })).status).toBe(401);
      const spoof = await post("SOC", { recipientRole: "SOC", idempotencyKey: KEY, recipient: "attacker@evil.test" });
      expect(spoof.status).toBe(400);
      expect(spoof.sends).toHaveLength(0);
    });
  });
});
