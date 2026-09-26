import type { Request, Response, NextFunction } from "express";
import { IrEmailService } from "../src/application/notification/services/IrEmailService";
import { IRoleEmailResolver, RoleEmailDirectory } from "../src/application/notification/services/RoleEmailDirectory";
import { INotificationRecipientRepository } from "../src/domain/notification/repositories/INotificationRecipientRepository";
import { ResponsePlan } from "../src/domain/response/entities/ResponsePlan.entity";
import { GetKnowledgeArticleUseCase, SendArticleToIrUseCase, PreviewArticleEmailUseCase } from "../src/application/knowledge/use-cases/KnowledgeArticles.usecases";
import { GetResponseGuideUseCase, SendResponseGuideToIrUseCase } from "../src/application/incident/use-cases/ResponseGuide.usecases";
import { EmailNotificationAdapter } from "../src/infrastructure/notification/EmailNotificationAdapter";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { Playbook } from "../src/domain/playbook/entities/Playbook.entity";
import { Runbook } from "../src/domain/runbook/entities/Runbook.entity";
import { Recommendation } from "../src/domain/recommendation/entities/Recommendation.entity";
import { buildIrEmailRoutes, IR_HANDOFF_SENDER_ROLES } from "../src/presentation/http/routes/ir-email.routes";
import { IrEmailController } from "../src/presentation/http/controllers/IrEmailController";
import { signToken } from "../src/presentation/http/middlewares/auth.middleware";

// No real email is ever sent here: every adapter is an in-memory fake or a nodemailer-shaped fake transporter.
const T = "00000000-0000-0000-0000-000000000001";
const IR = "ir-lead@corp.test";
const SMTP_PASSWORD = "Sup3r-Secret-SMTP-pass";
const PB_ID = "11111111-1111-4111-8111-111111111111";
const RB_ID = "22222222-2222-4222-8222-222222222222";
const INC = "33333333-3333-4333-8333-333333333333";

const playbook = Playbook.create({
  id: PB_ID, tenantId: T, code: "PB-SSH-BRUTEFORCE", name: "SSH Brute Force Response", description: "Contain repeated failed SSH logins.",
  version: "1.0", status: "ACTIVE", steps: [{ id: "s2", stepOrder: 2, title: "Block source", description: "Deny the source IP" }, { id: "s1", stepOrder: 1, title: "Validate", description: null }],
});
const runbook = Runbook.create({
  id: RB_ID, tenantId: T, code: "RB-BLOCK-IP", name: "Block Source IP", version: "1.2", status: "ACTIVE", description: "Deny traffic from an IP.",
  trigger: "Brute force source identified", preconditions: ["IP present in evidence"], objective: "Stop the source", procedure: ["Confirm the IP", "Apply deny rule"],
  decisionPoints: [], expectedResult: "Source blocked", escalation: null, verificationCriteria: ["Connections rejected"], createdAt: new Date(), updatedAt: new Date(),
});
const recommendation = Recommendation.create({
  id: "rec-1", tenantId: T, incidentId: INC, investigationNumber: 1, recommendationNumber: 2, status: "VALIDATED", summary: "Block 172.31.250.50.",
  createdBy: "LlmRecommendationAgent/v2.0.0", snapshotId: "snap-1",
  steps: [{ id: "st-1", stepOrder: 1, title: "Block Source IP — 172.31.250.50", objective: null, actionId: "a-1", target: "172.31.250.50", reason: "Origin of the SSH brute force",
    evidence: [], sourceRunbookId: RB_ID, precondition: null, expectedResult: null, requiresApproval: false, status: "PENDING",
    instructions: [{ order: 2, instruction: "Apply a deny rule", target: "172.31.250.50", expectedResult: "Rule applied" }, { order: 1, instruction: "Confirm the IP", target: null, expectedResult: null }],
    verificationCriteria: "Connections rejected" }],
});

const PLAN_ID = "55555555-5555-4555-8555-555555555555";
const OTHER_PLAN_ID = "66666666-6666-4666-8666-666666666666";
// Ticket from the older, superseded recommendation #1 (its own step), to prove the guide follows the ticket.
const oldRecommendation = Recommendation.create({
  id: "rec-old", tenantId: T, incidentId: INC, investigationNumber: 1, recommendationNumber: 1, status: "SUPERSEDED", summary: "Old plan.",
  createdBy: "LlmRecommendationAgent/v2.0.0", snapshotId: null,
  steps: [
    { id: "old-a", stepOrder: 1, title: "Block Source IP — 172.31.250.50", objective: null, actionId: "a-1", target: "172.31.250.50", reason: "Old reason",
      evidence: [], sourceRunbookId: RB_ID, precondition: null, expectedResult: null, requiresApproval: false, status: "PENDING",
      instructions: [{ order: 1, instruction: "Old instruction for the ticket step", target: null, expectedResult: null }], verificationCriteria: null },
    { id: "old-b", stepOrder: 2, title: "Reset credentials — labuser", objective: null, actionId: "a-2", target: "labuser", reason: "Other step",
      evidence: [], sourceRunbookId: null, precondition: null, expectedResult: null, requiresApproval: false, status: "PENDING",
      instructions: [], verificationCriteria: null },
  ],
});
const plan = (id: string, incidentId: string) =>
  ResponsePlan.create({
    id, tenantId: T, incidentId, recommendationId: "rec-old", recommendationStepId: "old-a", actionId: "a-1", target: "172.31.250.50", reason: "r",
    expectedResult: null, approvalStatus: "NOT_REQUIRED", assignedRole: "SOC", assignedTo: null, status: "READY_FOR_EXECUTION",
    executionResult: null, executedAt: null, completedAt: null, createdAt: new Date(), updatedAt: new Date(),
  } as never);

class MemoryRecipients implements INotificationRecipientRepository {
  rows = new Map<string, { role: string; email: string; updatedBy: string | null; updatedAt: Date }>();
  async findAll() { return [...this.rows.values()]; }
  async findByRole(_t: string, role: string) { return this.rows.get(role) ?? null; }
  async upsert(_t: string, role: string, email: string, updatedBy: string) { const r = { role, email, updatedBy, updatedAt: new Date() }; this.rows.set(role, r); return r; }
  async remove(_t: string, role: string) { this.rows.delete(role); }
}

function harness(opts: { irEmail?: string | null; adapter?: EmailNotificationAdapter; resolver?: IRoleEmailResolver } = {}) {
  const sends: { recipient: string; subject?: string; body: string }[] = [];
  const adapter =
    opts.adapter ??
    new EmailNotificationAdapter({ sendMail: async (m: { to: string; subject: string; text: string }) => (sends.push({ recipient: m.to, subject: m.subject, body: m.text }), { messageId: "msg-1" }) } as never, "vigix@corp.test", SMTP_PASSWORD);
  const resolver: IRoleEmailResolver = opts.resolver ?? { resolve: async () => (opts.irEmail === null ? { email: null, source: "none" } : { email: opts.irEmail ?? IR, source: "server" }) };
  const deliveries: Record<string, unknown>[] = [];
  const deliveryRepo = {
    findByEventId: async (eventId: string) =>
      deliveries.map((d, i) => ({ ...d, id: `d-${i + 1}` }) as Record<string, unknown>).filter((d) => d.eventId === eventId) as never[],
    create: async (d: Record<string, unknown>) => (deliveries.push({ ...d }), { id: `d-${deliveries.length}` }),
    updateStatus: async (id: string, u: Record<string, unknown>) => (Object.assign(deliveries[Number(id.slice(2)) - 1], u), {}),
    findById: async () => null,
  };
  const audits: { action: string; actor: string; entity: string; entityId: string; metadata: Record<string, unknown> }[] = [];
  const audit = { record: async (e: never) => void audits.push(e) } as unknown as AuditLogger;
  const service = new IrEmailService(adapter, resolver, deliveryRepo as never, audit);
  const getArticle = new GetKnowledgeArticleUseCase(
    { findById: async (id: string) => (id === PB_ID ? playbook : null) } as never,
    { findById: async (id: string) => (id === RB_ID ? runbook : null) } as never
  );
  const context = {
    getIncidentContext: async (id: string) => (id === INC ? { incidentId: INC, investigationNumber: 1, title: "sshd: brute force", status: "investigating", priority: "medium", alertSeverity: "medium" } : null),
    getMitreMappings: async () => [{ techniqueId: "T1110", tactic: "Credential Access", confidence: 0.85 }],
    getIocs: async () => [{ iocType: "IPV4", iocValue: "172.31.250.50", source: "ALERT", reputationScore: null }],
  };
  const getGuide = new GetResponseGuideUseCase(
    context as never,
    { findAllByIncident: async () => [recommendation, oldRecommendation] } as never,
    { findById: async (id: string) => (id === RB_ID ? runbook : null) } as never,
    { findPlaybook: async () => ({ code: "PB-SSH-BRUTEFORCE", version: "1.0" }) },
    { findById: async (id: string) => (id === PLAN_ID ? plan(PLAN_ID, INC) : id === OTHER_PLAN_ID ? plan(OTHER_PLAN_ID, "77777777-7777-4777-8777-777777777777") : null) } as never
  );
  return {
    sends, deliveries, audits,
    sendArticle: new SendArticleToIrUseCase(getArticle, service, "http://vigix.test"),
    previewArticle: new PreviewArticleEmailUseCase(getArticle, service, "http://vigix.test"),
    service,
    sendGuide: new SendResponseGuideToIrUseCase(getGuide, service, "http://vigix.test"),
  };
}

describe("Send knowledge article to IR", () => {
  test("playbook article: server-side IR recipient, generated subject, full content, delivery + audit", async () => {
    const h = harness();
    const r = await h.sendArticle.execute({ tenantId: T, articleId: PB_ID, actor: "soc-user-1" });
    expect(r.value).toMatchObject({ status: "SENT", recipientRole: "IR_TEAM", recipient: "i***@corp.test", error: null });
    expect(r.value.sentAt).toEqual(expect.any(String));
    expect(h.sends).toHaveLength(1);
    const mail = h.sends[0];
    expect(mail.recipient).toBe(IR);
    expect(mail.subject).toBe("[VIGIX] Playbook PB-SSH-BRUTEFORCE — SSH Brute Force Response");
    for (const part of ["Title: SSH Brute Force Response", "Type: Playbook", "Playbook ID: PB-SSH-BRUTEFORCE", "1. Validate", "2. Block source — Deny the source IP", "Source: VIGIX Knowledge Base"]) {
      expect(mail.body).toContain(part);
    }
    expect(h.deliveries[0]).toMatchObject({ eventType: "ARTICLE_SENT_TO_IR", channel: "email", recipientRole: "IR_TEAM", status: "SENT" });
    expect(h.audits).toEqual([expect.objectContaining({
      action: "ARTICLE_SENT_TO_IR", actor: "soc-user-1", entity: "KnowledgeArticle", entityId: PB_ID,
      metadata: expect.objectContaining({ recipientRole: "IR_TEAM", deliveryStatus: "SENT", articleType: "PLAYBOOK", sentAt: expect.any(String) }),
    })]);
  });

  test("runbook article: procedure in the body; an explicit subject wins but can never inject headers", async () => {
    const h = harness();
    await h.sendArticle.execute({ tenantId: T, articleId: RB_ID, actor: "soc-user-1", subject: "Please review\r\nBcc: attacker@evil.test" });
    expect(h.sends[0].subject).toBe("Please review Bcc: attacker@evil.test");
    expect(h.sends[0].body).toContain("Runbook ID: RB-BLOCK-IP · version 1.2");
    expect(h.sends[0].body).toContain("Procedure:\n  1. Confirm the IP\n  2. Apply deny rule");
  });

  test("unknown article sends nothing and audits nothing", async () => {
    const h = harness();
    expect((await h.sendArticle.execute({ tenantId: T, articleId: "44444444-4444-4444-8444-444444444444", actor: "u" })).error).toBe("ARTICLE_NOT_FOUND");
    expect((await h.sendArticle.execute({ tenantId: T, articleId: "not-a-uuid", actor: "u" })).error).toBe("ARTICLE_NOT_FOUND");
    expect(h.sends).toHaveLength(0);
    expect(h.audits).toHaveLength(0);
  });

  test("preview renders exactly the email that would be sent, without sending", async () => {
    const h = harness();
    const p = await h.previewArticle.execute({ tenantId: T, articleId: RB_ID });
    expect(p.value.article).toMatchObject({ type: "RUNBOOK", code: "RB-BLOCK-IP", title: "Block Source IP" });
    expect(p.value.email.subject).toBe("[VIGIX] Runbook RB-BLOCK-IP — Block Source IP");
    expect(h.sends).toHaveLength(0);
  });
});

describe("Send incident response guide to IR", () => {
  test("guide email carries incident, severity, MITRE, IOC, action, target, instructions and playbook/runbook source", async () => {
    const h = harness();
    const r = await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "soc-user-1" });
    expect(r.value.status).toBe("SENT");
    const { subject, body } = h.sends[0];
    expect(subject).toBe("[VIGIX] Response guide — INC-33333333 sshd: brute force");
    for (const part of [
      `Incident ID: ${INC}`, "Title: sshd: brute force", "Severity: MEDIUM", "T1110 (Credential Access)",
      "IPV4: 172.31.250.50 (source: ALERT)", "1. Block Source IP — 172.31.250.50", "Target: 172.31.250.50",
      "1) Confirm the IP", "2) Apply a deny rule [expected: Rule applied]", "Source runbook: RB-BLOCK-IP — Block Source IP",
      "playbook PB-SSH-BRUTEFORCE v1.0", `/incidents/${INC}`,
    ]) expect(body).toContain(part);
    expect(h.deliveries[0]).toMatchObject({ eventType: "RESPONSE_GUIDE_SENT_TO_IR", incidentId: INC, status: "SENT" });
    expect(h.audits[0]).toMatchObject({ action: "RESPONSE_GUIDE_SENT_TO_IR", actor: "soc-user-1", entity: "Incident", entityId: INC, metadata: { recipientRole: "IR_TEAM", deliveryStatus: "SENT", recommendationId: "rec-1" } });
  });

  test("unknown incident sends nothing", async () => {
    const h = harness();
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: "44444444-4444-4444-8444-444444444444", actor: "u" })).error).toBe("INCIDENT_NOT_FOUND");
    expect(h.sends).toHaveLength(0);
  });
});

describe("IR email failure handling", () => {
  test("missing IR_TEAM_EMAIL (no Settings value, no server default): not sent, still audited", async () => {
    const h = harness({ irEmail: null });
    const r = await h.sendArticle.execute({ tenantId: T, articleId: PB_ID, actor: "soc-user-1" });
    expect(r.value).toMatchObject({ status: "NOT_SENT", error: "IR_TEAM_EMAIL_NOT_CONFIGURED", recipient: null, sentAt: null });
    expect(h.sends).toHaveLength(0);
    expect(h.deliveries).toHaveLength(0);
    expect(h.audits[0].metadata).toMatchObject({ deliveryStatus: "NOT_SENT", error: "IR_TEAM_EMAIL_NOT_CONFIGURED" });
  });

  test("email channel not configured on the server: not sent", async () => {
    const h = harness({ adapter: new EmailNotificationAdapter(null, undefined, undefined) });
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" })).value).toMatchObject({ status: "NOT_SENT", error: "CHANNEL_NOT_CONFIGURED" });
  });

  test("provider failure: FAILED + DELIVERY_FAILED, recorded, and no SMTP secret or full address leaks to the caller or audit", async () => {
    const failing = new EmailNotificationAdapter(
      { sendMail: async () => { throw new Error(`535 auth failed for vigix@corp.test with password ${SMTP_PASSWORD}`); } } as never,
      "vigix@corp.test",
      SMTP_PASSWORD
    );
    const h = harness({ adapter: failing });
    const r = await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "soc-user-1" });
    expect(r.value).toMatchObject({ status: "FAILED", error: "DELIVERY_FAILED", sentAt: null });
    expect(h.deliveries[0]).toMatchObject({ status: "FAILED" });
    expect(h.audits[0].metadata).toMatchObject({ deliveryStatus: "FAILED", error: "DELIVERY_FAILED" });
    const exposed = JSON.stringify({ result: r.value, audit: h.audits, delivery: h.deliveries });
    expect(exposed).not.toContain(SMTP_PASSWORD);
    expect(JSON.stringify({ result: r.value, audit: h.audits })).not.toContain(IR); // caller + audit only ever see the masked address
  });
});

describe("Authorization (existing RBAC: requireRole with the IR hand-off roles)", () => {
  const calls: string[] = [];
  const fake = (name: string) => async (_req: Request, res: Response) => (calls.push(name), void res.status(200).json({ ok: true }));
  const controller = { article: fake("article"), sendArticleToIr: fake("sendArticle"), responseGuide: fake("guide"), sendResponseGuideToIr: fake("sendGuide") } as unknown as IrEmailController;
  const router = buildIrEmailRoutes(controller);

  async function call(method: "get" | "post", path: string, role: string | null) {
    const layer = (router as unknown as { stack: { route?: { path: string; methods: Record<string, boolean>; stack: { handle: (req: Request, res: Response, next: NextFunction) => unknown }[] } }[] }).stack
      .find((l) => l.route?.path === path && l.route.methods[method])!;
    const req = { header: (n: string) => (n.toLowerCase() === "authorization" && role ? `Bearer ${signToken({ id: `user-${role}`, tenantId: T, role })}` : undefined), params: {}, body: {} } as unknown as Request;
    let status = 200;
    const res = { status: (s: number) => ((status = s), res), json: () => res } as unknown as Response;
    for (const { handle } of layer.route!.stack) {
      let proceed = false;
      await handle(req, res, () => void (proceed = true));
      if (!proceed) break;
    }
    return status;
  }

  test.each([
    ["/knowledge/articles/:articleId/send-to-ir", "sendArticle"],
    ["/incidents/:incidentId/send-response-guide", "sendGuide"],
  ])("%s: SOC and admin may send; IR_TEAM, MANAGER and anonymous may not", async (path, handler) => {
    calls.length = 0;
    expect(await call("post", path, null)).toBe(401);
    expect(await call("post", path, "IR_TEAM")).toBe(403);
    expect(await call("post", path, "MANAGER")).toBe(403);
    expect(calls).toEqual([]);
    expect(await call("post", path, "SOC")).toBe(200);
    expect(await call("post", path, "admin")).toBe(200);
    expect(calls).toEqual([handler, handler]);
  });

  test("previews are readable by any signed-in role", async () => {
    expect(await call("get", "/incidents/:incidentId/response-guide", "MANAGER")).toBe(200);
    expect(await call("get", "/knowledge/articles/:articleId", "IR_TEAM")).toBe(200);
    expect(await call("get", "/knowledge/articles/:articleId", null)).toBe(401);
  });

  test("the sender roles are the IR hand-off roles, not an IR-specific hard-coded list", () => {
    expect([...IR_HANDOFF_SENDER_ROLES]).toEqual(["SOC"]);
  });
});

describe("Response guide from a response ticket", () => {
  test("uses the ticket's own recommendation step (even if superseded) and references the ticket", async () => {
    const h = harness();
    const r = await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "soc-user-1", responseId: PLAN_ID });
    expect(r.value.status).toBe("SENT");
    const { subject, body } = h.sends[0];
    expect(subject).toBe("[VIGIX] Response guide — INC-33333333 ticket 55555555 sshd: brute force");
    expect(body).toContain("Old instruction for the ticket step");
    expect(body).not.toContain("Reset credentials — labuser"); // only the ticket's step
    expect(body).toContain(`Response ticket: ${PLAN_ID} · status READY_FOR_EXECUTION`);
    expect(body).toContain(`VIGIX response ticket: http://vigix.test/tickets/${PLAN_ID}`);
    expect(h.audits[0].metadata).toMatchObject({ responseId: PLAN_ID, recommendationId: "rec-old" });
  });

  test("unknown ticket, or a ticket of another incident, is RESPONSE_NOT_FOUND and sends nothing", async () => {
    const h = harness();
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", responseId: "88888888-8888-4888-8888-888888888888" })).error).toBe("RESPONSE_NOT_FOUND");
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", responseId: OTHER_PLAN_ID })).error).toBe("RESPONSE_NOT_FOUND");
    expect(h.sends).toHaveLength(0);
    expect(h.audits).toHaveLength(0);
  });
});

describe("IR_TEAM recipient is resolved at send time (Settings/DB over .env)", () => {
  test("a DB (Settings) recipient overrides IR_TEAM_EMAIL", async () => {
    const repo = new MemoryRecipients();
    await repo.upsert(T, "IR_TEAM", "ir-oncall@corp.test", "soc-user-1");
    const h = harness({ resolver: new RoleEmailDirectory(repo, { IR_TEAM: "ir-env@corp.test" }) });
    await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" });
    expect(h.sends[0].recipient).toBe("ir-oncall@corp.test");
    expect(await h.service.previewRecipient(T)).toEqual({ recipientRole: "IR_TEAM", recipient: "i***@corp.test", source: "settings", emailChannelConfigured: true });
  });

  test("without a DB value the .env IR_TEAM_EMAIL is used; with neither nothing is sent", async () => {
    const withEnv = harness({ resolver: new RoleEmailDirectory(new MemoryRecipients(), { IR_TEAM: "ir-env@corp.test" }) });
    await withEnv.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" });
    expect(withEnv.sends[0].recipient).toBe("ir-env@corp.test");

    const none = harness({ resolver: new RoleEmailDirectory(new MemoryRecipients(), {}) });
    const r = await none.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" });
    expect(r.value).toMatchObject({ status: "NOT_SENT", error: "IR_TEAM_EMAIL_NOT_CONFIGURED" });
    expect(none.sends).toHaveLength(0);
    expect((await none.service.previewRecipient(T)).recipient).toBeNull();
  });

  test("a recipient changed in Settings is used by the very next send (no restart)", async () => {
    const repo = new MemoryRecipients();
    const h = harness({ resolver: new RoleEmailDirectory(repo, { IR_TEAM: "ir-env@corp.test" }) });
    await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" });
    await repo.upsert(T, "IR_TEAM", "ir-new@corp.test", "ir-user-1");
    await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u" });
    expect(h.sends.map((m) => m.recipient)).toEqual(["ir-env@corp.test", "ir-new@corp.test"]);
  });
});

describe("Duplicate-send protection (idempotency key per confirmation dialog)", () => {
  const KEY = "99999999-9999-4999-8999-999999999999";

  test("repeating a SENT request returns the first result and sends nothing again", async () => {
    const h = harness();
    const first = await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY });
    const again = await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY });
    expect(h.sends).toHaveLength(1);
    expect(h.audits).toHaveLength(1);
    expect(first.value).toMatchObject({ status: "SENT", duplicate: false });
    expect(again.value).toMatchObject({ status: "SENT", duplicate: true, deliveryId: first.value.deliveryId, recipient: "i***@corp.test" });
  });

  test("a double click (concurrent requests, same key) sends once; the other is DUPLICATE_IN_PROGRESS", async () => {
    const h = harness();
    const [a, b] = await Promise.all([
      h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY }),
      h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY }),
    ]);
    expect(h.sends).toHaveLength(1);
    expect([a.value.error, b.value.error].sort()).toEqual(["DUPLICATE_IN_PROGRESS", null].sort());
  });

  test("after a provider failure the same key may be retried; different keys are separate sends", async () => {
    let fail = true;
    const sends: string[] = [];
    const flaky = new EmailNotificationAdapter({ sendMail: async (m: { to: string }) => { if (fail) throw new Error("smtp down"); sends.push(m.to); return { messageId: "m" }; } } as never, "vigix@corp.test", SMTP_PASSWORD);
    const h = harness({ adapter: flaky });
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY })).value.status).toBe("FAILED");
    fail = false;
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: KEY })).value).toMatchObject({ status: "SENT", duplicate: false });
    expect((await h.sendGuide.execute({ tenantId: T, incidentId: INC, actor: "u", idempotencyKey: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" })).value.status).toBe("SENT");
    expect(sends).toHaveLength(2);
    expect(h.audits.map((a) => a.metadata.deliveryStatus)).toEqual(["FAILED", "SENT", "SENT"]);
  });
});
