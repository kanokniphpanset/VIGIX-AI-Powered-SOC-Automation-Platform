import { InAppNotifier, InAppRecordingDispatcher, IN_APP_ROLES } from "../src/application/notification/services/InAppNotifier";
import { IrEmailService } from "../src/application/notification/services/IrEmailService";
import { CreateInAppNotificationData, IInAppNotificationRepository } from "../src/domain/notification/repositories/IInAppNotificationRepository";
import type { NotificationEvent } from "../src/application/notification/events/NotificationEvent";

/** In-app notifications (header bell): role-aware, persistent, and written for every workflow event and every sent email. */
function repo(fail = false) {
  const rows: CreateInAppNotificationData[] = [];
  const repository: IInAppNotificationRepository = {
    createMany: async (r) => {
      if (fail) throw new Error("db down");
      rows.push(...r);
    },
    list: async () => ({ items: [], unread: 0 }),
    markRead: async () => 0,
  };
  return { rows, repository };
}

const event = (eventType: NotificationEvent["eventType"], extra: Partial<NotificationEvent> = {}): NotificationEvent =>
  ({
    eventType,
    eventId: "e1",
    timestamp: new Date().toISOString(),
    tenantId: "t1",
    recipient: { roles: ["IR_TEAM"], channels: ["email"] },
    incident: { id: "inc-1", title: "Suspicious PowerShell", priority: "high", investigationNumber: 1 },
    links: {},
    ...extra,
  }) as NotificationEvent;

describe("InAppNotifier — who sees what", () => {
  it("APPROVAL_APPROVED (the IR decision) reaches SOC (read-only) and IR — the email itself still goes only to IR", async () => {
    const { rows, repository } = repo();
    const inner = { emit: jest.fn().mockResolvedValue(undefined) };
    const dispatcher = new InAppRecordingDispatcher(inner, new InAppNotifier(repository));
    const e = event("APPROVAL_APPROVED", { approval: { id: "a1", role: "IR_TEAM", status: "approved", reason: "r", decidedBy: "ir", comment: "ok" } });
    await dispatcher.emit(e);
    expect(rows.map((r) => r.recipientRole).sort()).toEqual(["IR_TEAM", "SOC"]);
    expect(rows[0]).toMatchObject({ tenantId: "t1", eventType: "APPROVAL_APPROVED", incidentId: "inc-1", link: "/incidents/inc-1", title: expect.stringContaining("IR APPROVED") });
    expect(inner.emit).toHaveBeenCalledWith(e); // delivery (email) unchanged
  });

  it("APPROVAL_REQUIRED (a re-opened IR decision) goes to IR only, linking to the tickets awaiting the IR decision", async () => {
    const { rows, repository } = repo();
    await new InAppNotifier(repository).recordEvent(event("APPROVAL_REQUIRED", { recipient: { roles: ["IR_TEAM"], channels: ["email"] }, approval: { id: "a1", role: "IR_TEAM", status: "pending", reason: "r", decidedBy: null, comment: null } }));
    expect(rows.map((r) => r.recipientRole).sort()).toEqual(["IR_TEAM"]);
    expect(rows[0].link).toBe("/tickets?queue=awaiting-decision");
  });

  it("RESPONSE_ASSIGNED links to the ticket and reaches IR + SOC", async () => {
    const { rows, repository } = repo();
    await new InAppNotifier(repository).recordEvent(
      event("RESPONSE_ASSIGNED", { ticket: { id: "rp-1", incidentId: "inc-1", status: "PENDING_IR_DECISION", approvalStatus: "PENDING", action: { id: "x", name: "Block IP", code: "ACT" } as never, target: "1.2.3.4", runbook: null, assignedRole: "IR_TEAM" } })
    );
    expect(rows.map((r) => r.recipientRole).sort()).toEqual(["IR_TEAM", "SOC"]);
    expect(rows[0]).toMatchObject({ responseId: "rp-1", link: "/tickets/rp-1", title: expect.stringContaining("awaiting IR decision") });
    expect(rows[0].title).toContain("Block IP");
  });

  it("matrix: escalation and resolution reach every workflow role; a new incident reaches the SOC", () => {
    expect(IN_APP_ROLES.INCIDENT_ESCALATED).toEqual(["SOC", "IR_TEAM"]);
    expect(IN_APP_ROLES.INCIDENT_RESOLVED).toEqual(["SOC", "IR_TEAM"]);
    expect(Object.values(IN_APP_ROLES).flat()).not.toContain("MANAGER");
    expect(IN_APP_ROLES.NEW_INCIDENT).toEqual(["SOC"]);
  });

  it("a storage failure never breaks the workflow or the email delivery", async () => {
    const { repository } = repo(true);
    const inner = { emit: jest.fn().mockResolvedValue(undefined) };
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    await expect(new InAppRecordingDispatcher(inner, new InAppNotifier(repository)).emit(event("RESPONSE_COMPLETED"))).resolves.toBeUndefined();
    spy.mockRestore();
    expect(inner.emit).toHaveBeenCalled();
  });
});

describe("IrEmailService — every email actually sent has an in-app notification", () => {
  function emailWorld(sendStatus: "SENT" | "FAILED", configured = true) {
    const { rows, repository } = repo();
    const deliveries: Array<{ id: string; eventId: string; status: string; recipient: string; sentAt: Date | null }> = [];
    const service = new IrEmailService(
      { isConfigured: () => configured, send: async () => ({ status: sendStatus, channel: "email", deliveredAt: new Date() }) } as never,
      { resolve: async () => ({ email: "ir@corp.test", source: "ENV" }) } as never,
      {
        create: async (d: { eventId: string; recipient: string }) => {
          const row = { id: `d${deliveries.length + 1}`, eventId: d.eventId, status: "PENDING", recipient: d.recipient, sentAt: null };
          deliveries.push(row);
          return row;
        },
        findByEventId: async (eventId: string) => deliveries.filter((d) => d.eventId === eventId),
        updateStatus: async (id: string, u: { status: string }) => Object.assign(deliveries.find((d) => d.id === id)!, u),
      } as never,
      { record: async () => undefined } as never,
      new InAppNotifier(repository)
    );
    const send = (key = "k1") =>
      service.send({ tenantId: "t1", actor: "soc-1", action: "INCIDENT_CONTEXT_EMAIL", entity: "Incident", entityId: "inc-1", incidentId: "inc-1", subject: "INC-1 needs IR", body: "b", idempotencyKey: key, recipientRole: "IR_TEAM" });
    return { rows, send };
  }

  it("SOC emails IR -> IR gets an IR_NOTIFIED bell entry for the incident", async () => {
    const w = emailWorld("SENT");
    expect((await w.send()).status).toBe("SENT");
    expect(w.rows).toEqual([expect.objectContaining({ recipientRole: "IR_TEAM", eventType: "IR_NOTIFIED", incidentId: "inc-1", title: "Email to IR_TEAM: INC-1 needs IR", link: "/incidents/inc-1" })]);
  });

  it("a repeated (idempotent) send does not duplicate the bell entry; a failed or unconfigured send creates none", async () => {
    const ok = emailWorld("SENT");
    await ok.send("same");
    await ok.send("same");
    expect(ok.rows).toHaveLength(1);
    const failed = emailWorld("FAILED");
    await failed.send();
    expect(failed.rows).toEqual([]);
    const off = emailWorld("SENT", false);
    await off.send();
    expect(off.rows).toEqual([]);
  });
});
