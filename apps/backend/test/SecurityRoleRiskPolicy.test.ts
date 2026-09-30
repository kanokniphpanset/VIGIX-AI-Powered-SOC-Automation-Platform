import express from "express";
import jwt from "jsonwebtoken";
import { AddressInfo } from "node:net";

import { POLICIES } from "../prisma/seeds/policy.seed";
import { Policy } from "../src/domain/policy/entities/Policy.entity";
import { PolicyRule } from "../src/domain/policy/entities/PolicyRule.entity";
import { IPolicyRepository } from "../src/domain/policy/repositories/IPolicyRepository";
import { PolicyEvaluator } from "../src/infrastructure/policy-engine/PolicyEvaluator";
import { PolicyIncidentIntake } from "../src/infrastructure/policy-engine/PolicyIncidentIntake";
import { IngestAlertFromSiemUseCase } from "../src/application/alert/use-cases/IngestAlertFromSiem.usecase";
import { CreateIncidentUseCase } from "../src/application/incident/use-cases/CreateIncident.usecase";
import { ReturnDueMonitoredAlertsUseCase } from "../src/application/triage/MonitoredAlertReview.usecase";
import { InAppNotifier } from "../src/application/notification/services/InAppNotifier";
import { UpdateIncidentStatusUseCase } from "../src/application/incident/use-cases/UpdateIncidentStatus.usecase";
import { TriageAlertUseCase, DecideIncidentNotificationUseCase, ValidateIncidentSeverityUseCase } from "../src/application/triage/SocTriage.usecases";
import { NotificationDecisionService } from "../src/application/triage/NotificationDecisionService";
import { IrEmailService } from "../src/application/notification/services/IrEmailService";
import { IncidentAssignmentService } from "../src/application/incident/services/IncidentAssignmentService";
import { Alert, AlertStatus, AlertTriage } from "../src/domain/alert/entities/Alert.entity";
import { IAlertRepository } from "../src/domain/alert/repositories/IAlertRepository";
import { AlertAlreadyClosedError, IIncidentRepository } from "../src/domain/incident/repositories/IIncidentRepository";
import { buildResponseRoutes } from "../src/presentation/http/routes/response.routes";
import { buildApprovalRoutes } from "../src/presentation/http/routes/approval.routes";
import { buildSocTriageRoutes } from "../src/presentation/http/routes/soc-triage.routes";

/**
 * Two-role workflow (SOC + IR_TEAM), severity from the Wazuh rule:
 *   LOW alert -> stored only, never in the SOC workflow | MEDIUM -> Alert Inbox, SOC review (no claim)
 *   HIGH / CRITICAL alert -> incident opened automatically + AI job; SOC investigates
 *   LOW email: SOC chooses SEND (EMAIL_SENT, duplicate-protected) or SKIP (EMAIL_SKIPPED) — never automatic
 *   severity validation (human confirm / correct, Policy re-evaluates); RESOLVED only through verification; AI can neither approve nor execute (RBAC)
 * REAL: PolicyEvaluator over the canonical seed rules, IrEmailService. FAKE: persistence, SMTP.
 */

const TENANT = "00000000-0000-0000-0000-000000000001";

const policies: Policy[] = POLICIES.map((p, i) =>
  Policy.create({
    id: `pol-${i}`,
    tenantId: TENANT,
    code: p.code,
    name: p.name,
    description: p.description,
    type: p.type,
    enabled: true,
    version: 1,
    precedence: p.precedence,
    createdAt: new Date(),
    updatedAt: new Date(),
    rules: p.rules.map((r, j) =>
      PolicyRule.create({ id: `rule-${i}-${j}`, policyId: `pol-${i}`, condition: r.condition as never, result: r.result as never, enabled: true, createdAt: new Date(), updatedAt: new Date() })
    ),
  })
);
const policyEvaluator = new PolicyEvaluator({ findAllEnabled: async () => policies } as unknown as IPolicyRepository);

type Audit = { action: string; entity: string; entityId: string; actor: string; metadata?: Record<string, unknown> };

function wazuhAlert(id: string, level: number) {
  return { id, timestamp: "2026-09-24T07:04:30.180+0000", rule: { id: "5551", level, description: "PAM: Multiple failed logins in a small period of time." }, agent: { id: "001", name: "vigix-lab-ubuntu" }, data: { srcip: "172.31.250.50" } };
}

function world() {
  const audit: Audit[] = [];
  const auditLogger = { record: async (e: Audit) => void audit.push(e) } as never;
  const alerts: Alert[] = [];
  const links = new Map<string, string>();
  const incidents: Array<{ id: string; alertId: string; status: string }> = [];
  const alertRepository = {
    findById: async (id: string) => alerts.find((a) => a.id === id) ?? null,
    findByExternalId: async (source: string, ext: string) => alerts.filter((a) => a.siemSource === source && a.externalAlertId === ext),
    save: async (a: Alert) => (alerts.push(a), a),
    recordTriage: async (id: string, _t: string, triage: AlertTriage, status: AlertStatus) => patch(id, { status, triage }),
    // Conditional write, like the Prisma repository: only an OPEN alert with no incident can be closed (one winner).
    commitTriage: async (id: string, _t: string, actor: string, d: { disposition: "FALSE_POSITIVE" | "INFORMATIONAL"; reason: string; at: Date }) => {
      const a = alerts.find((x) => x.id === id);
      if (!a || !["NEW", "IN_TRIAGE", "MONITORING"].includes(a.workflowState) || links.has(id)) return null;
      return patch(id, { triage: { disposition: d.disposition, note: d.reason, triagedBy: actor, triagedAt: d.at }, status: "closed", workflowState: "TRIAGED", closedAt: d.at });
    },
    findDueMonitors: async (now: Date) => alerts.filter((a) => a.workflowState === "MONITORING" && a.reviewAt && a.reviewAt <= now),
    returnDueMonitor: async (id: string, _t: string, now: Date) => {
      const a = alerts.find((x) => x.id === id);
      if (!a || a.workflowState !== "MONITORING" || !a.reviewAt || a.reviewAt > now) return null;
      return patch(id, { workflowState: "NEW", status: "received" });
    },
  } as unknown as IAlertRepository;
  function patch(id: string, p: Record<string, unknown>) {
    const i = alerts.findIndex((a) => a.id === id);
    alerts[i] = Alert.create({ ...alerts[i].toJSON(), ...p } as never);
    return alerts[i];
  }
  const incidentRepository = {
    createWithAlerts: async (d: { alertIds: string[] }) => {
      if (d.alertIds.some((a) => links.has(a))) throw Object.assign(new Error("unique"), { code: "P2002" });
      // Same guard as the Prisma transaction: an alert the SOC closed meanwhile is never escalated.
      if (d.alertIds.some((a) => { const x = alerts.find((y) => y.id === a); return x?.workflowState === "TRIAGED" && ["FALSE_POSITIVE", "INFORMATIONAL"].includes(x.triage?.disposition ?? ""); })) {
        throw new AlertAlreadyClosedError();
      }
      const inc = { id: `inc-${incidents.length + 1}`, alertId: d.alertIds[0], status: "open" };
      incidents.push(inc);
      // Same transaction effect as the Prisma repository: the alert is escalated and triage is decided.
      d.alertIds.forEach((a) => (links.set(a, inc.id), patch(a, { status: "escalated", workflowState: "TRIAGED", closedAt: new Date() })));
      return inc;
    },
    findLinkedIncidents: async (ids: string[]) => new Map(ids.filter((i) => links.has(i)).map((i) => [i, links.get(i)!])),
    findById: async (id: string) => {
      const found = incidents.find((i) => i.id === id);
      return found ? { ...found } : null;
    },
    updateStatus: async (id: string, _t: string, status: string) => Object.assign(incidents.find((i) => i.id === id)!, { status }),
  } as unknown as IIncidentRepository;
  const jobs: Array<{ incidentId: string; alertId: string; trigger: string }> = [];
  const queue = {
    enqueue: async (j: { incidentId: string; alertId: string; trigger: string }) => (jobs.push(j), { id: `job-${jobs.length}`, status: "QUEUED" }),
    latestForIncident: async () => null,
  };
  const createIncident = new CreateIncidentUseCase(incidentRepository, alertRepository, auditLogger, queue as never);
  const ingest = new IngestAlertFromSiemUseCase(alertRepository, incidentRepository, queue as never, auditLogger, new PolicyIncidentIntake(policyEvaluator), createIncident);
  const normalize = (raw: ReturnType<typeof wazuhAlert>, severity: "low" | "medium" | "high" | "critical") => ({
    tenantId: TENANT,
    siemSource: "wazuh" as const,
    externalAlertId: raw.id,
    rawPayload: raw,
    severity,
    receivedAt: new Date(raw.timestamp),
  });

  // Email: real IrEmailService (recipient config + duplicate protection), fake SMTP + delivery store.
  const sent: Array<{ recipient: string; subject: string }> = [];
  const deliveries: Array<{ id: string; eventId: string; status: string; recipient: string; sentAt: Date | null }> = [];
  const irEmail = new IrEmailService(
    { isConfigured: () => true, send: async (m: { recipient: string; subject: string }) => (sent.push(m), { status: "SENT", channel: "email", deliveredAt: new Date() }) } as never,
    { resolve: async () => ({ email: "ir-team@corp.test", source: "SETTINGS" }) } as never,
    {
      findByEventId: async (eventId: string) => deliveries.filter((d) => d.eventId === eventId),
      create: async (d: { eventId: string; recipient: string }) => {
        const row = { id: `del-${deliveries.length + 1}`, eventId: d.eventId, status: "PENDING", recipient: d.recipient, sentAt: null };
        deliveries.push(row);
        return row;
      },
      updateStatus: async (id: string, d: { status: string; sentAt: Date | null }) => Object.assign(deliveries.find((x) => x.id === id)!, d),
    } as never,
    auditLogger
  );
  const notifications = new NotificationDecisionService(irEmail, auditLogger);
  const triage = new TriageAlertUseCase(alertRepository, incidentRepository, auditLogger, createIncident);
  const bell: Array<{ eventType: string; recipientRole: string; alertId?: string | null; incidentId: string | null }> = [];
  const inApp = new InAppNotifier({ createMany: async (rows) => void bell.push(...rows), list: async () => ({ items: [], unread: 0 }), markRead: async () => 0 });
  const context = {
    getIncidentContext: async (id: string) => (id === "inc-low" ? { incidentId: id, investigationNumber: 1, title: "Low incident", status: "investigating", priority: "low", alertSeverity: "low" } : null),
  };
  return { audit, auditLogger, alerts, incidents, jobs, sent, ingest, normalize, triage, createIncident, bell, inApp, alertRepository, incidentRepository, queue, notifications, context, patch };
}

describe("Alert intake by Wazuh severity: LOW out, MEDIUM to the SOC, HIGH / CRITICAL auto-incident", () => {
  it("LOW alert: stored for the record only — not in the SOC workflow, no incident, no AI job", async () => {
    const w = world();
    const r = await w.ingest.execute(w.normalize(wazuhAlert("low-1", 3), "low"));
    expect(r.value).toMatchObject({ incidentId: null, aiJob: null, duplicate: false, triageRequired: false });
    expect(w.alerts).toHaveLength(1);
    expect(w.incidents).toEqual([]);
    expect(w.jobs).toEqual([]);
    expect(w.audit.find((a) => a.action === "ALERT_OUTSIDE_SOC_WORKFLOW")).toMatchObject({ entity: "Alert", metadata: { severity: "low" } });
    expect(w.audit.some((a) => a.action === "ALERT_ROUTED_TO_TRIAGE")).toBe(false);
  });

  it("MEDIUM alert: routed to SOC review in the Alert Inbox — no automatic incident, no AI job", async () => {
    const w = world();
    const r = await w.ingest.execute(w.normalize(wazuhAlert("a-medium", 7), "medium"));
    expect(r.value).toMatchObject({ incidentId: null, aiJob: null, duplicate: false, triageRequired: true });
    expect(w.incidents).toEqual([]);
    expect(w.jobs).toEqual([]);
    expect(w.audit.find((a) => a.action === "ALERT_ROUTED_TO_TRIAGE")).toMatchObject({ entity: "Alert", metadata: { severity: "medium", assignedRole: "SOC", matchedPolicies: expect.arrayContaining(["RULE-I02"]) } });
  });

  it.each([["high", "RULE-I03"], ["critical", "RULE-I04"]] as const)("%s alert: incident opened automatically with the alert's severity (Policy %s) + AI job; SOC notified", async (severity, rule) => {
    const w = world();
    const r = await w.ingest.execute(w.normalize(wazuhAlert(`a-${severity}`, 12), severity));
    expect(r.value).toMatchObject({ incidentId: "inc-1", duplicate: false, triageRequired: false });
    expect(w.incidents).toEqual([expect.objectContaining({ id: "inc-1", alertId: r.value.alert.id })]);
    expect(w.jobs).toEqual([expect.objectContaining({ incidentId: "inc-1", alertId: r.value.alert.id })]);
    expect(w.alerts[0]).toMatchObject({ workflowState: "TRIAGED", status: "escalated" });
    const created = w.audit.find((a) => a.action === "INCIDENT_CREATED")!;
    expect(created).toMatchObject({ actor: "vigix-ingest", metadata: { priority: severity, alertSeverities: [severity] } });
    expect(w.audit.find((a) => a.action === "ALERT_ESCALATED_TO_INCIDENT")).toMatchObject({ actor: "vigix-ingest", metadata: { trigger: "AUTOMATIC", incidentId: "inc-1", matchedPolicies: expect.arrayContaining([rule]) } });
  });

  it("a repeated alert is idempotent (no second alert, no second incident)", async () => {
    const w = world();
    await w.ingest.execute(w.normalize(wazuhAlert("hi-2", 12), "high"));
    const again = await w.ingest.execute(w.normalize(wazuhAlert("hi-2", 12), "high"));
    expect(again.value).toMatchObject({ duplicate: true, incidentId: "inc-1" });
    expect(w.alerts).toHaveLength(1);
    expect(w.incidents).toHaveLength(1);
  });

  it("policy unavailable: the deterministic severity rule applies (HIGH still opens its incident; MEDIUM still waits)", async () => {
    const w = world();
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    const ingest = new IngestAlertFromSiemUseCase(w.alertRepository, w.incidentRepository, w.queue as never, w.auditLogger, { evaluate: async () => Promise.reject(new Error("db down")) }, w.createIncident);
    const high = await ingest.execute(w.normalize(wazuhAlert("hi-3", 12), "high"));
    const med = await ingest.execute(w.normalize(wazuhAlert("med-3", 7), "medium"));
    spy.mockRestore();
    expect(high.value).toMatchObject({ incidentId: "inc-1", triageRequired: false });
    expect(med.value).toMatchObject({ incidentId: null, triageRequired: true });
    expect(w.alerts).toHaveLength(2);
  });

  it("automatic incident fails -> the HIGH alert stays in the Alert Inbox for the SOC (never lost)", async () => {
    const w = world();
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    const ingest = new IngestAlertFromSiemUseCase(w.alertRepository, w.incidentRepository, w.queue as never, w.auditLogger, new PolicyIncidentIntake(policyEvaluator), { execute: async () => Promise.reject(new Error("tx failed")) });
    const r = await ingest.execute(w.normalize(wazuhAlert("hi-4", 12), "high"));
    spy.mockRestore();
    expect(r.value).toMatchObject({ incidentId: null, triageRequired: true });
    expect(w.alerts[0].workflowState).toBe("NEW");
    expect(w.audit.find((a) => a.action === "ALERT_ROUTED_TO_TRIAGE")?.metadata).toMatchObject({ autoIncidentFailed: "ERROR" });
  });
});

describe("SOC review in the Alert Inbox: no claim, no owner, no email", () => {
  const at = (iso: string) => () => new Date(iso);
  async function inboxAlert(w: ReturnType<typeof world>, id = "t-1", severity: "low" | "medium" | "high" | "critical" = "medium") {
    return (await w.ingest.execute(w.normalize(wazuhAlert(id, 7), severity))).value.alert;
  }
  const decide = (w: ReturnType<typeof world>, alertId: string, actor: string, decision: "FALSE_POSITIVE" | "INFORMATIONAL" | "CREATE_INCIDENT", reason: string | null, extra: object = {}) =>
    w.triage.execute({ tenantId: TENANT, alertId, actor, decision, reason, ...extra });

  it("any SOC analyst decides an open MEDIUM alert directly — there is no claim step and no owner field", async () => {
    const w = world();
    const alert = await inboxAlert(w);
    expect(alert.workflowState).toBe("NEW");
    expect(alert.toJSON()).not.toHaveProperty("owner");
    const r = await decide(w, alert.id, "soc-2", "FALSE_POSITIVE", "Known lab scanner");
    expect(r.value.alert).toMatchObject({ workflowState: "TRIAGED", status: "closed" });
    expect(w.audit.some((a) => /CLAIM|RELEASE/.test(a.action))).toBe(false);
  });

  it("two analysts deciding the same alert at once: exactly one decision is committed (conditional write)", async () => {
    const w = world();
    const alert = await inboxAlert(w);
    const results = await Promise.all(["soc-1", "soc-2", "soc-3"].map((actor) => decide(w, alert.id, actor, "INFORMATIONAL", `closed by ${actor}`)));
    expect(results.filter((r) => r.isSuccess)).toHaveLength(1);
    expect(results.filter((r) => r.isFailure && r.error === "ALERT_ALREADY_DECIDED")).toHaveLength(2);
    expect(w.audit.filter((a) => a.action === "ALERT_TRIAGED")).toHaveLength(1);
  });

  it("FALSE_POSITIVE: TRIAGED + closedAt, ALERT_TRIAGED, no email, no incident, alert kept", async () => {
    const w = world();
    const alert = await inboxAlert(w);
    const r = await decide(w, alert.id, "soc-1", "FALSE_POSITIVE", "Known lab scanner");
    expect(r.value.alert).toMatchObject({ workflowState: "TRIAGED", status: "closed" });
    expect(r.value.alert!.closedAt).toBeInstanceOf(Date);
    expect(r.value.alert!.triage).toMatchObject({ disposition: "FALSE_POSITIVE", note: "Known lab scanner", triagedBy: "soc-1" });
    expect(w.audit.find((a) => a.action === "ALERT_TRIAGED")).toMatchObject({ actor: "soc-1", metadata: { disposition: "FALSE_POSITIVE", reason: "Known lab scanner", severity: "medium", previousState: "NEW", workflowState: "TRIAGED" } });
    expect(w.sent).toEqual([]);
    expect(w.audit.some((a) => a.action.startsWith("EMAIL_"))).toBe(false);
    expect(w.incidents).toEqual([]);
    expect(w.alerts).toHaveLength(1);
    // Decided once: a second decision is refused.
    expect((await decide(w, alert.id, "soc-2", "INFORMATIONAL", "again")).error).toBe("ALERT_ALREADY_DECIDED");
  });

  it("INFORMATIONAL: TRIAGED + closed, no email", async () => {
    const w = world();
    const alert = await inboxAlert(w);
    expect((await decide(w, alert.id, "soc-1", "INFORMATIONAL", "expected maintenance")).value.alert).toMatchObject({ workflowState: "TRIAGED", status: "closed" });
    expect(w.sent).toEqual([]);
  });

  it("closing an alert without a reason is allowed (the reason is optional)", async () => {
    for (const reason of [null, "", "  "]) {
      const w = world();
      const alert = await inboxAlert(w);
      const r = await decide(w, alert.id, "soc-1", "FALSE_POSITIVE", reason);
      expect(r.value.alert).toMatchObject({ workflowState: "TRIAGED", status: "closed" });
      expect(r.value.alert!.triage).toMatchObject({ disposition: "FALSE_POSITIVE", note: null });
    }
  });

  it("LOW alerts are outside the SOC workflow: no decision can be taken on them", async () => {
    const w = world();
    const alert = await inboxAlert(w, "low-x", "low");
    expect((await decide(w, alert.id, "soc-1", "FALSE_POSITIVE", "noise")).error).toBe("NOT_IN_SOC_WORKFLOW");
    expect((await decide(w, alert.id, "soc-1", "CREATE_INCIDENT", null)).error).toBe("NOT_IN_SOC_WORKFLOW");
    expect(w.alerts[0].workflowState).toBe("NEW");
  });

  it("HIGH / CRITICAL are escalated, never closed from the inbox (a legacy one without its incident can only become one)", async () => {
    const w = world();
    const legacy = (await w.alertRepository.save(Alert.create({ id: "legacy-high", tenantId: TENANT, externalAlertId: "lh-1", siemSource: "wazuh", rawPayload: wazuhAlert("lh-1", 12), severity: "high", status: "received", receivedAt: new Date(), createdAt: new Date() })));
    expect((await decide(w, legacy.id, "soc-1", "FALSE_POSITIVE", "noise")).error).toBe("CLOSE_NOT_ALLOWED");
    const r = await decide(w, legacy.id, "soc-1", "CREATE_INCIDENT", null);
    expect(r.value.incidentId).toBe("inc-1");
    expect(w.audit.find((a) => a.action === "INCIDENT_CREATED")?.metadata).toMatchObject({ priority: "high" });
  });

  it("legacy MONITORING alert: still decidable; due review returns it to the queue exactly once (history kept)", async () => {
    const w = world();
    const alert = await inboxAlert(w, "mon-1");
    const due = new Date(Date.now() - 60_000);
    w.patch(alert.id, { workflowState: "MONITORING", status: "monitoring", reviewAt: due, monitorReason: "watch recurrence", triage: { disposition: "MONITOR", note: "watch recurrence", triagedBy: "soc-1", triagedAt: new Date(due.getTime() - 3600_000) } });
    const review = (iso: string) => new ReturnDueMonitoredAlertsUseCase(w.alertRepository, w.auditLogger, w.inApp, at(iso));
    const now = new Date().toISOString();
    expect((await review(now).execute()).returned).toEqual([alert.id]);
    expect((await review(now).execute()).returned).toEqual([]); // repeated runs change nothing
    expect(w.alerts[0]).toMatchObject({ workflowState: "NEW", monitorReason: "watch recurrence", status: "received" });
    expect(w.alerts[0].triage).toMatchObject({ disposition: "MONITOR" }); // history kept
    expect(w.audit.filter((a) => a.action === "ALERT_REVIEW_DUE")).toHaveLength(1);
    expect(w.bell).toEqual([expect.objectContaining({ eventType: "ALERT_REVIEW_DUE", recipientRole: "SOC", alertId: alert.id, incidentId: null })]);
    expect(w.incidents).toEqual([]); // never auto-creates an incident
    expect((await decide(w, alert.id, "soc-1", "INFORMATIONAL", "no recurrence")).value.alert).toMatchObject({ workflowState: "TRIAGED" });
  });

  it("CREATE_INCIDENT (MEDIUM): exactly one incident with the alert's Wazuh severity, AI queued, no email", async () => {
    const w = world();
    const alert = await inboxAlert(w, "ci-1", "medium");
    const r = await decide(w, alert.id, "soc-1", "CREATE_INCIDENT", null, { incident: { title: "Brute force on lab host" } });
    expect(r.value.incidentId).toBe("inc-1");
    expect(w.incidents).toEqual([expect.objectContaining({ id: "inc-1", alertId: alert.id })]);
    expect(w.jobs).toEqual([expect.objectContaining({ incidentId: "inc-1", alertId: alert.id, trigger: "MANUAL" })]);
    expect(w.alerts[0]).toMatchObject({ workflowState: "TRIAGED", status: "escalated" });
    expect(w.audit.find((a) => a.action === "INCIDENT_CREATED")?.metadata).toMatchObject({ priority: "medium" });
    expect(w.audit.find((a) => a.action === "ALERT_ESCALATED_TO_INCIDENT")).toMatchObject({ actor: "soc-1", entityId: alert.id, metadata: { incidentId: "inc-1", severity: "medium", trigger: "SOC_REVIEW" } });
    expect(w.sent).toEqual([]);
    // Once in an incident the alert cannot be decided or escalated again.
    expect((await decide(w, alert.id, "soc-1", "CREATE_INCIDENT", null)).error).toBe("ALERT_IN_INCIDENT");
    expect(w.incidents).toHaveLength(1);
  });

  it("the incident severity is always the Wazuh alert severity — a triage request cannot set another one", async () => {
    const w = world();
    const alert = await inboxAlert(w, "ci-2", "medium");
    await decide(w, alert.id, "soc-1", "CREATE_INCIDENT", "Privileged account involved", { incident: { severity: "critical" } });
    expect(w.audit.find((a) => a.action === "INCIDENT_CREATED")?.metadata).toMatchObject({ priority: "medium" });
    expect(w.audit.find((a) => a.action === "ALERT_ESCALATED_TO_INCIDENT")?.metadata).toMatchObject({ severity: "medium", reason: "Privileged account involved" });
  });

  it("an alert the SOC already closed as FALSE_POSITIVE cannot be turned into an incident", async () => {
    const w = world();
    const alert = await inboxAlert(w);
    await decide(w, alert.id, "soc-1", "FALSE_POSITIVE", "scanner");
    const r = await w.createIncident.execute({ tenantId: TENANT, createdBy: "soc-1", title: "x", priority: "medium", alertIds: [alert.id] });
    expect(r.error).toMatchObject({ code: "ALERT_ALREADY_TRIAGED" });
    expect(w.incidents).toEqual([]);
  });

  it("incident email choice: SOC can Send (once — duplicate protected) or Don't send; never automatic", async () => {
    const w = world();
    const decide = new DecideIncidentNotificationUseCase(w.context as never, w.notifications);
    const skip = await decide.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", choice: "SKIP", note: "handled, no stakeholders" });
    expect(skip.value).toEqual({ choice: "SKIP", email: null });
    expect(w.sent).toEqual([]);
    const first = await decide.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", choice: "SEND", note: null });
    const second = await decide.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-2", choice: "SEND", note: null });
    expect(first.value.email).toMatchObject({ status: "SENT", duplicate: false });
    expect(second.value.email).toMatchObject({ status: "SENT", duplicate: true });
    expect(w.sent).toHaveLength(1);
    expect(w.audit.filter((a) => a.action === "EMAIL_SENT")).toHaveLength(1);
    expect(w.audit.find((a) => a.action === "EMAIL_SKIPPED")?.metadata).toMatchObject({ severity: "LOW", reason: "handled, no stakeholders" });
  });
});

describe("Human severity validation and RESOLVED only via verification", () => {
  // Replaces the audit-only risk validation: the analyst confirms or corrects the SEVERITY that Policy uses.
  const severityWriter = (tickets: string[] = []) => {
    const writes: { severity: string; description: string }[] = [];
    return { writes, writer: { setSeverity: async (i: { severity: string; description: string }) => void writes.push(i), ticketStatuses: async () => tickets } };
  };

  it("confirming the Wazuh severity needs no reason: SEVERITY_VALIDATED {changed:false, overridesWazuh:false}, nothing written", async () => {
    const w = world();
    const { writes, writer } = severityWriter();
    const reassign = jest.fn(async () => undefined);
    const uc = new ValidateIncidentSeverityUseCase(w.context as never, writer, w.auditLogger, reassign);
    const r = await uc.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "LOW", note: null });
    expect(r.value).toEqual({ severity: "LOW", previous: "LOW", changed: false, wazuhSeverity: "LOW", overridesWazuh: false });
    expect(writes).toHaveLength(0);
    expect(reassign).not.toHaveBeenCalled();
    expect(w.audit).toEqual([expect.objectContaining({ action: "SEVERITY_VALIDATED", metadata: expect.objectContaining({ wazuhSeverity: "LOW", changed: false, previous: "LOW", severity: "LOW", overridesWazuh: false, actor: "soc-1" }) })]);
    // No AI value exists anywhere in the decision or its audit.
    expect(JSON.stringify(w.audit)).not.toMatch(/ai(Suggestion|Severity)|differsFromAi/);
  });

  it("an override of the Wazuh severity may carry a reason; the Wazuh value stays recorded next to the SOC value", async () => {
    const w = world();
    const { writer } = severityWriter();
    const uc = new ValidateIncidentSeverityUseCase(w.context as never, writer, w.auditLogger);
    const r = await uc.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "HIGH", note: "confirmed exfiltration" });
    expect(r.value).toMatchObject({ severity: "HIGH", previous: "LOW", changed: true, wazuhSeverity: "LOW", overridesWazuh: true });
    expect(w.audit[0].metadata).toMatchObject({ wazuhSeverity: "LOW", severity: "HIGH", overridesWazuh: true, reason: "confirmed exfiltration" });
  });

  it("the reason is optional: an override or a revert to Wazuh goes through without one", async () => {
    const w = world();
    const { writes, writer } = severityWriter();
    const uc = new ValidateIncidentSeverityUseCase(w.context as never, writer, w.auditLogger);
    expect((await uc.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "HIGH", note: null })).value).toMatchObject({ changed: true, overridesWazuh: true });
    expect(writes).toHaveLength(1);
    const ctx = { getIncidentContext: async () => ({ incidentId: "inc-low", investigationNumber: 1, title: "t", status: "investigating", priority: "high", alertSeverity: "low" }) };
    const revert = new ValidateIncidentSeverityUseCase(ctx as never, severityWriter().writer, w.auditLogger);
    expect((await revert.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "LOW", note: "  " })).value).toMatchObject({ changed: true, overridesWazuh: false });
  });

  it("correct: severity written + timeline, audited with previous/new, Policy ownership re-evaluated", async () => {
    const w = world();
    const { writes, writer } = severityWriter(["COMPLETED"]);
    const reassign = jest.fn(async () => undefined);
    const r = await new ValidateIncidentSeverityUseCase(w.context as never, writer, w.auditLogger, reassign).execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "HIGH", note: "lateral movement seen" });
    expect(r.value).toMatchObject({ severity: "HIGH", previous: "LOW", changed: true });
    expect(writes).toEqual([expect.objectContaining({ severity: "HIGH", description: expect.stringContaining("LOW -> HIGH") })]);
    expect(reassign).toHaveBeenCalledWith({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1" });
    expect(w.audit[0]).toMatchObject({ action: "SEVERITY_VALIDATED", metadata: { previous: "LOW", severity: "HIGH", changed: true, note: "lateral movement seen", actorRole: "SOC" } });
  });

  it("a change is refused while a ticket awaits the IR decision or is in progress (SEVERITY_LOCKED); confirming is still allowed", async () => {
    const w = world();
    for (const busy of ["PENDING_IR_DECISION", "PENDING_APPROVAL", "IN_PROGRESS"]) {
      const { writes, writer } = severityWriter([busy]);
      const uc = new ValidateIncidentSeverityUseCase(w.context as never, writer, w.auditLogger);
      expect((await uc.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "CRITICAL", note: "escalating" })).error).toBe("SEVERITY_LOCKED");
      expect(writes).toHaveLength(0);
      expect((await uc.execute({ tenantId: TENANT, incidentId: "inc-low", actor: "soc-1", actorRole: "SOC", severity: "LOW", note: "stays LOW" })).isSuccess).toBe(true);
    }
  });

  it("unknown incident -> INCIDENT_NOT_FOUND", async () => {
    const w = world();
    const r = await new ValidateIncidentSeverityUseCase(w.context as never, severityWriter().writer, w.auditLogger).execute({ tenantId: TENANT, incidentId: "nope", actor: "soc-1", actorRole: "SOC", severity: "HIGH", note: null });
    expect(r.error).toBe("INCIDENT_NOT_FOUND");
  });

  it("PATCH status cannot resolve an incident; other manual transitions are audited", async () => {
    const w = world();
    const med = (await w.ingest.execute(w.normalize(wazuhAlert("med-2", 10), "medium"))).value.alert;
    await w.createIncident.execute({ tenantId: TENANT, createdBy: "soc-1", title: "Medium case", priority: "medium", alertIds: [med.id] });
    const update = new UpdateIncidentStatusUseCase(w.incidentRepository, w.auditLogger);
    expect((await update.execute({ id: "inc-1", tenantId: TENANT, status: "resolved", actor: "soc-1" })).error).toBe("RESOLVE_REQUIRES_VERIFICATION");
    expect(w.incidents[0].status).toBe("open");
    await update.execute({ id: "inc-1", tenantId: TENANT, status: "investigating", actor: "soc-1" });
    expect(w.audit.find((a) => a.action === "INCIDENT_STATUS_CHANGED")).toMatchObject({ actor: "soc-1", metadata: { from: "open", to: "investigating", manual: true } });
  });
});

describe("INCIDENT_ASSIGNED — SOC investigates every severity, IR_TEAM executes", () => {
  // Two-role workflow: ownership no longer moves to IR by severity; IR decides and executes each Response Ticket.
  it.each([
    ["LOW", "SOC"],
    ["MEDIUM", "SOC"],
    ["HIGH", "SOC"],
    ["CRITICAL", "SOC"],
  ] as const)("severity %s -> %s", async (severity, role) => {
    const audit: Audit[] = [];
    const approvalService = { evaluate: async () => ({ severity, policy: await policyEvaluator.evaluate(TENANT, { severity }) }) };
    await new IncidentAssignmentService(approvalService as never, { record: async (e: Audit) => void audit.push(e) } as never).assign({ tenantId: TENANT, incidentId: "inc-1", actor: "policy-engine", trigger: "AI_JOB_INGEST" });
    expect(audit[0]).toMatchObject({ action: "INCIDENT_ASSIGNED", metadata: { responsibleRole: role, executorRole: "IR_TEAM", severity } });
    expect(audit[0].metadata).not.toHaveProperty("riskScore");
  });
});

describe("RBAC — AI (or any non-human role) can neither approve nor execute", () => {
  // Real HTTP round trips on an ephemeral port: allow for a loaded machine during the full parallel run.
  jest.setTimeout(30_000);
  const secret = process.env.JWT_SECRET ?? "dev-only-insecure-secret-change-in-production";
  const token = (role: string) => jwt.sign({ id: `${role}-user`, email: "x@corp.test", role, tenantId: TENANT }, secret);
  const reached: string[] = [];
  const ok = (name: string) => (_req: express.Request, res: express.Response) => void (reached.push(name), res.json({ ok: true }));
  let base = "";
  let server: ReturnType<express.Express["listen"]>;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use("/api/responses", buildResponseRoutes({ list: ok("list"), create: ok("create"), getById: ok("get"), start: ok("start"), complete: ok("complete"), fail: ok("fail"), decideManually: ok("manual-decision") } as never));
    app.use("/api/approvals", buildApprovalRoutes({ request: ok("request"), getById: ok("get"), approve: ok("approve"), reject: ok("reject") } as never));
    app.use("/api/v1", buildSocTriageRoutes({ triage: ok("triage"), notificationDecision: ok("notify"), severityValidation: ok("severity"), severity: ok("severity-read") } as never));
    server = app.listen(0);
    await new Promise((r) => server.once("listening", r));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise((r) => server.close(r)));

  const post = (path: string, auth?: string) => fetch(`${base}${path}`, { method: "POST", headers: { "Content-Type": "application/json", ...(auth ? { Authorization: `Bearer ${auth}` } : {}) }, body: "{}" }).then((r) => r.status);

  it("no token (e.g. the AI orchestrator) -> 401 on approve / reject / start / complete", async () => {
    for (const path of ["/api/approvals/a1/approve", "/api/approvals/a1/reject", "/api/responses/r1/start", "/api/responses/r1/complete"]) expect(await post(path)).toBe(401);
  });

  it("an AI / SOC / analyst / retired MANAGER token cannot approve, reject or execute (403)", async () => {
    for (const role of ["AI", "ai-orchestrator", "SOC", "analyst", "MANAGER"]) {
      expect(await post("/api/approvals/a1/approve", token(role))).toBe(403);
      expect(await post("/api/approvals/a1/reject", token(role))).toBe(403);
      expect(await post("/api/responses/r1/start", token(role))).toBe(403);
      expect(await post("/api/responses/r1/complete", token(role))).toBe(403);
    }
    expect(reached).toEqual([]);
  });

  it("IR_TEAM decides (approve / reject) and executes; request-more-evidence no longer exists", async () => {
    expect(await post("/api/responses/r1/start", token("IR_TEAM"))).toBe(200);
    expect(await post("/api/approvals/a1/approve", token("IR_TEAM"))).toBe(200);
    expect(await post("/api/approvals/a1/reject", token("IR_TEAM"))).toBe(200);
    expect(await post("/api/approvals/a1/request-more-evidence", token("IR_TEAM"))).toBe(404);
  });

  it("SOC owns alert review, the incident email choice and severity validation; claim / release routes are gone", async () => {
    expect(await post("/api/v1/alerts/x/triage", token("SOC"))).toBe(200);
    expect(await post("/api/v1/incidents/x/notification-decision", token("SOC"))).toBe(200);
    expect(await post("/api/v1/incidents/x/severity-validation", token("SOC"))).toBe(200);
    expect(await post("/api/v1/incidents/x/severity-validation", token("IR_TEAM"))).toBe(403);
    expect(await post("/api/v1/alerts/x/triage", token("IR_TEAM"))).toBe(403);
    expect(await post("/api/v1/alerts/x/triage", token("AI"))).toBe(403);
    for (const path of ["/api/v1/alerts/x/claim", "/api/v1/alerts/x/release"]) expect(await post(path, token("SOC"))).toBe(404);
  });
});
