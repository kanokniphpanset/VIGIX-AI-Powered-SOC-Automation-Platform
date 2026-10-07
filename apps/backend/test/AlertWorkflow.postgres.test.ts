import 'dotenv/config';
import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { PrismaAlertInboxQuery } from '../src/infrastructure/database/postgres/repositories/AlertInboxQuery.prisma';
import { alertWorkflow } from '../src/infrastructure/database/postgres/AlertWorkflow';
import { ListAlertInboxUseCase } from '../src/application/alert/use-cases/AlertInbox.usecases';
import { AuditLogger } from '../src/infrastructure/database/postgres/repositories/AuditLogger';
import { PrismaAlertRepository } from '../src/infrastructure/database/postgres/repositories/AlertRepository.prisma';
import { PrismaIncidentRepository } from '../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma';
import { IngestAlertFromSiemUseCase } from '../src/application/alert/use-cases/IngestAlertFromSiem.usecase';
import { CreateIncidentUseCase } from '../src/application/incident/use-cases/CreateIncident.usecase';
import { GetIncidentSeverityUseCase } from '../src/application/triage/IncidentSeverity.usecase';
import { PrismaIncidentSeverityReader } from '../src/infrastructure/database/postgres/repositories/IncidentSeverityWriter.prisma';

// Real Postgres; isolated tenant and IDs, removed after this suite. No network delivery or AI execution.
// Real Postgres round trips: allow for a loaded machine during the full parallel run.
jest.setTimeout(30_000);
const db = new PrismaClient();
const tenantId = randomUUID();
const actor = randomUUID();
const other = randomUUID();
const workflow = alertWorkflow(db);
const now = new Date();
const queue = new ListAlertInboxUseCase(new PrismaAlertInboxQuery(db), { triageSlaMinutes: async () => ({ CRITICAL: 15, HIGH: 30, MEDIUM: 240, LOW: 1440 }) }, () => now);
const alert = async (extra: object = {}) => db.alert.create({ data: { tenantId, externalAlertId: randomUUID(), siemSource: 'wazuh', severity: 'medium', status: 'received', receivedAt: now, rawPayload: { rule: { id: '5712', level: 12, description: 'Source login failures' }, data: { srcip: '192.0.2.1' } }, ...extra } });
const input = (alertId: string) => ({ tenantId, alertId, actor });

beforeAll(async () => {
  await db.tenant.create({ data: { id: tenantId, name: 'phase34-integration-isolated' } });
  await db.user.createMany({ data: [actor, other].map(id => ({ id, tenantId, email: `${id}@phase34.invalid`, passwordHash: 'not-a-login', role: 'SOC' })) });
}, 30000);
afterAll(async () => {
  const incidents = await db.incident.findMany({ where: { tenantId }, select: { id: true } });
  const ids = incidents.map(i => i.id);
  await db.evidence.deleteMany({ where: { investigation: { incidentId: { in: ids } } } });
  await db.investigation.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incidentTimeline.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incidentAlert.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incident.deleteMany({ where: { tenantId } });
  await db.inAppNotification.deleteMany({ where: { tenantId } });
  await db.auditLog.deleteMany({ where: { tenantId } });
  await db.alert.deleteMany({ where: { tenantId } });
  await db.user.deleteMany({ where: { tenantId } });
  await db.tenant.delete({ where: { id: tenantId } });
  await db.$disconnect();
}, 30000);

test('SQL pagination discovers alerts beyond 500; LOW excluded; status, severity, search, SLA ordering and tenant isolation', async () => {
  const oldest = new Date(now.getTime() - 40 * 86400000);
  const old = await alert({ receivedAt: oldest, externalAlertId: 'older-than-500-needle' });
  await db.alert.createMany({ data: Array.from({ length: 510 }, (_, i) => ({ id: randomUUID(), tenantId, externalAlertId: `page-${i}`, siemSource: 'wazuh', severity: 'medium', receivedAt: now, rawPayload: {} })) });
  // LOW alerts are stored but never part of the SOC workflow.
  await db.alert.createMany({ data: Array.from({ length: 5 }, (_, i) => ({ id: randomUUID(), tenantId, externalAlertId: `low-${i}`, siemSource: 'wazuh', severity: 'low', receivedAt: now, rawPayload: {} })) });
  const first = (await queue.execute({ tenantId, filters: { limit: 10 } })).value;
  expect(first.total).toBe(511);
  expect(first.status).toBe('all');
  // Urgency: the open alert whose SLA (MEDIUM = 240 min) breached first is on top.
  expect(first.items[0]).toMatchObject({ id: old.id, ageMinutes: 40 * 1440, slaStatus: 'BREACHED', actionable: true, displayState: 'NEEDS_REVIEW', slaDueAt: new Date(oldest.getTime() + 240 * 60000).toISOString() });
  expect(first.items[0]).not.toHaveProperty('owner');
  const last = (await queue.execute({ tenantId, filters: { sort: 'newest', offset: 500, limit: 20 } })).value;
  expect(last.items).toHaveLength(11);
  expect(last.items.some(a => a.id === old.id)).toBe(true);
  const search = (await queue.execute({ tenantId, filters: { severity: 'medium', search: 'older-than-500' } })).value;
  expect(search.items.map(a => a.id)).toEqual([old.id]);
  expect((await queue.execute({ tenantId, filters: { severity: 'low' } })).value.total).toBe(0);
  expect((await queue.execute({ tenantId, filters: { status: 'needs-review' } })).value.total).toBe(511);
  expect((await queue.execute({ tenantId, filters: { status: 'closed' } })).value.total).toBe(0);
  const page1 = (await queue.execute({ tenantId, filters: { sort: 'oldest', limit: 10 } })).value.items;
  const page2 = (await queue.execute({ tenantId, filters: { sort: 'oldest', limit: 10, offset: 10 } })).value.items;
  expect(new Set([...page1, ...page2].map(a => a.id)).size).toBe(20);
  expect((await queue.execute({ tenantId: randomUUID(), filters: {} })).value.total).toBe(0);
});

test('no claim: two SOC analysts deciding at once — exactly one decision, one audit, no overwrite', async () => {
  const a = await alert();
  const results = await Promise.all([
    workflow.triage.execute({ ...input(a.id), decision: 'FALSE_POSITIVE', reason: 'first analyst' }),
    workflow.triage.execute({ ...input(a.id), actor: other, decision: 'INFORMATIONAL', reason: 'second analyst' }),
  ]);
  expect(results.filter(r => r.isSuccess)).toHaveLength(1);
  expect(results.filter(r => r.isFailure && r.error === 'ALERT_ALREADY_DECIDED')).toHaveLength(1);
  expect(await db.auditLog.count({ where: { tenantId, entityId: a.id, action: 'ALERT_TRIAGED' } })).toBe(1);
  const stored = await db.alert.findUniqueOrThrow({ where: { id: a.id } });
  expect(stored).toMatchObject({ workflowState: 'TRIAGED', owner: null, claimedAt: null });
});

test('a failed audit rolls the decision back so a retry can succeed', async () => {
  const a = await alert();
  const spy = jest.spyOn(AuditLogger.prototype, 'record').mockRejectedValueOnce(new Error('audit unavailable'));
  await expect(workflow.triage.execute({ ...input(a.id), decision: 'FALSE_POSITIVE', reason: 'scanner' })).rejects.toThrow('audit unavailable');
  spy.mockRestore();
  expect((await db.alert.findUniqueOrThrow({ where: { id: a.id } })).workflowState).toBe('NEW');
  expect((await workflow.triage.execute({ ...input(a.id), decision: 'FALSE_POSITIVE', reason: 'scanner' })).isSuccess).toBe(true);
});

test.each(['FALSE_POSITIVE', 'INFORMATIONAL'] as const)('%s (MEDIUM) atomically closes with audit, preserving the raw payload, no email', async decision => {
  const a = await alert();
  expect((await workflow.triage.execute({ ...input(a.id), decision, reason: 'Verified source evidence' })).isSuccess).toBe(true);
  const stored = await db.alert.findUniqueOrThrow({ where: { id: a.id } });
  expect(stored).toMatchObject({ workflowState: 'TRIAGED', status: 'closed', triageDisposition: decision, rawPayload: a.rawPayload });
  expect(stored.closedAt).not.toBeNull();
  expect(await db.auditLog.count({ where: { entityId: a.id, action: 'ALERT_TRIAGED' } })).toBe(1);
  expect(await db.notificationDelivery.count({ where: { tenantId } })).toBe(0);
});

test('closing a MEDIUM alert without a reason is allowed (the reason is optional)', async () => {
  const a = await alert();
  expect((await workflow.triage.execute({ ...input(a.id), decision: 'FALSE_POSITIVE', reason: null })).isSuccess).toBe(true);
  expect(await db.alert.findUniqueOrThrow({ where: { id: a.id } })).toMatchObject({ workflowState: 'TRIAGED', triageDisposition: 'FALSE_POSITIVE', triageNote: null });
});

test('HIGH / CRITICAL cannot be closed from the inbox; LOW cannot be decided at all', async () => {
  const high = await alert({ severity: 'high' });
  const low = await alert({ severity: 'low' });
  expect((await workflow.triage.execute({ ...input(high.id), decision: 'FALSE_POSITIVE', reason: 'noise' })).error).toBe('CLOSE_NOT_ALLOWED');
  expect((await workflow.triage.execute({ ...input(low.id), decision: 'FALSE_POSITIVE', reason: 'noise' })).error).toBe('NOT_IN_SOC_WORKFLOW');
});

test('legacy monitor review returns once across concurrent scheduler runs, preserving history and the alert notification', async () => {
  const a = await alert({ workflowState: 'MONITORING', status: 'monitoring', monitorReason: 'Observe', triageDisposition: 'MONITOR', triageNote: 'Observe', triagedBy: actor, triagedAt: now, reviewAt: new Date(Date.now() - 1000) });
  // Scope the scheduler database adapter to this suite's tenant so existing monitored alerts are never touched.
  const original = PrismaAlertRepository.prototype.findDueMonitors;
  const spy = jest.spyOn(PrismaAlertRepository.prototype, 'findDueMonitors').mockImplementation(async function(this: InstanceType<typeof PrismaAlertRepository>, at, limit) { return (await original.call(this, at, limit)).filter(x => x.tenantId === tenantId); });
  try { await Promise.all([workflow.review.execute(), workflow.review.execute()]); await workflow.review.execute(); } finally { spy.mockRestore(); }
  const stored = await db.alert.findUniqueOrThrow({ where: { id: a.id } });
  expect(stored).toMatchObject({ workflowState: 'NEW', status: 'received', triageDisposition: 'MONITOR', monitorReason: 'Observe', closedAt: null });
  expect(await db.auditLog.count({ where: { entityId: a.id, action: 'ALERT_REVIEW_DUE' } })).toBe(1);
  expect(await db.inAppNotification.findMany({ where: { tenantId, alertId: a.id } })).toEqual([expect.objectContaining({ alertId: a.id, link: `/alerts/${a.id}`, eventType: 'ALERT_REVIEW_DUE' })]);
  // Back in the queue it is decided like any open alert — no claim.
  expect((await workflow.triage.execute({ ...input(a.id), actor: other, decision: 'INFORMATIONAL', reason: 'no recurrence' })).isSuccess).toBe(true);
});

test('Create Incident: concurrent submits create exactly one incident with the Wazuh severity, no email, no ticket', async () => {
  const a = await alert();
  const results = await Promise.all([actor, other].map(who => workflow.triage.execute({ ...input(a.id), actor: who, decision: 'CREATE_INCIDENT', reason: null })));
  expect(results.filter(r => r.isSuccess)).toHaveLength(1);
  expect(await db.incident.count({ where: { tenantId, alertId: a.id } })).toBe(1);
  expect((await db.incident.findFirstOrThrow({ where: { tenantId, alertId: a.id } })).priority).toBe('medium');
  expect(await db.incidentAlert.count({ where: { alertId: a.id } })).toBe(1);
  expect(await db.auditLog.count({ where: { entityId: a.id, action: 'ALERT_ESCALATED_TO_INCIDENT' } })).toBe(1);
  expect(await db.notificationDelivery.count({ where: { tenantId } })).toBe(0);
  expect(await db.responsePlan.count({ where: { tenantId } })).toBe(0);
});

test('ingestion: a HIGH Wazuh alert opens its incident automatically on the real database (one incident, severity kept)', async () => {
  const alerts = new PrismaAlertRepository(db);
  const incidents = new PrismaIncidentRepository(db);
  const audit = new AuditLogger(db);
  const jobs: string[] = [];
  const aiQueue = { enqueue: async (j: { incidentId: string }) => (jobs.push(j.incidentId), { id: randomUUID(), status: 'QUEUED' }), latestForIncident: async () => null };
  const ingest = new IngestAlertFromSiemUseCase(alerts, incidents, aiQueue as never, audit, { evaluate: async () => ({ autoCreateIncident: true, matchedPolicies: ['RULE-I03'] }) }, new CreateIncidentUseCase(incidents, alerts, audit, aiQueue as never));
  const raw = { rule: { id: '5712', level: 12, description: 'Brute force success' }, agent: { name: 'lab-01' } };
  const r = await ingest.execute({ tenantId, siemSource: 'wazuh', externalAlertId: `auto-${randomUUID()}`, rawPayload: raw, severity: 'high', receivedAt: now });
  expect(r.value.incidentId).not.toBeNull();
  const incident = await db.incident.findUniqueOrThrow({ where: { id: r.value.incidentId! } });
  expect(incident).toMatchObject({ tenantId, priority: 'high', title: 'Brute force success', alertId: r.value.alert.id });
  expect(await db.alert.findUniqueOrThrow({ where: { id: r.value.alert.id } })).toMatchObject({ workflowState: 'TRIAGED', status: 'escalated' });
  expect(jobs).toEqual([incident.id]);
  expect(await db.auditLog.count({ where: { entityId: r.value.alert.id, action: 'ALERT_ESCALATED_TO_INCIDENT' } })).toBe(1);
  // Redelivery of the same Wazuh alert creates nothing new.
  const again = await ingest.execute({ tenantId, siemSource: 'wazuh', externalAlertId: r.value.alert.externalAlertId, rawPayload: raw, severity: 'high', receivedAt: now });
  expect(again.value).toMatchObject({ duplicate: true, incidentId: incident.id });
  expect(await db.incident.count({ where: { tenantId, alertId: r.value.alert.id } })).toBe(1);
  // Alert Inbox: linked only as the incident's originating alert (no incident_alerts row yet — it is added when the
  // investigation starts), the alert is already "in incident": no review button and no stale review-SLA status.
  await db.incidentAlert.deleteMany({ where: { incidentId: incident.id } });
  const row = (await queue.execute({ tenantId, filters: { search: r.value.alert.externalAlertId } })).value.items[0];
  expect(row).toMatchObject({ id: r.value.alert.id, displayState: 'IN_INCIDENT', actionable: false, slaStatus: null, incident: { id: incident.id } });
  expect((await queue.execute({ tenantId, filters: { status: 'in-incident', search: r.value.alert.externalAlertId } })).value.total).toBe(1);
  expect((await queue.execute({ tenantId, filters: { status: 'needs-review', search: r.value.alert.externalAlertId } })).value.total).toBe(0);
  // The incident severity is the Wazuh one, read back with its rule level — there is no AI severity anywhere.
  const severity = (await new GetIncidentSeverityUseCase(new PrismaIncidentSeverityReader(db)).execute({ tenantId, incidentId: incident.id })).value;
  expect(severity).toEqual({ source: 'WAZUH_RULE_LEVEL', wazuhSeverity: 'HIGH', wazuhRuleLevel: 12, wazuhRuleId: '5712', severity: 'HIGH', overridden: false, override: null });
});
