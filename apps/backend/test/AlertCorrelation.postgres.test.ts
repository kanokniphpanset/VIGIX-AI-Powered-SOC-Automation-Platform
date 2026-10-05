import 'dotenv/config';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { AuditLogger } from '../src/infrastructure/database/postgres/repositories/AuditLogger';
import { PrismaAlertRepository } from '../src/infrastructure/database/postgres/repositories/AlertRepository.prisma';
import { PrismaIncidentRepository } from '../src/infrastructure/database/postgres/repositories/IncidentRepository.prisma';
import { PrismaInvestigationRepository } from '../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma';
import { PrismaIncidentCorrelationReader } from '../src/infrastructure/database/postgres/repositories/IncidentCorrelationReader.prisma';
import { PrismaRecommendationContextRepository } from '../src/infrastructure/database/postgres/repositories/RecommendationContextRepository.prisma';
import { IngestAlertFromSiemUseCase } from '../src/application/alert/use-cases/IngestAlertFromSiem.usecase';
import { CreateIncidentUseCase } from '../src/application/incident/use-cases/CreateIncident.usecase';
import { WazuhAdapter } from '../src/infrastructure/external-services/siem/WazuhAdapter';
import { MockRehuntAdapter } from '../src/infrastructure/external-services/siem/MockRehuntAdapter';
import { REHUNT_IOC_TYPES } from '../src/domain/investigation/alertIocs';

// Automatic alert correlation on the real database (ATK-04). Isolated tenant, removed after this suite. No AI.
jest.setTimeout(30_000);
const db = new PrismaClient();
const tenantId = randomUUID();
const otherTenant = randomUUID();
const atk04 = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../../resources/mock-attacks/malware/case-02-not-resolved.json'), 'utf-8'));
const wazuh = new WazuhAdapter();
const audit = new AuditLogger(db);
const alerts = new PrismaAlertRepository(db);
const incidents = new PrismaIncidentRepository(db);
const investigations = new PrismaInvestigationRepository(db);
const ctx = new PrismaRecommendationContextRepository(db);
const aiQueue = { enqueue: async () => ({ id: randomUUID(), status: 'QUEUED' }), latestForIncident: async () => null };
const ingest = new IngestAlertFromSiemUseCase(
  alerts,
  incidents,
  aiQueue as never,
  audit,
  { evaluate: async () => ({ autoCreateIncident: true, matchedPolicies: ['RULE-I03'] }) },
  new CreateIncidentUseCase(incidents, alerts, audit, aiQueue as never),
  { reader: new PrismaIncidentCorrelationReader(db), investigations }
);
// Each delivery is a distinct SIEM alert (fresh external id), same payload.
const deliver = (raw: object, tenant = tenantId) => ingest.execute({ ...wazuh.normalize({ ...raw, id: `corr-${randomUUID()}` } as never), tenantId: tenant });

/** Round-3 re-hunt of ATK-04 (C2-only traffic) with the incident's own hunted IOCs, as RunRehuntVerification builds them. */
async function round3(incidentId: string) {
  const iocs = (await ctx.getIocs(incidentId)).filter((i) => REHUNT_IOC_TYPES.includes(i.iocType.toUpperCase())).map((i) => ({ type: i.iocType, value: i.iocValue }));
  return new MockRehuntAdapter().rehunt({ incidentId, responseId: 'r', hosts: ['WKS-FIN-07'], iocs, rule: { id: '87105' }, timeRange: { start: new Date(), end: new Date() }, investigationNumber: 3 });
}

beforeAll(async () => {
  await db.tenant.createMany({ data: [{ id: tenantId, name: 'correlation-isolated' }, { id: otherTenant, name: 'correlation-isolated-2' }] });
});
afterAll(async () => {
  const tenants = [tenantId, otherTenant];
  const ids = (await db.incident.findMany({ where: { tenantId: { in: tenants } }, select: { id: true } })).map((i) => i.id);
  await db.evidenceIoc.deleteMany({ where: { evidence: { investigation: { incidentId: { in: ids } } } } });
  await db.threatIntelIoc.deleteMany({ where: { incidentId: { in: ids } } });
  await db.evidence.deleteMany({ where: { investigation: { incidentId: { in: ids } } } });
  await db.investigation.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incidentTimeline.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incidentAlert.deleteMany({ where: { incidentId: { in: ids } } });
  await db.incident.deleteMany({ where: { tenantId: { in: tenants } } });
  await db.auditLog.deleteMany({ where: { tenantId: { in: tenants } } });
  await db.alert.deleteMany({ where: { tenantId: { in: tenants } } });
  await db.tenant.deleteMany({ where: { id: { in: tenants } } });
  await db.$disconnect();
});

test('ATK-04: the C2 alert joins the malware incident, its IOCs are hunted, and round 3 is no longer a false RESOLVED', async () => {
  const primary = await deliver(atk04.alert);
  const incidentId = primary.value.incidentId!;
  expect(primary.value.correlation).toBeUndefined();

  // Before correlation: the incident hunts only the malware's hashes -> round 3 (C2-only traffic) finds nothing.
  expect((await round3(incidentId)).threatContained).toBe(true);

  const related = await deliver(atk04.relatedAlerts[0]);
  expect(related.value).toMatchObject({ incidentId, triageRequired: false, correlation: { incidentId, reasons: ['SHARED_IOC'] } });
  expect(await db.incident.count({ where: { tenantId } })).toBe(1);
  expect((await db.incidentAlert.findMany({ where: { incidentId } })).map((l) => l.alertId).sort()).toEqual([primary.value.alert.id, related.value.alert.id].sort());
  expect(await db.alert.findUniqueOrThrow({ where: { id: related.value.alert.id } })).toMatchObject({ status: 'escalated', workflowState: 'TRIAGED' });

  // The related alert is WAZUH_ALERT evidence of Investigation #1, linked to its C2 indicators.
  const inv1 = await db.investigation.findFirstOrThrow({ where: { incidentId, investigationNumber: 1 } });
  const ev = await db.evidence.findFirstOrThrow({ where: { investigationId: inv1.id, alertId: related.value.alert.id, type: 'WAZUH_ALERT' }, include: { iocLinks: { include: { ioc: true } } } });
  expect(ev.iocLinks.map((l) => l.ioc.iocValue)).toEqual(expect.arrayContaining(['45.155.205.233', 'vigix-mock-c2.net', 'http://vigix-mock-c2.net/stage2.bin']));

  const r3 = await round3(incidentId);
  expect(r3).toMatchObject({ threatContained: false, iocRecurrence: true, matchingEvents: 1 });
  expect(r3.events[0].matchedIocValues).toEqual(expect.arrayContaining(['45.155.205.233', 'vigix-mock-c2.net']));

  const timeline = await db.incidentTimeline.findMany({ where: { incidentId, eventType: 'alert_added' } });
  expect(timeline).toHaveLength(1);
  expect(timeline[0].description).toMatch(/correlated into the incident automatically \(SHARED_IOC: c:\\users\\fin\.analyst/);
  const auditRow = await db.auditLog.findFirstOrThrow({ where: { tenantId, action: 'ALERT_CORRELATED_TO_INCIDENT' } });
  expect(auditRow).toMatchObject({ entityId: related.value.alert.id, actor: 'vigix-ingest' });
  expect(auditRow.metadata).toMatchObject({ incidentId, reasons: ['SHARED_IOC'], trigger: 'AUTOMATIC' });
});

test('a resolved incident or another tenant never absorbs the alert: a new incident opens', async () => {
  const open = await db.incident.findFirstOrThrow({ where: { tenantId, status: { in: ['open', 'investigating'] } } });
  await incidents.updateStatus(open.id, tenantId, 'resolved');

  const again = await deliver(atk04.relatedAlerts[0]);
  expect(again.value.correlation).toBeUndefined();
  expect(again.value.incidentId).not.toBe(open.id);

  const elsewhere = await deliver(atk04.relatedAlerts[0], otherTenant);
  expect(elsewhere.value.correlation).toBeUndefined();
  expect(elsewhere.value.incidentId).not.toBeNull();
  expect(await db.incident.count({ where: { tenantId: otherTenant } })).toBe(1);
});

test('the recorded-IOC path: an alert from another host stating an indicator only the incident records joins it', async () => {
  const host = await deliver({ ...atk04.alert, agent: { id: '099', name: 'WKS-OTHER-99', ip: '10.0.9.99' }, data: { md5: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }, rule: { ...atk04.alert.rule, id: '87999' } });
  const incidentId = host.value.incidentId!;
  const inv1 = await db.investigation.findFirstOrThrow({ where: { incidentId, investigationNumber: 1 } });
  // e.g. an analyst-added / re-hunt-carried C2 IP
  await db.threatIntelIoc.create({ data: { incidentId, investigationId: inv1.id, iocType: 'IPV4', iocValue: '203.0.113.200', source: 'ANALYST', status: 'ACTIVE' } });
  const c2 = await deliver({ ...atk04.relatedAlerts[0], agent: { id: '100', name: 'WKS-THIRD-01', ip: '10.0.9.100' }, data: { dstip: '203.0.113.200' } });
  expect(c2.value).toMatchObject({ incidentId, correlation: { reasons: ['SHARED_IOC'], sharedIocs: ['203.0.113.200'] } });
});
