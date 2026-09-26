import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { DashboardSummary } from '../api/vigix.ts'
import { activityText, attention, caseFlow, caseStep, dueText, healthSummary, myWork, thaiAgo, thaiDuration } from './dashboard.ts'

const d = {
  generatedAt: '2026-09-26T00:00:00Z',
  alerts: { total: 0, last24h: 0, unlinked: 0, bySeverity: {}, daily: [] },
  incidents: { total: 9, byStatus: { open: 2, investigating: 3, resolved: 4, escalated: 1 }, openByPriority: {}, mttrMinutes: 90, resolvedLast7d: 0, openedLast7d: 0 },
  responses: { byStatus: { PENDING_IR_DECISION: 2, PENDING_APPROVAL: 1, READY_FOR_EXECUTION: 1, IN_PROGRESS: 2, FAILED: 1, COMPLETED: 5 }, pendingApprovalsByRole: {} },
  verifications: { byResult: { RESOLVED: 4, NOT_RESOLVED: 1 } },
  topTechniques: [], topSources: [], activity: [],
  sla: { breached: 2, atRisk: 1, onTrack: 3, notStarted: 0, watchlist: [] },
  integrations: {} as never,
  aiJobs: { byStatus: { FAILED: 1 }, total: 1 },
  triage: { pending: 0, pendingLow: 0, monitoring: 0, byDisposition: {} },
  approvals: { byRoleStatus: {} },
  verificationDetail: { spread: 0, awaitingRehunt: 3, escalationEvents: 0, escalatedIncidents: 1 },
  recommendationReady: 2,
  severityDistribution: { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, unknown: 0 },
  kpi: { investigationTimeMinutes: null, investigationSamples: 0, timeToDecisionMinutes: null, decisionSamples: 0, workload: [], automationSuccessRate: null, automationFinished: 0 },
  systemHealth: [
    { key: 'db', label: 'PostgreSQL', status: 'UP', detail: null, latencyMs: 2 },
    { key: 'qdrant', label: 'Qdrant', status: 'DOWN', detail: 'refused', latencyMs: null },
    { key: 'wazuh', label: 'Wazuh Manager', status: 'UNKNOWN', detail: null, latencyMs: null },
  ],
} as unknown as DashboardSummary

test('SOC sees its own work first: review alerts -> investigate -> send to IR, one button each', () => {
  const cards = myWork('SOC', d, 7)
  assert.deepEqual(cards.map((c) => [c.key, c.value, c.to]), [
    ['review', 7, '/alerts?status=needs-review'],
    ['investigate', 5, '/incidents?view=investigation'],
    ['send', 2, '/incidents?view=recommendation'],
  ])
  assert.ok(cards.every((c) => c.cta && c.hint))
})

test('IR sees decide -> start -> in progress -> re-hunt; legacy PENDING_APPROVAL counts as awaiting the IR decision', () => {
  assert.deepEqual(myWork('IR_TEAM', d, null).map((c) => [c.key, c.value]), [['decide', 3], ['ready', 1], ['progress', 2], ['rehunt', 3]])
})

test('admin sees both sides read-only; an unknown inbox count stays unknown (never a made-up 0)', () => {
  const cards = myWork('admin', d, null)
  assert.equal(cards.length, 7)
  assert.ok(cards.every((c) => c.cta === 'ดูรายการ'))
  assert.equal(cards[0].value, null)
})

test('the case flow covers every stage, in order, each linking to its filtered list', () => {
  const flow = caseFlow(d, 7)
  assert.deepEqual(flow.map((s) => s.who), ['SOC', 'SOC', 'SOC', 'IR', 'IR', 'IR', 'ผลลัพธ์', 'ผลลัพธ์'])
  assert.deepEqual(flow.map((s) => s.value), [7, 5, 2, 3, 3, 3, 4, 1])
  assert.ok(flow.every((s) => s.to.startsWith('/')))
})

test('attention lists only what needs action now, most urgent kinds included', () => {
  const keys = attention(d).map((a) => a.key)
  assert.deepEqual(keys, ['sla-breached', 'sla-risk', 'escalated', 'failed', 'ai-failed', 'down-qdrant'])
  const calm = attention({ ...d, sla: { ...d.sla, breached: 0, atRisk: 0 }, incidents: { ...d.incidents, byStatus: {} }, responses: { ...d.responses, byStatus: {} }, aiJobs: { byStatus: {}, total: 0 }, systemHealth: [] })
  assert.deepEqual(calm, [])
})

test('system health: UNKNOWN / not configured are not counted as healthy or broken', () => {
  assert.deepEqual(healthSummary(d.systemHealth), { ok: 1, total: 2, problems: ['Qdrant'], tone: 'danger' })
})

test('one vocabulary for the current step of a case', () => {
  const s = (status: string, responseStatus: string | null, lastVerification: string | null = null) => caseStep({ status, responseStatus, lastVerification }).label
  assert.equal(s('investigating', null), 'กำลังสืบสวน')
  assert.equal(s('investigating', 'PENDING_IR_DECISION'), 'รอ IR ตัดสินใจ')
  assert.equal(s('investigating', 'PENDING_APPROVAL'), 'รอ IR ตัดสินใจ')
  assert.equal(s('investigating', 'READY_FOR_EXECUTION'), 'อนุมัติแล้ว รอลงมือ')
  assert.equal(s('investigating', 'COMPLETED'), 'รอ Re-hunt')
  assert.equal(s('investigating', 'COMPLETED', 'NOT_RESOLVED'), 'กำลังสืบสวนรอบใหม่')
  assert.equal(s('investigating', 'REJECTED'), 'IR ปฏิเสธ — SOC ทบทวน')
  assert.equal(s('resolved', 'COMPLETED', 'RESOLVED'), 'แก้ไขแล้ว')
  assert.equal(s('escalated', 'COMPLETED', 'NOT_RESOLVED'), 'ยกระดับ')
})

test('durations and due times read naturally in Thai', () => {
  assert.equal(thaiDuration(null), 'ไม่มีข้อมูล')
  assert.equal(thaiDuration(0), 'ไม่ถึง 1 นาที')
  assert.equal(thaiDuration(45), '45 นาที')
  assert.equal(thaiDuration(125), '2 ชม. 5 นาที')
  assert.equal(thaiDuration(1500), '1 วัน 1 ชม.')
  const now = Date.parse('2026-09-26T00:00:00Z')
  assert.equal(dueText('2026-09-26T00:30:00Z', now), 'ครบกำหนดอีก 30 นาที')
  assert.equal(dueText('2026-09-25T23:20:00Z', now), 'เกินมาแล้ว 40 นาที')
})

test('relative time reads in Thai', () => {
  const now = Date.parse('2026-09-26T12:00:00Z')
  assert.equal(thaiAgo('2026-09-26T11:59:40Z', now), 'เมื่อสักครู่')
  assert.equal(thaiAgo('2026-09-26T11:33:00Z', now), '27 นาทีที่แล้ว')
  assert.equal(thaiAgo('2026-09-26T07:00:00Z', now), '5 ชม.ที่แล้ว')
  assert.equal(thaiAgo('2026-09-23T12:00:00Z', now), '3 วันที่แล้ว')
})

test('activity feed: plain Thai, no Policy codes, no AI severity / risk score, Wazuh rule kept as evidence', () => {
  const auto = 'Incident opened automatically: HIGH Wazuh alert (rule 5712, level 12) — Policy RULE-A03, RULE-P02, RULE-P07, RULE-I03, POL-003.'
  assert.equal(activityText('created', auto), 'เปิด Incident อัตโนมัติจาก Alert HIGH ของ Wazuh (rule 5712, level 12)')
  const ai = activityText('ai_analysis_complete', 'AI pipeline completed: decision=auto_response (advisory), suggested severity=medium')
  assert.ok(!/severity|risk|decision=/i.test(ai))
  assert.equal(activityText('status_changed', 'Status changed to resolved — Policy RULE-V01. decision=x risk_score=40.0 suggested severity=high'), 'Status changed to resolved.')
})

test('the same view-model in English when the TH/EN switch is on EN (numbers and links unchanged)', () => {
  const th = myWork('SOC', d, 7)
  const en = myWork('SOC', d, 7, 'en')
  assert.deepEqual(en.map((c) => [c.key, c.value, c.to]), th.map((c) => [c.key, c.value, c.to]))
  assert.equal(en[0].cta, 'Review alerts')
  assert.equal(attention(d, 'en')[0].text, '2 cases breached SLA')
  assert.equal(caseStep({ status: 'investigating', responseStatus: 'PENDING_IR_DECISION', lastVerification: null }, 'en').label, 'Awaiting IR decision')
  assert.equal(thaiDuration(125, 'en'), '2 h 5 min')
  assert.equal(dueText('2026-09-25T23:20:00Z', Date.parse('2026-09-26T00:00:00Z'), 'en'), 'overdue by 40 min')
  assert.equal(thaiAgo('2026-09-26T11:33:00Z', Date.parse('2026-09-26T12:00:00Z'), 'en'), '27 min ago')
})
