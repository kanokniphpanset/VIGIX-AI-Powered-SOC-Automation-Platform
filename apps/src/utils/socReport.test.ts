import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { DashboardSummary } from '../api/vigix.ts'
import { REPORT_WINDOWS, buildSocReport, isSocReport, pct, severityFill, thaiDate, thaiDuration, thaiMonthYear, windowLabel, windowStart, type TableBlock } from './socReport.ts'

const summary = {
  generatedAt: '2026-09-30T10:00:00+07:00',
  alerts: { total: 410, last24h: 12, unlinked: 7, bySeverity: {}, daily: [] },
  incidents: { total: 52, byStatus: { resolved: 41, open: 2, investigating: 4, escalated: 3, dismissed: 2 }, openByPriority: {}, mttrMinutes: 192, resolvedLast7d: 9, openedLast7d: 11 },
  responses: { byStatus: { COMPLETED: 20, IN_PROGRESS: 8 }, pendingApprovalsByRole: {} },
  verifications: { byResult: { RESOLVED: 38, NOT_RESOLVED: 3 } },
  topTechniques: [{ techniqueId: 'T1059', tactic: 'execution', incidents: 9 }],
  topSources: [],
  activity: [],
  sla: { breached: 3, atRisk: 2, onTrack: 5, notStarted: 0, watchlist: [] },
  integrations: {},
  aiJobs: { byStatus: {}, total: 0 },
  triage: { pending: 0, pendingLow: 0, monitoring: 0, byDisposition: {} },
  approvals: { byRoleStatus: { IR_TEAM: { approved: 16, rejected: 1, pending: 1 } } },
  verificationDetail: { spread: 0, awaitingRehunt: 4, escalationEvents: 0, escalatedIncidents: 3 },
  recommendationReady: 0,
  severityDistribution: { LOW: 13, MEDIUM: 23, HIGH: 12, CRITICAL: 4, unknown: 0 },
  kpi: { investigationTimeMinutes: 24, investigationSamples: 40, timeToDecisionMinutes: null, decisionSamples: 0, workload: [], automationSuccessRate: null, automationFinished: 0 },
  systemHealth: [],
} as unknown as DashboardSummary

const report = buildSocReport(summary, { period: 'weekly', preparedAt: new Date(2026, 8, 30, 15, 30) })
const section = (id: string) => report.sections.find((s) => s.id === id)!
const tables = report.sections.flatMap((s) => s.blocks.filter((b): b is TableBlock => b.kind === 'table'))

test('Thai calendar helpers use the Buddhist era', () => {
  assert.equal(thaiMonthYear('2026-09'), 'กันยายน 2569')
  assert.equal(thaiMonthYear('2026-08', true), 'ส.ค. 2569')
  assert.equal(thaiDate(new Date(2026, 8, 30)), '30 กันยายน 2569')
  assert.equal(thaiDate(new Date(2026, 8, 30), true), '30 ก.ย. 2569')
})

test('report windows: daily, weekly, 1 month, 3 months back from preparation', () => {
  assert.deepEqual(REPORT_WINDOWS.map((w) => w.label), ['รายงานประจำวัน', 'รายงานประจำสัปดาห์', 'รายงาน 1 เดือน', 'รายงาน 3 เดือน'])
  const now = new Date(2026, 8, 30, 15, 30)
  assert.deepEqual(windowStart('daily', now), new Date(2026, 8, 30))
  assert.equal(now.getTime() - windowStart('weekly', now).getTime(), 7 * 86_400_000)
  assert.deepEqual(windowStart('1m', now), new Date(2026, 7, 30, 15, 30))
  assert.deepEqual(windowStart('3m', now), new Date(2026, 5, 30, 15, 30))
  // A month back from 31 May is 30 April (clamped), not 1 May.
  assert.deepEqual(windowStart('1m', new Date(2026, 4, 31, 9, 0)), new Date(2026, 3, 30, 9, 0))
  assert.equal(windowLabel('daily', now), 'รายงานประจำวัน (30 กันยายน 2569)')
  assert.equal(windowLabel('weekly', now), 'รายงานประจำสัปดาห์ (23 ก.ย. 2569 – 30 ก.ย. 2569)')
  assert.equal(windowLabel('3m', now), 'รายงาน 3 เดือน (30 มิ.ย. 2569 – 30 ก.ย. 2569)')
})

test('percentages and durations', () => {
  assert.equal(pct(41, 52), '78.8%')
  assert.equal(pct(52, 52), '100%')
  assert.equal(pct(1, 0), '—')
  assert.equal(thaiDuration(24), '24 นาที')
  assert.equal(thaiDuration(192), '3 ชม. 12 นาที')
  assert.equal(thaiDuration(null), 'ไม่มีข้อมูล')
})

test('cover follows the template and the chosen period', () => {
  assert.equal(report.meta.length, 6)
  assert.equal(report.meta[0].value, 'รายงานประจำสัปดาห์ (23 ก.ย. 2569 – 30 ก.ย. 2569)')
  assert.equal(report.meta[1].value, '30 กันยายน 2569')
  assert.deepEqual(report.sections.map((s) => s.id), ['summary', 'incidents', 'ir', 'timing', 'verification', 'improvement', 'plan', 'references'])
})

test('executive summary KPIs come from the live summary', () => {
  const kpis = section('summary').blocks[0]
  assert.equal(kpis.kind, 'kpis')
  if (kpis.kind !== 'kpis') return
  assert.deepEqual(kpis.items.map((k) => k.value), ['52', '41', '28', '16', '4', '3'])
})

test('severity table is coloured like the template', () => {
  const sev = tables.find((t) => t.severityTone)!
  assert.deepEqual(sev.rows.map((r) => [r[0], r[1], r[2]]), [
    ['CRITICAL', '4', '7.7%'],
    ['HIGH', '12', '23.1%'],
    ['MEDIUM', '23', '44.2%'],
    ['LOW', '13', '25%'],
  ])
  assert.equal(severityFill('critical'), 'F4CCCC')
  assert.equal(severityFill('Closed'), null)
})

test('missing metrics say so instead of inventing a number', () => {
  const ir = section('ir').blocks[0] as TableBlock
  assert.equal(ir.rows.find((r) => r[0] === 'เวลาอนุมัติเฉลี่ย')![2], 'ไม่มีข้อมูล')
  const sources = tables.find((t) => t.columns[0] === 'Source')!
  assert.deepEqual(sources.rows, [['ไม่มีข้อมูล', '0']])
})

test('every table is rectangular', () => {
  for (const t of tables) {
    assert.equal(t.widths.length, t.columns.length, t.columns.join('|'))
    assert.equal(t.align.length, t.columns.length, t.columns.join('|'))
    for (const r of t.rows) assert.equal(r.length, t.columns.length, `${t.columns[0]}: ${r.join('|')}`)
  }
})

test('the trend table compares with the previous window, not a month', () => {
  const trend = tables.find((t) => t.columns[3] === 'เปลี่ยนแปลง')!
  assert.deepEqual(trend.columns.slice(1, 3), ['รอบก่อน', 'รอบนี้'])
})

test('drafts of an older shape are rejected', () => {
  assert.equal(isSocReport(report), true)
  assert.equal(isSocReport({ ...report, version: 2, period: '2026-09' }), false)
  assert.equal(isSocReport({ ...report, period: '7d' }), false)
  assert.equal(isSocReport({ title: 'x', sections: [] }), false)
  assert.equal(isSocReport(null), false)
})
