import type { DashboardSummary } from '@/api/vigix'

/**
 * SOC Operations Report (daily / weekly / 1-month / 3-month windows) — the T-NET company template (VIGIX_Monthly_SOC_Report_From_Template.docx) as data.
 * The company header, section order and table layout are the template; every value inside is editable and is
 * pre-filled from the live VIGIX summary. Pure (no DOM / no fetch) so it runs under `node --test`.
 * Rendered by utils/socReportDocx.ts (Word) and utils/socReportHtml.ts (print / PDF).
 */

export const COMPANY = {
  name: 'บริษัท ที-เน็ต ไอ ทีโซลูชั่น จำกัด',
  address: ['131 อาคารกลุ่มนวัตกรรม 1 ชั้น 2 ห้อง INC1-212 หมู่ 9', 'ถนนพหลโยธิน ตำบลคลองหนึ่ง อำเภอคลองหลวง จังหวัดปทุมธานี 12120'],
  contact: 'Tel. 02-564-7210 ต่อ 5512  Email. info@tnetitsolution.co.th',
}

/** Template colours (hex without #, as Word stores them). */
export const REPORT_COLORS = {
  header: '24557F',
  border: 'B7B7B7',
  kpiFill: 'F7F7F7',
  noteFill: 'FFF2CC',
  noteBorder: 'D9A441',
  noteText: '444444',
}
const SEVERITY_FILL: Record<string, string> = { CRITICAL: 'F4CCCC', HIGH: 'FCE4D6', MEDIUM: 'EAF1F7', LOW: 'F2F2F2' }
/** Fill of a severity cell in the template's severity table (CRITICAL/HIGH/MEDIUM/LOW), otherwise null. */
export const severityFill = (text: string): string | null => SEVERITY_FILL[text.trim().toUpperCase()] ?? null

export type Align = 'left' | 'center'
export interface KpiBlock {
  kind: 'kpis'
  items: { label: string; value: string }[]
}
export interface TableBlock {
  kind: 'table'
  columns: string[]
  /** Relative column widths (scaled to the page width on export). */
  widths: number[]
  align: Align[]
  rows: string[][]
  /** Colour the first cell by severity (template severity table). */
  severityTone?: boolean
}
export interface TextBlock {
  kind: 'text'
  text: string
}
/** Bold sub-heading inside a section (e.g. "การกระจายตามระดับความรุนแรง (Severity)"). */
export interface HeadingBlock {
  kind: 'heading'
  text: string
}
/** Yellow remark box (template note row). */
export interface NoteBlock {
  kind: 'note'
  text: string
}
export type ReportBlock = KpiBlock | TableBlock | TextBlock | HeadingBlock | NoteBlock

export interface ReportSection {
  id: string
  title: string
  include: boolean
  pageBreakBefore?: boolean
  blocks: ReportBlock[]
}

export interface SocReport {
  version: 3
  /** Report window (see REPORT_WINDOWS). */
  period: ReportWindow
  title: string
  subtitle: string
  /** Label/value pairs, laid out two per row like the template's cover table. */
  meta: { label: string; value: string }[]
  sections: ReportSection[]
  footer: string
}

const THAI_MONTHS = ['มกราคม', 'กุมภาพันธ์', 'มีนาคม', 'เมษายน', 'พฤษภาคม', 'มิถุนายน', 'กรกฎาคม', 'สิงหาคม', 'กันยายน', 'ตุลาคม', 'พฤศจิกายน', 'ธันวาคม']
const THAI_MONTHS_SHORT = ['ม.ค.', 'ก.พ.', 'มี.ค.', 'เม.ย.', 'พ.ค.', 'มิ.ย.', 'ก.ค.', 'ส.ค.', 'ก.ย.', 'ต.ค.', 'พ.ย.', 'ธ.ค.']

/** '2026-09' -> 'กันยายน 2569' (Buddhist era). */
export function thaiMonthYear(period: string, short = false): string {
  const [y, m] = period.split('-').map(Number)
  if (!y || !m || m < 1 || m > 12) return period
  return `${(short ? THAI_MONTHS_SHORT : THAI_MONTHS)[m - 1]} ${y + 543}`
}
/** Date -> '30 กันยายน 2569' ('30 ก.ย. 2569' when short). */
export function thaiDate(d: Date, short = false): string {
  return `${d.getDate()} ${(short ? THAI_MONTHS_SHORT : THAI_MONTHS)[d.getMonth()]} ${d.getFullYear() + 543}`
}

/**
 * Report windows, each ending at the moment of preparation: daily = since local midnight, weekly = the last 7×24 hours,
 * 1 / 3 months = back to the same date and time 1 / 3 calendar months earlier (clamped to the month's last day).
 */
export const REPORT_WINDOWS = [
  { key: 'daily', days: 0, months: 0, label: 'รายงานประจำวัน' },
  { key: 'weekly', days: 7, months: 0, label: 'รายงานประจำสัปดาห์' },
  { key: '1m', days: 0, months: 1, label: 'รายงาน 1 เดือน' },
  { key: '3m', days: 0, months: 3, label: 'รายงาน 3 เดือน' },
] as const
export type ReportWindow = (typeof REPORT_WINDOWS)[number]['key']
export const DEFAULT_WINDOW: ReportWindow = 'weekly'
const windowOf = (w: ReportWindow) => REPORT_WINDOWS.find((x) => x.key === w) ?? REPORT_WINDOWS[0]
export const isReportWindow = (x: unknown): x is ReportWindow => REPORT_WINDOWS.some((w) => w.key === x)

/** First instant counted in the window ending at `now`. */
export function windowStart(w: ReportWindow, now: Date): Date {
  const { days, months } = windowOf(w)
  if (months) {
    const first = new Date(now.getFullYear(), now.getMonth() - months, 1, now.getHours(), now.getMinutes(), now.getSeconds(), now.getMilliseconds())
    const lastDay = new Date(first.getFullYear(), first.getMonth() + 1, 0).getDate()
    first.setDate(Math.min(now.getDate(), lastDay))
    return first
  }
  if (days === 0) return new Date(now.getFullYear(), now.getMonth(), now.getDate())
  return new Date(now.getTime() - days * 86_400_000)
}
/** Cover text: 'รายงานประจำวัน (30 กันยายน 2569)' / 'รายงานประจำสัปดาห์ (23 ก.ย. 2569 – 30 ก.ย. 2569)'. */
export function windowLabel(w: ReportWindow, now: Date): string {
  const { label, days, months } = windowOf(w)
  if (!days && !months) return `${label} (${thaiDate(now)})`
  return `${label} (${thaiDate(windowStart(w, now), true)} – ${thaiDate(now, true)})`
}

export const NO_DATA = 'ไม่มีข้อมูล'
/** 1 decimal percentage, '—' when the base is 0. */
export function pct(n: number, of: number): string {
  if (!of) return '—'
  const v = Math.round((n / of) * 1000) / 10
  return `${Number.isInteger(v) ? v.toFixed(0) : v.toFixed(1)}%`
}
/** Minutes -> '24 นาที' / '3 ชม. 12 นาที' / '2 วัน 4 ชม.'; null -> 'ไม่มีข้อมูล'. */
export function thaiDuration(min: number | null | undefined): string {
  if (min == null || !Number.isFinite(min)) return NO_DATA
  const m = Math.round(min)
  if (m < 60) return `${m} นาที`
  if (m < 1440) return `${Math.floor(m / 60)} ชม. ${m % 60} นาที`
  return `${Math.floor(m / 1440)} วัน ${Math.floor((m % 1440) / 60)} ชม.`
}

const sum = (r: Record<string, number> | undefined) => Object.values(r ?? {}).reduce((a, b) => a + b, 0)
const s = (n: number) => String(n)

function table(columns: string[], widths: number[], align: Align[], rows: string[][], severityTone = false): TableBlock {
  return { kind: 'table', columns, widths, align, rows, severityTone }
}

/**
 * Build the report from the live summary. `d` must be fetched for the same window (dashboardApi.summary with
 * `since = windowStart(period, preparedAt)`), so event counts cover the window and backlog items are "as of now".
 */
export function buildSocReport(d: DashboardSummary, opts: { period: ReportWindow; preparedAt: Date }): SocReport {
  const byStatus = d.incidents.byStatus
  const totalIncidents = d.incidents.total
  const resolved = byStatus.resolved ?? 0
  const openInProgress = (byStatus.open ?? 0) + (byStatus.investigating ?? 0)
  const escalated = byStatus.escalated ?? 0
  const dismissed = byStatus.dismissed ?? 0

  // IR decisions (IR_TEAM is the only approver; older rows may still name a retired role and are counted in the totals).
  const approvalByStatus: Record<string, number> = {}
  for (const statuses of Object.values(d.approvals.byRoleStatus)) for (const [k, n] of Object.entries(statuses)) approvalByStatus[k] = (approvalByStatus[k] ?? 0) + n
  const ir = d.approvals.byRoleStatus.IR_TEAM ?? {}
  const approvalRequests = sum(approvalByStatus)
  const approved = approvalByStatus.approved ?? 0
  const rejected = approvalByStatus.rejected ?? 0
  const pendingApproval = (approvalByStatus.pending ?? 0) + (approvalByStatus.waiting ?? 0)
  const moreEvidence = approvalByStatus.more_evidence_requested ?? 0

  const responsePlans = sum(d.responses.byStatus)
  const completedPlans = d.responses.byStatus.COMPLETED ?? 0
  const verifTotal = sum(d.verifications.byResult)
  const verifResolved = d.verifications.byResult.RESOLVED ?? 0
  const verifNotResolved = d.verifications.byResult.NOT_RESOLVED ?? 0
  const awaitingRehunt = d.verificationDetail.awaitingRehunt
  const sev = d.severityDistribution
  const sevTotal = sev.CRITICAL + sev.HIGH + sev.MEDIUM + sev.LOW
  const asOf = thaiDate(new Date(d.generatedAt))
  const cycle = windowLabel(opts.period, opts.preparedAt)

  const sections: ReportSection[] = [
    {
      id: 'summary',
      title: 'ส่วนที่ 1 สรุปภาพรวมการดำเนินงาน (Executive Summary)',
      include: true,
      blocks: [
        {
          kind: 'kpis',
          items: [
            { label: 'Incident ทั้งหมด', value: s(totalIncidents) },
            { label: 'ปิดแล้ว', value: s(resolved) },
            { label: 'Response Ticket (IR)', value: s(responsePlans) },
            { label: 'IR อนุมัติ', value: s(ir.approved ?? 0) },
            { label: 'รอตรวจสอบ Verification', value: s(awaitingRehunt) },
            { label: 'เกิน SLA', value: s(d.sla.breached) },
          ],
        },
        {
          kind: 'text',
          text:
            `ในรอบรายงาน ${cycle} VIGIX รับ Alert จาก Wazuh ${d.alerts.total} รายการ และเปิด Incident ${totalIncidents} Case ` +
            `ปิดแล้ว ${resolved} Case (${pct(resolved, totalIncidents)}) อยู่ระหว่างดำเนินการ ${openInProgress} Case และ Escalate ${escalated} Case ` +
            `ผลการตรวจสอบหลังการรับมือ (Re-hunt) ยืนยันว่าควบคุมภัยคุกคามได้ ${verifResolved} จาก ${verifTotal} ครั้ง (${pct(verifResolved, verifTotal)}) ` +
            `และ ณ วันที่ ${asOf} มี Incident ที่เกิน SLA ${d.sla.breached} Case`,
        },
      ],
    },
    {
      id: 'incidents',
      title: 'ส่วนที่ 2 สรุปเหตุการณ์ที่เกิดขึ้น',
      include: true,
      blocks: [
        table(['หัวข้อ', 'จำนวน', 'ร้อยละ', 'หมายเหตุ'], [34, 23, 23, 25], ['left', 'center', 'center', 'left'], [
          ['Incident ทั้งหมด', s(totalIncidents), pct(totalIncidents, totalIncidents), 'ทุกสถานะ'],
          ['Closed / Resolved', s(resolved), pct(resolved, totalIncidents), 'ปิดแล้ว'],
          ['Open / In Progress', s(openInProgress), pct(openInProgress, totalIncidents), 'อยู่ระหว่างดำเนินการ'],
          ['Escalated', s(escalated), pct(escalated, totalIncidents), 'Re-hunt ไม่ผ่านครบ 3 รอบ'],
          ['Merged / Dismissed', s(dismissed), pct(dismissed, totalIncidents), 'รวมกับ Case อื่น / ไม่ใช่ภัยคุกคาม'],
          ['Pending Approval', s(pendingApproval), pct(pendingApproval, approvalRequests), 'ของ Approval Request ทั้งหมด'],
          ['Verification Pending', s(awaitingRehunt), '—', 'รอผลการตรวจสอบ (Re-hunt)'],
        ]),
        { kind: 'heading', text: 'การกระจายตามระดับความรุนแรง (Severity)' },
        table(['Severity', 'จำนวน', 'ร้อยละ', 'แนวทางดำเนินการ'], [34, 23, 23, 25], ['center', 'center', 'center', 'left'], [
          ['CRITICAL', s(sev.CRITICAL), pct(sev.CRITICAL, sevTotal), 'IR approval (Response Ticket)'],
          ['HIGH', s(sev.HIGH), pct(sev.HIGH, sevTotal), 'IR review / response'],
          ['MEDIUM', s(sev.MEDIUM), pct(sev.MEDIUM, sevTotal), 'SOC investigation'],
          ['LOW', s(sev.LOW), pct(sev.LOW, sevTotal), 'SOC monitoring / investigation'],
        ], true),
        { kind: 'heading', text: 'เทคนิค MITRE ATT&CK ที่พบบ่อย (Top Techniques)' },
        table(['Technique', 'Tactic', 'จำนวน Incident'], [30, 45, 25], ['center', 'left', 'center'],
          d.topTechniques.length ? d.topTechniques.slice(0, 5).map((t) => [t.techniqueId, t.tactic, s(t.incidents)]) : [['—', NO_DATA, '0']]),
        { kind: 'heading', text: 'แหล่งที่มาของการโจมตี (Top Attacking Sources)' },
        table(['Source', 'จำนวน Incident'], [60, 40], ['left', 'center'],
          d.topSources.length ? d.topSources.slice(0, 5).map((x) => [x.value, s(x.incidents)]) : [[NO_DATA, '0']]),
      ],
    },
    {
      id: 'ir',
      title: 'ส่วนที่ 3 การปฏิบัติงานของทีม IR และการอนุมัติ',
      include: true,
      blocks: [
        table(['หัวข้อ', 'จำนวน', 'ร้อยละ/เวลา', 'หมายเหตุ'], [34, 20, 20, 26], ['left', 'center', 'center', 'left'], [
          ['Response Ticket ที่ส่งให้ IR', s(responsePlans), pct(completedPlans, responsePlans), `ดำเนินการเสร็จ ${completedPlans} Ticket`],
          ['Approval Request ทั้งหมด', s(approvalRequests), '—', 'ตาม Policy'],
          ['อนุมัติ (Approved)', s(approved), pct(approved, approvalRequests), `IR ${ir.approved ?? 0} (การตัดสินใจของ IR)`],
          ['ปฏิเสธ (Rejected)', s(rejected), pct(rejected, approvalRequests), 'ต้องทบทวนเหตุผล/เงื่อนไข'],
          ['ขอหลักฐานเพิ่ม (ข้อมูลเดิม)', s(moreEvidence), pct(moreEvidence, approvalRequests), 'Legacy: more evidence requested'],
          ['รออนุมัติ', s(pendingApproval), pct(pendingApproval, approvalRequests), 'ค้าง ณ วันที่จัดทำรายงาน'],
          ['เวลาอนุมัติเฉลี่ย', '-', thaiDuration(d.kpi.timeToDecisionMinutes), 'Request → Decision'],
        ]),
        { kind: 'heading', text: 'แนวโน้มเมื่อเทียบกับรอบก่อน (Trend)' },
        table(['ตัวชี้วัด', 'รอบก่อน', 'รอบนี้', 'เปลี่ยนแปลง'], [34, 22, 22, 22], ['left', 'center', 'center', 'center'], [
          ['Incident ทั้งหมด', '—', s(totalIncidents), '—'],
          ['Closed', '—', s(resolved), '—'],
          ['Response Ticket (IR)', '—', s(responsePlans), '—'],
          ['Approved', '—', s(approved), '—'],
          ['Average Resolution Time', '—', thaiDuration(d.incidents.mttrMinutes), '—'],
        ]),
      ],
    },
    {
      id: 'timing',
      title: 'ส่วนที่ 4 ระยะเวลาและผลสำเร็จของการรับมือ',
      include: true,
      pageBreakBefore: true,
      blocks: [
        table(['ตัวชี้วัด', 'ผลรอบนี้', 'รายละเอียด'], [34, 22, 44], ['left', 'center', 'left'], [
          ['Average Investigation Time', thaiDuration(d.kpi.investigationTimeMinutes), `Incident opened → first recommendation (${d.kpi.investigationSamples} Case)`],
          ['Average Time-to-Decision', thaiDuration(d.kpi.timeToDecisionMinutes), `Approval requested → final decision (${d.kpi.decisionSamples} Case)`],
          ['Average Resolution Time', thaiDuration(d.incidents.mttrMinutes), 'Incident → Resolved'],
          ['Verification Success', pct(verifResolved, verifTotal), `${verifResolved} จาก ${verifTotal} ครั้งที่ตรวจสอบแล้วไม่พบความผิดปกติ`],
          ['Automation Success', d.kpi.automationSuccessRate == null ? NO_DATA : `${Math.round(d.kpi.automationSuccessRate)}%`, `จาก ${d.kpi.automationFinished} Response ที่ทำงานเสร็จ`],
          ['SLA Breached', `${d.sla.breached} Case`, `At risk ${d.sla.atRisk} / On track ${d.sla.onTrack} — ควรทบทวนสาเหตุและการแจ้งเตือน`],
        ]),
      ],
    },
    {
      id: 'verification',
      title: 'ส่วนที่ 5 ผลการตรวจสอบหลังการรับมือ (Verification Outcome)',
      include: true,
      blocks: [
        table(['ผลการตรวจสอบ', 'จำนวน', 'ร้อยละ', 'การดำเนินการต่อ'], [30, 18, 24, 28], ['left', 'center', 'center', 'left'], [
          ['Normal / Resolved', s(verifResolved), pct(verifResolved, verifTotal), 'ปิด Case'],
          ['Still Abnormal', s(verifNotResolved), pct(verifNotResolved, verifTotal), 'วิเคราะห์ต่อ / Re-hunt ซ้ำ'],
          ['Awaiting Re-hunt', s(awaitingRehunt), '—', 'รอตรวจสอบหลัง Response'],
          ['Escalated', s(d.verificationDetail.escalatedIncidents), pct(d.verificationDetail.escalatedIncidents, totalIncidents) + ' ของ Incident', 'Escalate / เปิด Response Ticket เพิ่มเติม'],
        ]),
      ],
    },
    {
      id: 'improvement',
      title: 'ส่วนที่ 6 ข้อเสนอแนะเพื่อการปรับปรุงและพัฒนารอบถัดไป (Improvement & Development)',
      include: true,
      pageBreakBefore: true,
      blocks: [
        {
          kind: 'text',
          text: 'หลักการ: ใช้ข้อมูลจากเหตุการณ์และผลการปฏิบัติงานในรอบรายงานเพื่อระบุช่องว่างของ Knowledge, Playbook, Policy, Detection และ Workflow แล้วกำหนด Action ที่ติดตามได้ในรอบถัดไป',
        },
        table(['ด้านที่พัฒนา', 'สิ่งที่พบจาก Report', 'ข้อเสนอแนะ / สิ่งที่ควรพัฒนา', 'Priority', 'ผู้รับผิดชอบ'], [16, 27, 33, 10, 14], ['left', 'left', 'left', 'center', 'center'], [
          ['Knowledge Base', 'Incident บางประเภทเกิดซ้ำและใช้ Evidence/ขั้นตอนคล้ายกัน', 'เพิ่ม/ปรับ Knowledge Article สำหรับ Incident Type ที่พบบ่อย พร้อม Evidence สำคัญ', 'สูง', 'SOC / IR'],
          ['Playbook', `มี Re-hunt ที่ยังพบความผิดปกติ ${verifNotResolved} ครั้ง`, 'ทบทวน Playbook ให้ครอบคลุม Validate → Containment → Response → Verification และกำหนด Exit Criteria', 'สูง', 'IR'],
          ['Policy', `มี Case รอ Approval ${pendingApproval} รายการ และเกิน SLA ${d.sla.breached} Case`, 'ทบทวน Approval Rule, Assignment และ SLA ให้สอดคล้องกับ Severity/ภาระงาน', 'สูง', 'SOC / IR'],
          ['Detection / Wazuh', `Alert ในรอบ ${d.alerts.total} รายการ (ยังไม่ผูก Incident ${d.alerts.unlinked})`, 'ทบทวน Wazuh Rule / Threshold / Suppression และเพิ่ม Rule สำคัญ', 'กลาง', 'SOC'],
          ['AI / RAG', 'มีบาง Case ที่ Analyst ปรับ Severity/ข้อเสนอแนะจาก AI', 'เก็บ feedback และเพิ่ม Evidence/Knowledge เพื่อปรับ Retrieval และ Recommendation', 'กลาง', 'AI / SOC'],
          ['Workflow / Notification', `SLA at risk ${d.sla.atRisk} Case`, 'เพิ่ม Notification / Escalation ก่อนครบ SLA และติดตาม Pending State จาก Dashboard', 'กลาง', 'Platform / SOC'],
          ['Verification', `รอ Re-hunt ${awaitingRehunt} รายการ`, 'ปรับ Query Template และเกณฑ์ Verification ให้สอดคล้องกับ Incident Type/Playbook', 'กลาง', 'IR / SOC'],
        ]),
      ],
    },
    {
      id: 'plan',
      title: 'ส่วนที่ 7 แผนงานที่ควรติดตามในรอบถัดไป',
      include: true,
      blocks: [
        table(['ลำดับ', 'Action', 'ผลลัพธ์ที่คาดหวัง', 'สถานะ'], [9, 40, 35, 16], ['center', 'left', 'left', 'center'], [
          ['1', 'Update Knowledge Base และ Playbook สำหรับ Top Incident Types', 'ลด Investigation Time / ลดการพึ่งพาความรู้เฉพาะบุคคล', 'Planned'],
          ['2', 'Review Policy / Approval / SLA จาก Case ที่เกิน SLA', 'ลด Case ค้างและทำให้การ Escalate ชัดเจนขึ้น', 'Planned'],
          ['3', 'Review Wazuh Detection Rules และ Alert Noise', 'ลด Alert ที่ไม่เกิดประโยชน์และเพิ่มคุณภาพ Signal', 'Planned'],
          ['4', 'เก็บ Analyst Feedback ต่อ AI Recommendation', 'ปรับปรุง Evidence และ Recommendation Quality', 'Planned'],
          ['5', 'ปรับ Verification / Re-hunt Template', 'เพิ่มความสม่ำเสมอในการยืนยันผลหลัง Response', 'Planned'],
        ]),
        {
          kind: 'note',
          text:
            `หมายเหตุ: ตัวเลขในรายงานนี้ดึงจาก VIGIX ณ วันที่ ${asOf} นับเฉพาะเหตุการณ์ในรอบรายงาน ${cycle} ` +
            'ส่วนรายการค้าง (รออนุมัติ, รอ Re-hunt, SLA) เป็นสถานะ ณ วันที่จัดทำรายงาน ' +
            'โดยแยก Wazuh Rule Level ออกจาก VIGIX Severity และไม่ใช้ Risk Score เป็นเกณฑ์ตัดสินใจ กรุณาตรวจทานก่อนเผยแพร่',
        },
      ],
    },
    {
      id: 'references',
      title: 'ส่วนที่ 8 ข้อมูลอ้างอิง',
      include: true,
      blocks: [
        table(['แหล่งข้อมูล', 'ข้อมูลที่ใช้ในรายงาน'], [35, 65], ['left', 'left'], [
          ['VIGIX Incident Records', 'จำนวน, Status, Severity, Type, Timestamp'],
          ['Approval + Response Tickets', 'Approval Request, Decision, Approver, IR Assignment, Response Status'],
          ['Verification Records', 'Re-hunt, Result, Verification Status'],
          ['SLA / Audit Log', 'Investigation Time, Time-to-Decision, Resolution Time, SLA Breach, key timestamps'],
        ]),
      ],
    },
  ]

  return {
    version: 3,
    period: opts.period,
    title: 'รายงานสรุปการปฏิบัติงานด้านความมั่นคงปลอดภัย (SOC Operations Report)',
    subtitle: 'สำหรับทีม SOC และทีม Incident Response (IR)  |  VIGIX',
    meta: [
      { label: 'รอบรายงาน', value: cycle },
      { label: 'วันที่จัดทำ', value: thaiDate(opts.preparedAt) },
      { label: 'แหล่งข้อมูล', value: 'VIGIX / Wazuh' },
      { label: 'กลุ่มผู้รับรายงาน', value: 'SOC / IR' },
      { label: 'สถานะข้อมูล', value: `ข้อมูลจริงจากระบบ ณ ${asOf}` },
      { label: 'หลักการคำนวณ', value: 'ข้อมูล Incident + Approval + Response + Verification + SLA' },
    ],
    sections,
    footer: 'VIGIX • SOC Operations Report',
  }
}

/** Accept only a well-formed saved draft (localStorage may hold an older shape, e.g. a v2 monthly report). */
export function isSocReport(x: unknown): x is SocReport {
  const r = x as SocReport
  return !!r && r.version === 3 && isReportWindow(r.period) && typeof r.title === 'string' && Array.isArray(r.meta) && Array.isArray(r.sections)
}
