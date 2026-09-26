import type { Severity, IncidentStatus, MatchVerdict, StepStatus } from '@/types'
import { dateLocale, labelMap } from '../i18n/locale.ts'

/** Anchor "now" for the demo dataset — keeps mock timestamps stable and relative. */
export const DEMO_NOW = new Date('2026-09-15T09:00:00+07:00')

export function isoOffset(daysAgo: number, hour = 9, minute = 0): string {
  const d = new Date(DEMO_NOW)
  d.setDate(d.getDate() - daysAgo)
  d.setHours(hour, minute, 0, 0)
  return d.toISOString()
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString(dateLocale(), {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

export function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleDateString(dateLocale(), { day: '2-digit', month: 'short', year: 'numeric' })
}

export function timeAgo(iso: string): string {
  const diffMs = DEMO_NOW.getTime() - new Date(iso).getTime()
  const mins = Math.round(diffMs / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.round(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.round(hours / 24)
  return `${days}d ago`
}

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_LABEL: Record<Severity, string> = labelMap({ CRITICAL: 'sev.CRITICAL', HIGH: 'sev.HIGH', MEDIUM: 'sev.MEDIUM', LOW: 'sev.LOW' })

export const SEVERITY_CLASSES: Record<Severity, { bg: string; text: string; border: string; dot: string; solidBg: string }> = {
  CRITICAL: { bg: 'bg-critical-50', text: 'text-critical-700', border: 'border-critical-200', dot: 'bg-critical-500', solidBg: 'bg-critical-500' },
  HIGH: { bg: 'bg-high-50', text: 'text-high-700', border: 'border-high-200', dot: 'bg-high-500', solidBg: 'bg-high-500' },
  MEDIUM: { bg: 'bg-medium-50', text: 'text-medium-700', border: 'border-medium-200', dot: 'bg-medium-500', solidBg: 'bg-medium-500' },
  LOW: { bg: 'bg-low-50', text: 'text-low-700', border: 'border-low-200', dot: 'bg-low-500', solidBg: 'bg-low-500' },
}

export const STATUS_LABEL: Record<IncidentStatus, string> = {
  NEW: 'New',
  INVESTIGATING: 'Investigating',
  VALIDATION: 'Validation',
  ASSIGNED: 'Assigned',
  WAITING_APPROVAL: 'Waiting Approval',
  APPROVED: 'Approved',
  RESPONDING: 'Responding',
  VERIFYING: 'Verifying',
  RE_INVESTIGATING: 'Re-investigating',
  RESOLVED: 'Resolved',
  CLOSED: 'Closed',
  ESCALATED: 'Escalated',
}

export const STATUS_CLASSES: Record<IncidentStatus, string> = {
  NEW: 'bg-slate-100 text-slate-700 border-slate-200',
  INVESTIGATING: 'bg-accent-50 text-accent-700 border-blue-200',
  VALIDATION: 'bg-violet-50 text-violet-700 border-violet-200',
  ASSIGNED: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  WAITING_APPROVAL: 'bg-amber-50 text-amber-700 border-amber-200',
  APPROVED: 'bg-teal-50 text-teal-700 border-teal-200',
  RESPONDING: 'bg-orange-50 text-orange-700 border-orange-200',
  VERIFYING: 'bg-cyan-50 text-cyan-700 border-cyan-200',
  RE_INVESTIGATING: 'bg-fuchsia-50 text-fuchsia-700 border-fuchsia-200',
  RESOLVED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  CLOSED: 'bg-slate-100 text-slate-600 border-slate-200',
  ESCALATED: 'bg-red-100 text-red-800 border-red-300',
}

export function severityFromScore(score: number): Severity {
  if (score >= 75) return 'CRITICAL'
  if (score >= 50) return 'HIGH'
  if (score >= 25) return 'MEDIUM'
  return 'LOW'
}

/** Same wazuhLevel -> band thresholds incidentService.ts uses when creating an incident from an alert — kept here so the raw Alert queue and Incident creation always agree on what a given level means. */
export function priorityFromWazuhLevel(level: number): Severity {
  if (level >= 12) return 'CRITICAL'
  if (level >= 9) return 'HIGH'
  if (level >= 6) return 'MEDIUM'
  return 'LOW'
}

export const VERDICT_LABEL: Record<MatchVerdict, string> = {
  MALICIOUS: 'Malicious',
  SUSPICIOUS: 'Suspicious',
  UNKNOWN: 'Unknown',
  NO_MATCH: 'No Match',
  ERROR_TIMEOUT: 'Error / Timeout',
}

export const VERDICT_CLASSES: Record<MatchVerdict, string> = {
  MALICIOUS: 'bg-critical-50 text-critical-700 border-critical-200',
  SUSPICIOUS: 'bg-high-50 text-high-700 border-high-200',
  UNKNOWN: 'bg-slate-100 text-slate-600 border-slate-200',
  NO_MATCH: 'bg-slate-50 text-slate-500 border-slate-200',
  ERROR_TIMEOUT: 'bg-amber-50 text-amber-700 border-amber-200 italic',
}

export const STEP_STATUS_LABEL: Record<StepStatus, string> = {
  PENDING: 'Pending',
  IN_PROGRESS: 'In Progress',
  COMPLETED: 'Completed',
  SKIPPED: 'Skipped',
}

export const STEP_STATUS_CLASSES: Record<StepStatus, string> = {
  PENDING: 'bg-slate-100 text-slate-500 border-slate-200',
  IN_PROGRESS: 'bg-accent-50 text-accent-700 border-blue-200',
  COMPLETED: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  SKIPPED: 'bg-slate-50 text-slate-400 border-slate-200',
}

export function initials(name: string): string {
  return name
    .split(' ')
    .map((p) => p[0])
    .slice(0, 2)
    .join('')
    .toUpperCase()
}
