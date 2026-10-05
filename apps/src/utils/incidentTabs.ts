// The four tabs of the incident page and which one opens first (pure; runs under `node --test`).
// Older links and the "ขั้นต่อไป" card still name the eight former tabs (?tab=audit, tab: 'recommendation' …); each one
// maps to the tab that now holds that content, plus the section to scroll to inside it.
import type { NextKey } from './nextStep.ts'

export type IncidentTab = 'overview' | 'evidence' | 'ai' | 'history'
export const INCIDENT_TABS: IncidentTab[] = ['overview', 'evidence', 'ai', 'history']

/** Former tab name (or a current one) → where it lives now. Anchors are element ids on the incident page. */
const LEGACY: Record<string, { tab: IncidentTab; anchor?: string }> = {
  overview: { tab: 'overview' },
  evidence: { tab: 'evidence' },
  investigation: { tab: 'evidence', anchor: 'sec-investigation' },
  ai: { tab: 'ai' },
  recommendation: { tab: 'ai', anchor: 'sec-recommendation' },
  history: { tab: 'history' },
  verification: { tab: 'history', anchor: 'sec-verification' },
  email: { tab: 'history', anchor: 'sec-email' },
  audit: { tab: 'history', anchor: 'sec-audit' },
}

export function resolveTab(name: unknown): { tab: IncidentTab; anchor?: string } | null {
  return typeof name === 'string' && Object.hasOwn(LEGACY, name) ? LEGACY[name] : null
}

/** The tab that holds the work of the current step, opened when the page is entered without ?tab=. */
export function tabForStep(key: NextKey | null | undefined): IncidentTab {
  switch (key) {
    case 'soc-ai':
    case 'soc-recommend':
    case 'soc-regenerate':
    case 'soc-send':
    case 'soc-noaction':
    case 'soc-rejected':
    case 'soc-failed':
      return 'ai'
    case 'ir-rehunt':
    case 'resolved':
    case 'dismissed':
    case 'escalated':
      return 'history'
    default:
      // soc-severity (the severity panel is on the overview) and the IR decide / start / complete steps, whose work
      // happens on the Response Ticket that the card's button opens.
      return 'overview'
  }
}
