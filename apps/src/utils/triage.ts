// Alert Inbox — SOC review (mirrors backend/src/domain/alert/triageWorkflow.ts). No claim, no owner: any SOC analyst
// reviews an open alert. Severity comes from the Wazuh rule level; AI never provides one.
//   LOW       never shown (outside the SOC workflow)
//   MEDIUM    SOC reviews: create an incident, or close it (False positive / Informational, reason required)
//   HIGH/CRIT incident opened automatically at ingestion; a legacy one without an incident can only become one
import { labelMap, tr } from '../i18n/locale.ts'

export type InboxStatus = 'all' | 'needs-review' | 'in-incident' | 'closed'
export type ReviewDecision = 'CREATE_INCIDENT' | 'FALSE_POSITIVE' | 'INFORMATIONAL'

/** [tab, label]: the label is read in the current language each time (a getter), so a render follows the language. */
export const STATUS_TABS: readonly [InboxStatus, string][] = (['all', 'needs-review', 'in-incident', 'closed'] as const).map((k) => {
  const tab: [InboxStatus, string] = [k, '']
  Object.defineProperty(tab, 1, { enumerable: true, get: () => tr(`tri.tab.${k}`) })
  return tab
})
export const DECISION_LABEL: Record<ReviewDecision, string> = labelMap({ CREATE_INCIDENT: 'tri.dec.CREATE_INCIDENT', FALSE_POSITIVE: 'tri.dec.FALSE_POSITIVE', INFORMATIONAL: 'tri.dec.INFORMATIONAL' })
export const STATUS_LABEL: Record<string, string> = labelMap({ NEEDS_REVIEW: 'tri.st.NEEDS_REVIEW', MONITORING: 'tri.st.MONITORING', CLOSED: 'tri.st.CLOSED', IN_INCIDENT: 'tri.st.IN_INCIDENT' })

export interface ReviewFacts { severity: string; actionable: boolean }

/** Decisions the SOC may take on this alert (empty when it is decided, in an incident, or not in the SOC workflow). */
export function reviewDecisions(a: ReviewFacts): ReviewDecision[] {
  if (!a.actionable) return []
  return a.severity.toLowerCase() === 'medium' ? ['CREATE_INCIDENT', 'FALSE_POSITIVE', 'INFORMATIONAL'] : ['CREATE_INCIDENT']
}
export const reasonRequired = (d: ReviewDecision) => d !== 'CREATE_INCIDENT'

export const available = (v: unknown): string => (v === null || v === undefined || v === '' ? tr('c.notAvailable') : String(v))
