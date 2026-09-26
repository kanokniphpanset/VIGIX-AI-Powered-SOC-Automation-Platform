import type { RoleName, Severity } from './common'

/**
 * Lifecycle of a single raw alert as it moves through the triage queue:
 *   NEW       -> just ingested, priority is the vendor/Wazuh-derived value only
 *   GROUPED   -> clustered with other related alerts via "Set Alert"
 *   TRIAGED   -> an analyst has set a working severity (may differ from priority)
 *   ASSIGNED  -> a responsible person/role has been set
 *   PROMOTED  -> converted into a full Incident (see promotedIncidentId)
 *   DISMISSED -> closed out as noise / false positive, never promoted
 */
export type AlertStatus = 'NEW' | 'GROUPED' | 'TRIAGED' | 'ASSIGNED' | 'PROMOTED' | 'DISMISSED'

export interface Alert {
  id: string
  ruleId: string
  ruleDescription: string
  wazuhLevel: number
  /** Vendor/Wazuh-derived priority as received — never edited by hand, always reflects wazuhLevel. */
  priority: Severity
  /** Analyst's own working severity, set via the "Set Alert" bulk action. Null until triaged. */
  severity: Severity | null
  incidentTypeGuess: string
  agent: string
  hostname: string
  sourceIp: string
  destinationIp?: string
  rawLog: string
  status: AlertStatus
  groupId: string | null
  assignedTo: string | null
  assignedRole: RoleName | null
  promotedIncidentId: string | null
  receivedAt: string
  updatedAt: string
}

/** A manually-created cluster of related alerts — the result of selecting several alerts and running "Set Alert". */
export interface AlertGroup {
  id: string
  name: string
  /** Free-text note on why these alerts were clustered together / what's shared about them. */
  description?: string
  severity: Severity | null
  assignedTo: string | null
  assignedRole: RoleName | null
  createdBy: string
  createdAt: string
  alertIds: string[]
}

/** Payload for the bulk "Set Alert" action — every field is optional so a single call can group-only, triage-only, assign-only, or all three at once. */
export interface SetAlertInput {
  alertIds: string[]
  groupName?: string
  description?: string
  existingGroupId?: string
  severity?: Severity
  assignedTo?: string
  assignedRole?: RoleName
}
