import type { IncidentStatus, StepStatus } from './common'
import type { AssetEvidence, IocRecord } from './investigation'

export type ResponseStepKey =
  | 'CONTAINMENT'
  | 'INVESTIGATION'
  | 'THREAT_HUNTING'
  | 'ERADICATION'
  | 'RECOVERY'
  | 'VERIFICATION'

/** The function a task falls under inside an IR engagement — who should pick it up. */
export type ResponseDuty = 'IR Lead' | 'IR Engineer' | 'Malware Analyst' | 'Threat Hunter' | 'System Owner'

export interface ResponseTask {
  id: string
  text: string
  /** Optional how-to: console path, tool or command to use. */
  hint?: string
  duty: ResponseDuty
  /** Required tasks must be checked off before the step can be completed. */
  required: boolean
  done: boolean
  doneBy?: string
  doneAt?: string
}

/** What kind of action a recommended-action card describes — drives its icon. */
export type ResponseActionKind = 'block-ip' | 'isolate-host' | 'lock-accounts' | 'waf-rule' | 'quarantine-file' | 'purge-email' | 'block-egress'

/** One numbered stage of doing an action: what to do, and how to do it. */
export interface ResponseActionStep {
  what: string
  how: string
  /** Optional command, query or rule the responder can copy. */
  command?: string
}

/** A recommended action (e.g. "Block IP") together with the procedure for carrying it out. */
export interface ResponseAction {
  id: string
  kind: ResponseActionKind
  title: string
  /** Why this action is recommended for this incident. */
  summary: string
  duty: ResponseDuty
  steps: ResponseActionStep[]
}

export interface ResponseStep {
  order: number
  key: ResponseStepKey
  title: string
  status: StepStatus
  owner: string
  startTime?: string
  completedTime?: string
  action: string
  result?: string
  evidence?: string[]
  comment?: string
  // --- Runbook detail (filled in lazily from the response playbook) ---
  objective?: string
  evidenceRequired?: string
  expectedResult?: string
  /** Target time to finish this step, e.g. "15 min". */
  target?: string
  tasks?: ResponseTask[]
  /** What the investigation's approved recommendation said to do in this step. */
  recommendedAction?: string
  /** Recommended actions with their how-to procedure; the first one is the primary recommendation. */
  actions?: ResponseAction[]
}

export interface ResponseProcess {
  incidentId: string
  steps: ResponseStep[]
}

export interface IrTeamMember {
  name: string
  title: string
  initials: string
  /** What this person is strongest at — drives the suggested owner for each step. */
  duties: ResponseDuty[]
  /** Response steps this person currently has in progress, across all incidents. */
  activeSteps: number
}

/** Everything the Response page needs, as one read model (the shape a real API would return). */
export interface Runbook {
  incidentId: string
  status: IncidentStatus
  steps: ResponseStep[]
  playbook: string
  organizationPolicy: string
  ragSources: string[]
  team: IrTeamMember[]
  asset: AssetEvidence
  iocs: IocRecord[]
}
