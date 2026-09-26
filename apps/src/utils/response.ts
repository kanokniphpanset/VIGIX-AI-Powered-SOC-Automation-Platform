import type { IrTeamMember, ResponseDuty, ResponseStep } from '@/types'

export const DUTY_INFO: Record<ResponseDuty, { description: string; chip: string; dot: string }> = {
  'IR Lead': { description: 'Coordinates the response, owns the case notes and stakeholder communication.', chip: 'bg-violet-50 text-violet-700 border-violet-200', dot: 'bg-violet-500' },
  'IR Engineer': { description: 'Hands-on containment, eradication and recovery on the affected assets.', chip: 'bg-blue-50 text-blue-700 border-blue-200', dot: 'bg-blue-500' },
  'Malware Analyst': { description: 'Forensic preservation and analysis of samples and images.', chip: 'bg-rose-50 text-rose-700 border-rose-200', dot: 'bg-rose-500' },
  'Threat Hunter': { description: 'Searches the wider estate for related activity to size the blast radius.', chip: 'bg-teal-50 text-teal-700 border-teal-200', dot: 'bg-teal-500' },
  'System Owner': { description: 'Business owner of the asset — signs off that service works after recovery.', chip: 'bg-amber-50 text-amber-700 border-amber-200', dot: 'bg-amber-500' },
}

export const DUTY_ORDER: ResponseDuty[] = ['IR Lead', 'IR Engineer', 'Malware Analyst', 'Threat Hunter', 'System Owner']

/**
 * done     – completed
 * skipped  – skipped with a reason
 * active   – in progress now
 * ready    – next up, can be started
 * locked   – an earlier step (or the process itself) hasn't been done yet
 */
export type StepState = 'done' | 'skipped' | 'active' | 'ready' | 'locked'

export function stepState(steps: ResponseStep[], index: number, processRunning: boolean): StepState {
  const step = steps[index]
  if (step.status === 'COMPLETED') return 'done'
  if (step.status === 'SKIPPED') return 'skipped'
  if (step.status === 'IN_PROGRESS') return 'active'
  const blocked = steps.slice(0, index).some((p) => p.status !== 'COMPLETED' && p.status !== 'SKIPPED')
  // Verification is carried out from the Verification tab once everything before it is done.
  const unlocked = step.key === 'VERIFICATION' ? true : processRunning
  return !blocked && unlocked ? 'ready' : 'locked'
}

export function taskProgress(step: ResponseStep) {
  const tasks = step.tasks ?? []
  return {
    total: tasks.length,
    done: tasks.filter((t) => t.done).length,
    requiredLeft: tasks.filter((t) => t.required && !t.done).length,
  }
}

/** The duty that appears most often in a step — the person best suited to own it. */
export function dominantDuty(step: ResponseStep): ResponseDuty | null {
  const counts = new Map<ResponseDuty, number>()
  for (const t of step.tasks ?? []) counts.set(t.duty, (counts.get(t.duty) ?? 0) + 1)
  let best: ResponseDuty | null = null
  for (const [duty, n] of counts) if (!best || n > (counts.get(best) ?? 0)) best = duty
  return best
}

/** Best-matching IR member for a step: has the step's main duty, then lightest current load. */
export function suggestOwner(step: ResponseStep, team: IrTeamMember[]): IrTeamMember | null {
  if (!team.length) return null
  const duty = dominantDuty(step)
  const pool = duty ? team.filter((m) => m.duties.includes(duty)) : []
  const candidates = pool.length ? pool : team
  return [...candidates].sort((a, b) => a.activeSteps - b.activeSteps)[0]
}
