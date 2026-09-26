import { tr } from '../i18n/locale.ts'
import { hasMsg } from '../i18n/messages.ts'
export interface MutationState { busy: boolean; error: string; success: boolean; saved: boolean }
export const mutationState = (): MutationState => ({ busy: false, error: '', success: false, saved: false })
/** Mirrors POST /api/responses and Send to IR (requireOperationalRole("SOC")): only the SOC sends to IR. */
export function canCreateTicket(role: string | null) { return role === 'SOC' }
export function canDecideApproval(role: string | null, approval: { status: string; approvalRole: string } | null) {
  // Mirrors DecideApproval: only IR_TEAM decides an open IR decision — admin never stands in.
  return !!approval && approval.status.toLowerCase() === 'pending' && role === 'IR_TEAM' && approval.approvalRole === 'IR_TEAM'
}
type ChainApproval = { responseId: string | null; status: string; approvalRole: string; stepOrder?: number; decidedAt: string | null; createdAt?: string }

/** The ticket's IR decision history, latest request last (legacy tickets may still hold several steps). */
export function approvalChainFor<T extends ChainApproval>(approvals: T[], responseId: string): T[] {
  const own = approvals.filter((a) => a.responseId === responseId).sort((a, b) => (a.createdAt ?? '').localeCompare(b.createdAt ?? '') || (a.stepOrder ?? 1) - (b.stepOrder ?? 1))
  const start = own.map((a) => a.stepOrder ?? 1).lastIndexOf(1)
  return (start >= 0 ? own.slice(start) : own).sort((a, b) => (a.stepOrder ?? 1) - (b.stepOrder ?? 1))
}

/** The step to show / decide: the active (pending) step, else the most recently decided one. */
export function currentApproval<T extends ChainApproval>(chain: T[]): T | null {
  return chain.find((a) => a.status === 'pending') ?? [...chain].filter((a) => a.decidedAt).sort((a, b) => (b.decidedAt ?? '').localeCompare(a.decidedAt ?? ''))[0] ?? chain[0] ?? null
}

export function workflowError(error: unknown): string {
  const e = error as { code?: string; status?: number }
  const code = e?.code ?? `HTTP_${e?.status ?? 0}`
  const key = `err.${code}`
  return hasMsg(key) ? tr(key) : tr('err.generic')
}
/** A completed write is not resent when only its reload failed. */
export async function mutate(state: MutationState, action: () => Promise<unknown>, reload: () => Promise<unknown>, describe = workflowError) {
  if (state.busy) return false
  state.busy = true; state.error = ''; state.success = false
  try {
    if (!state.saved) { await action(); state.saved = true }
    await reload(); state.success = true
    return true
  } catch (e) { state.error = state.saved ? tr('c.saveRefreshFailed') : describe(e); return false }
  finally { state.busy = false }
}
