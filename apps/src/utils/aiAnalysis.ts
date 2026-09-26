// Run / Re-run AI Analysis button state for Incident Detail. Runs under `node --test`; text follows the UI language.
import { tr } from '../i18n/locale.ts'
import { hasMsg } from '../i18n/messages.ts'

/** The AI analysis never carries a severity: VIGIX severity comes only from the Wazuh rule level. */
export interface AiAnalysisSnapshot {
  summary: string | null
}

export interface RunAiAnalysisResult {
  incidentId: string
  graphRunId: string
  status: 'SUCCESS' | 'PARTIAL_SUCCESS'
  rerun: boolean
  analysis: AiAnalysisSnapshot & { keyFindings: string[] }
}

export interface AiRunState {
  status: 'idle' | 'running' | 'success' | 'error'
  message: string | null
}

export const initialAiRunState = (): AiRunState => ({ status: 'idle', message: null })

/** An analysis exists once the pipeline has recorded an LLM summary for the incident. */
export const hasAiAnalysis = (a: AiAnalysisSnapshot | null | undefined): boolean => !!a && !!a.summary

export function aiButtonLabel(state: AiRunState, analysis: AiAnalysisSnapshot | null | undefined): string {
  if (state.status === 'running') return tr('ai.btn.running')
  return tr(hasAiAnalysis(analysis) ? 'ai.btn.rerun' : 'ai.btn.run')
}

export function aiRunErrorMessage(err: unknown): string {
  const code = typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : 'UNKNOWN'
  const own = `err.ai.${code}`
  if (hasMsg(own)) return tr(own)
  if (code === 'FORBIDDEN' || code === 'HTTP_403') return tr('err.ai.forbidden')
  if (code === 'ANALYSIS_IN_PROGRESS') return tr('err.ANALYSIS_IN_PROGRESS')
  if (code === 'INCIDENT_NOT_FOUND') return tr('err.INCIDENT_NOT_FOUND')
  return tr('err.ai.withCode', { code })
}

/** Runs once and reports each state; success only when the backend confirmed the pipeline run. */
export async function runAiAnalysis(run: () => Promise<RunAiAnalysisResult>, onChange: (s: AiRunState) => void): Promise<AiRunState> {
  onChange({ status: 'running', message: null })
  let next: AiRunState
  try {
    const r = await run()
    next = {
      status: 'success',
      message: `${tr(r.rerun ? 'ai.done.rerun' : 'ai.done.first')}${r.status === 'PARTIAL_SUCCESS' ? tr('ai.done.partial') : ''}`,
    }
  } catch (err) {
    next = { status: 'error', message: aiRunErrorMessage(err) }
  }
  onChange(next)
  return next
}
