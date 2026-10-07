// Generate / Regenerate Recommendation button state for Incident Detail. Runs under `node --test`; text follows the UI language.
// The action itself is the existing POST /api/recommendations/generate (validated by the backend; nothing saved on failure).
import { tr } from '../i18n/locale.ts'

export interface GenerateState {
  status: 'idle' | 'running' | 'success' | 'error'
  message: string | null
}

export const initialGenerateState = (): GenerateState => ({ status: 'idle', message: null })

/** Mirrors the backend gate on POST /api/recommendations/generate: requireRole("SOC", "IR_TEAM"); admin passes. */
export const canGenerateRecommendation = (role: string | null | undefined): boolean => role === 'SOC' || role === 'IR_TEAM' || role === 'admin'

export function generateButtonLabel(state: GenerateState, hasRecommendation: boolean): string {
  if (state.status === 'running') return tr('rec.btn.running')
  return tr(hasRecommendation ? 'rec.btn.regenerate' : 'rec.btn.generate')
}

export function generateErrorMessage(err: unknown): string {
  const code = typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : 'UNKNOWN'
  if (code === 'AI_UNAVAILABLE') return tr('err.rec.AI_UNAVAILABLE')
  if (code === 'INVALID_AI_OUTPUT') return tr('err.INVALID_AI_OUTPUT')
  if (code === 'INSUFFICIENT_EVIDENCE') return tr('err.rec.INSUFFICIENT_EVIDENCE')
  if (code === 'NO_NEW_RECOMMENDATION') return tr('err.rec.NO_NEW_RECOMMENDATION')
  if (code === 'DUPLICATE_RECOMMENDATION') return tr('err.rec.DUPLICATE_RECOMMENDATION')
  if (code === 'INCIDENT_NOT_FOUND') return tr('err.INCIDENT_NOT_FOUND')
  if (code === 'FORBIDDEN' || code === 'HTTP_403') return tr('err.rec.forbidden')
  return tr('err.rec.withCode', { code })
}

/**
 * Runs one generation; a click while one is running is ignored (returns null, calls nothing).
 * Success only when the backend returned the saved, validated recommendation.
 */
export async function runGenerate(
  current: GenerateState,
  generate: () => Promise<{ recommendationNumber: number }>,
  onChange: (s: GenerateState) => void,
): Promise<GenerateState | null> {
  if (current.status === 'running') return null
  onChange({ status: 'running', message: null })
  let next: GenerateState
  try {
    const rec = await generate()
    next = { status: 'success', message: tr('rec.done', { n: rec.recommendationNumber }) }
  } catch (err) {
    next = { status: 'error', message: generateErrorMessage(err) }
  }
  onChange(next)
  return next
}
