// Send-to-IR state for the article / response-guide modals. Runs under `node --test`; text follows the UI language.
import { tr } from '../i18n/locale.ts'
import { hasMsg } from '../i18n/messages.ts'

export interface IrEmailOutcome {
  status: 'SENT' | 'FAILED' | 'NOT_SENT'
  recipientRole: 'IR_TEAM'
  recipient: string | null
  sentAt: string | null
  deliveryId: string | null
  error: string | null
  /** The backend recognised a repeat of an already-sent request (same idempotency key): nothing was sent again. */
  duplicate?: boolean
}

/** Masked recipient from the preview endpoint. */
export interface RecipientPreview {
  recipient: string | null
  emailChannelConfigured: boolean
}

export interface SendState {
  status: 'idle' | 'sending' | 'sent' | 'error'
  /** Backend timestamp of the delivery (never the browser clock). */
  sentAt: string | null
  deliveryStatus: string | null
  recipient: string | null
  message: string | null
}

export const initialSendState = (): SendState => ({ status: 'idle', sentAt: null, deliveryStatus: null, recipient: null, message: null })

const SHARED = new Set(['IR_TEAM_EMAIL_NOT_CONFIGURED', 'CHANNEL_NOT_CONFIGURED', 'DELIVERY_FAILED', 'INCIDENT_NOT_FOUND', 'DUPLICATE_IN_PROGRESS'])

/** Backend error code (ApiError.code) → analyst-readable text in the current language. */
export function sendErrorMessage(err: unknown): string {
  const code = typeof err === 'object' && err !== null && 'code' in err ? String((err as { code: unknown }).code) : 'UNKNOWN'
  const own = `err.mail.${code}`
  if (hasMsg(own)) return tr(own)
  if (code === 'FORBIDDEN' || code === 'HTTP_403') return tr('err.mail.forbidden')
  const shared = `err.${code}`
  if (SHARED.has(code) && hasMsg(shared)) return tr(shared)
  return tr('err.mail.withCode', { code })
}

/** Why the dialog must not offer sending (checked before sending; the backend enforces the same). */
export function recipientProblem(p: RecipientPreview | null): string | null {
  if (!p) return null
  if (!p.recipient) return tr('err.IR_TEAM_EMAIL_NOT_CONFIGURED')
  if (!p.emailChannelConfigured) return tr('err.CHANNEL_NOT_CONFIGURED')
  return null
}

/**
 * Runs one send and reports each state. Success is only ever what the backend confirmed (status SENT) —
 * an error, or any other outcome, is shown as an error, never as sent.
 */
export async function runSend(send: () => Promise<IrEmailOutcome>, onChange: (s: SendState) => void): Promise<SendState> {
  onChange({ ...initialSendState(), status: 'sending' })
  let next: SendState
  try {
    const outcome = await send()
    next =
      outcome.status === 'SENT'
        ? { status: 'sent', sentAt: outcome.sentAt, deliveryStatus: outcome.status, recipient: outcome.recipient, message: null }
        : { status: 'error', sentAt: null, deliveryStatus: outcome.status, recipient: outcome.recipient, message: sendErrorMessage({ code: outcome.error ?? 'UNKNOWN' }) }
  } catch (err) {
    next = { status: 'error', sentAt: null, deliveryStatus: null, recipient: null, message: sendErrorMessage(err) }
  }
  onChange(next)
  return next
}
