import { tr } from '../i18n/locale.ts'

export interface FormField { key: string; label: string; type?: 'text' | 'textarea' | 'lines' | 'number' | 'checkbox' | 'datetime-local' | 'select'; required?: boolean; options?: string[]; min?: number; max?: number }
export function formPayload(fields: FormField[], values: Record<string, unknown>) {
  const payload: Record<string, unknown> = {}
  for (const f of fields) {
    const raw = values[f.key]
    if (f.type === 'checkbox') { payload[f.key] = !!raw; continue }
    const text = String(raw ?? '').trim()
    if (!text) { if (f.required) throw new Error(tr('form.required', { label: f.label })); continue }
    if (f.type === 'number') {
      const value = Number(text)
      if (!Number.isFinite(value) || (f.min != null && value < f.min) || (f.max != null && value > f.max)) throw new Error(tr('form.check', { label: f.label }))
      payload[f.key] = value
    } else if (f.type === 'datetime-local') {
      const date = new Date(text); if (!Number.isFinite(date.getTime())) throw new Error(tr('form.check', { label: f.label }))
      payload[f.key] = date.toISOString()
    } else if (f.type === 'lines') payload[f.key] = text.split('\n').map(s => s.trim()).filter(Boolean)
    else { if (f.options && !f.options.includes(text)) throw new Error(tr('form.choose', { label: f.label })); payload[f.key] = text }
  }
  return payload
}
