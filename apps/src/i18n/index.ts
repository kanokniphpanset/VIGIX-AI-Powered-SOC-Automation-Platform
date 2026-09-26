// Reactive UI language (Thai by default). Components call `useI18n()` and render `t('key', params)`; label helpers in
// utils read the same state through `tr()` / `currentLang()` (./locale.ts), so both switch together.
import { locale, setLocale, tr } from './locale.ts'
import type { MsgKey, Params } from './messages.ts'

export type { Lang, MsgKey } from './messages.ts'
export { currentLang, dateLocale, locale, setLocale, tr } from './locale.ts'

/** Reading `locale.value` inside `t` makes every template that calls it re-render when the language changes. */
const t = (key: MsgKey, params?: Params) => tr(key, params)

export function useI18n() {
  return { locale, setLocale, t }
}
