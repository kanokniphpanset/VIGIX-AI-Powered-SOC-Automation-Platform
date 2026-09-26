// The one reactive UI language (Thai by default). Pure enough for `node --test` (Vue's `ref` has no DOM dependency).
// Every label helper reads `currentLang()` / `tr()`, so a template or computed that shows a translated value re-renders
// when the language changes. The choice is a per-browser convenience kept in localStorage; without storage the UI
// simply starts in Thai.
import { ref } from 'vue'
import { isLang, translate, type Lang, type MsgKey, type Params } from './messages.ts'

const STORAGE_KEY = 'vigix.locale'

function readStored(): Lang {
  try {
    const v = globalThis.localStorage?.getItem(STORAGE_KEY)
    return isLang(v) ? v : 'th'
  } catch {
    return 'th'
  }
}

export const locale = ref<Lang>(readStored())
if (typeof document !== 'undefined') document.documentElement.lang = locale.value

export function setLocale(lang: Lang) {
  locale.value = lang
  if (typeof document !== 'undefined') document.documentElement.lang = lang
  try {
    globalThis.localStorage?.setItem(STORAGE_KEY, lang)
  } catch {
    /* storage unavailable: the choice lasts for this page only */
  }
}

/** The current language; reading it inside a render / computed makes that view follow language changes. */
export const currentLang = (): Lang => locale.value

/** Text for `key` in the current language (or `lang` when a caller — e.g. a test — pins one). */
export const tr = (key: MsgKey, params?: Params, lang: Lang = locale.value) => translate(lang, key, params)

/** BCP-47 tag for dates and numbers: Thai month names on the Gregorian calendar (the evidence timestamps are Gregorian). */
export const dateLocale = (lang: Lang = locale.value) => (lang === 'th' ? 'th-TH-u-ca-gregory' : 'en-US')

/**
 * A `Record` whose values are the current-language text of message keys — existing `LABEL[value]` lookups keep
 * working and follow the language (each read goes through `tr`). Unknown values read as undefined, as before.
 */
export function labelMap<K extends string>(keys: Record<K, MsgKey>): Record<K, string> {
  const map = {} as Record<K, string>
  for (const k of Object.keys(keys) as K[]) Object.defineProperty(map, k, { enumerable: true, get: () => tr(keys[k]) })
  return map
}
