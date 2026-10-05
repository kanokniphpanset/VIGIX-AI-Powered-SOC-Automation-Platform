<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { alertsApi, incidentsApi, type AlertView, type TimelineEntry } from '@/api/vigix'
import AlertReviewDialog from '@/components/alerts/AlertReviewDialog.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import HelpTip from '@/components/common/HelpTip.vue'
import { useSessionStore } from '@/stores/session'
import { available, reviewDecisions, STATUS_LABEL } from '@/utils/triage'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { statusLabel, toSeverity } from '@/utils/vigix'
import { timelineText } from '@/utils/systemText'
import { glossary, thaiAgo } from '@/utils/dashboard'
import { workflowError } from '@/utils/workflow'
import { useUiStore } from '@/stores/ui'
import { feedback } from '@/utils/feedback'
import { useI18n } from '@/i18n'

/**
 * Alert Detail — the six fields an analyst decides on first (host, user, rule, source / destination IP, MITRE), then every
 * other stored Wazuh field grouped and collapsed ("Not available" when absent). Severity is the Wazuh rule-level mapping.
 */
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()
const view = ref<AlertView | null>(null)
const timeline = ref<TimelineEntry[]>([])
const error = ref('')
const loading = ref(false)
const reviewId = ref<string | null>(null)
const a = computed(() => view.value?.alert)
const date = (v: string | null | undefined) => (v ? formatDateTime(v) : t('c.notAvailable'))
const canReview = computed(() => !!a.value && session.canTriage && reviewDecisions(a.value).length > 0)
/** The six fields an analyst decides on, shown first. "—" when absent, so every card stays in the same place. */
const keyFields = computed(() => {
  const x = a.value
  if (!x) return []
  const rule = [x.summary.ruleId, x.summary.ruleLevel != null ? `level ${x.summary.ruleLevel}` : null].filter(Boolean).join(' · ')
  return [
    [t('ad.f.host'), x.summary.host, null], [t('ad.f.user'), x.summary.user, null], [t('ad.f.rule'), rule || null, null],
    [t('ad.f.srcIp'), x.summary.sourceIp, null], [t('ad.f.dstIp'), x.summary.destinationIp, null], [t('ad.f.mitre'), x.summary.mitreTechniques.join(', ') || null, 'MITRE'],
  ] as const
})
/** Every other stored field, grouped and collapsed. */
const groups = computed(() => {
  const x = a.value
  if (!x) return []
  return [
    { title: t('ad.g.alert'), fields: [
      [t('ad.f.id'), x.externalAlertId], [t('ad.f.vigixId'), x.id], [t('ad.f.source'), x.siemSource], [t('ad.f.ruleId'), x.summary.ruleId],
      [t('ad.f.ruleDesc'), x.summary.ruleDescription], [t('ad.f.ruleLevel'), x.summary.ruleLevel], [t('ad.f.severity'), SEVERITY_LABEL[toSeverity(x.severity)]], [t('ad.f.fired'), x.firedTimes],
    ] },
    { title: t('ad.g.triage'), fields: [
      [t('ad.f.status'), STATUS_LABEL[x.displayState] ?? x.displayState], [t('ad.f.decision'), x.disposition ? statusLabel(x.disposition) : null], [t('ad.f.reason'), x.triage?.note],
      [t('ad.f.decidedBy'), x.triage?.triagedBy], [t('ad.f.decidedAt'), date(x.triage?.triagedAt)], [t('ad.f.closedAt'), date(x.closedAt)], [t('ad.f.incident'), x.incident?.title],
    ] },
    { title: t('ad.g.time'), fields: [
      [t('ad.f.timestamp'), view.value?.rawPayload.timestamp ?? null], [t('ad.f.received'), date(x.receivedAt)], [t('ad.f.slaDue'), date(x.slaDueAt)],
      [t('ad.f.slaStatus'), x.slaStatus ? statusLabel(x.slaStatus) : null], [t('ad.f.age'), x.ageMinutes],
    ] },
    { title: t('ad.g.network'), fields: [[t('ad.f.agentIp'), x.summary.agentIp]] },
  ] as { title: string; fields: (readonly [string, unknown])[] }[]
})
const fieldCount = computed(() => groups.value.reduce((n, g) => n + g.fields.length, 0))
let request = 0
async function load() {
  const current = ++request
  loading.value = true
  error.value = ''
  try {
    const result = await alertsApi.view(String(route.params.id))
    if (current !== request) return
    view.value = result
    timeline.value = result.alert.incident ? await incidentsApi.timeline(result.alert.incident.id) : []
  } catch (e) {
    if (current === request) error.value = workflowError(e)
  } finally {
    if (current === request) loading.value = false
  }
}
watch(() => route.params.id, load, { immediate: true })
async function reviewed(id: string | null) {
  reviewId.value = null
  ui.notify(feedback(id ? 'alertIncident' : 'alertClosed', locale.value))
  if (id) await router.push(`/incidents/${id}`)
  else await load()
}
</script>

<template>
  <div>
    <RouterLink to="/alerts" class="mb-4 inline-block text-sm text-accent-700">{{ t('ad.back') }}</RouterLink>
    <p v-if="error" role="alert" class="mb-4 rounded bg-rose-50 p-3 text-sm text-rose-700">{{ error }}</p>
    <p v-if="loading" class="text-sm text-slate-500">{{ t('ad.loading') }}</p>
    <template v-if="view && a">
      <header class="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p class="text-xs uppercase text-slate-500">{{ t('ad.kind', { source: a.siemSource }) }}</p>
          <h1 class="mt-1 text-2xl font-bold text-slate-900">{{ available(a.summary.ruleDescription) }}</h1>
          <p class="mt-2 flex items-center gap-2 text-sm text-slate-600"><SeverityBadge :severity="toSeverity(a.severity)" size="sm" /> {{ t('ad.ruleLevel', { level: available(a.summary.ruleLevel) }) }} · {{ STATUS_LABEL[a.displayState] ?? a.displayState }}</p>
          <p class="mt-1 flex flex-wrap items-center gap-1.5 text-xs text-slate-500">
            <span :title="date(a.receivedAt)">{{ t('ad.receivedAgo', { ago: thaiAgo(a.receivedAt, Date.now(), locale) }) }}</span>
            <template v-if="a.slaStatus">· <span :class="a.slaStatus === 'BREACHED' ? 'font-semibold text-rose-700' : a.slaStatus === 'AT_RISK' ? 'font-semibold text-amber-700' : ''" :title="date(a.slaDueAt)">{{ t('ad.f.slaStatus') }}: {{ statusLabel(a.slaStatus) }}</span> <HelpTip :text="glossary('SLA', locale)" /></template>
          </p>
        </div>
        <div class="flex gap-3 text-sm">
          <RouterLink v-if="a.incident" :to="`/incidents/${a.incident.id}`" class="rounded border border-slate-300 px-3 py-2">{{ t('ad.openIncident') }}</RouterLink>
          <button v-else-if="canReview" type="button" class="rounded bg-navy-800 px-3 py-2 text-white" @click="reviewId = a.id">{{ t('al.review') }}</button>
        </div>
      </header>
      <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="decide-h">
        <h2 id="decide-h" class="mb-3 font-semibold">{{ t('ad.decide') }}</h2>
        <dl class="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <div v-for="[label, value, tip] in keyFields" :key="label" class="min-w-0 rounded-lg bg-slate-50 px-3 py-2">
            <dt class="flex items-center gap-1 text-xs text-slate-500">{{ label }}<HelpTip v-if="tip" :text="glossary(tip, locale)" /></dt>
            <dd class="mt-0.5 break-words font-mono text-sm font-semibold text-slate-900">{{ value ?? '—' }}</dd>
          </div>
        </dl>
      </section>
      <details class="mt-4 rounded-xl border border-slate-200 bg-white">
        <summary class="cursor-pointer select-none px-5 py-4 font-semibold">{{ t('ad.details') }} <span class="text-sm font-normal text-slate-500">{{ t('ad.detailsN', { n: fieldCount }) }}</span></summary>
        <div class="space-y-5 border-t border-slate-100 p-5">
          <div v-for="g in groups" :key="g.title">
            <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ g.title }}</h3>
            <dl class="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3"><div v-for="[label, value] in g.fields" :key="label"><dt class="text-xs text-slate-500">{{ label }}</dt><dd class="mt-1 break-words text-slate-800">{{ available(value) }}</dd></div></dl>
          </div>
        </div>
      </details>
      <section class="mt-4 rounded-xl border border-slate-200 bg-white p-5"><h2 class="mb-3 flex items-center gap-1.5 font-semibold">{{ t('ad.evidence') }} <HelpTip :text="glossary('IOC', locale)" /></h2><p v-if="!view.iocs.length" class="text-sm text-slate-500">{{ t('ad.noIndicators') }}</p><ul v-else class="space-y-1 text-sm"><li v-for="ioc in view.iocs" :key="ioc.path + ioc.value"><span class="font-mono">{{ ioc.iocType }}: {{ ioc.value }}</span><span class="ml-2 text-xs text-slate-500">{{ ioc.path }}</span></li></ul><details class="mt-4"><summary class="cursor-pointer text-sm font-medium">{{ t('ad.payload') }}</summary><pre class="mt-3 max-h-[36rem] overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-4 text-xs">{{ JSON.stringify(view.rawPayload, null, 2) }}</pre></details></section>
      <section class="mt-4 rounded-xl border border-slate-200 bg-white p-5 text-sm"><h2 class="mb-3 font-semibold">{{ t('ad.activity') }}</h2><p v-if="!timeline.length">{{ t('c.notAvailable') }}</p><ol v-else class="space-y-2"><li v-for="entry in timeline" :key="entry.id"><span class="text-xs text-slate-500">{{ date(entry.occurredAt) }} · {{ entry.actor }}</span><p>{{ timelineText(entry.eventType, entry.description) }}</p></li></ol></section>
      <AlertReviewDialog :alert-id="reviewId" @close="reviewId = null" @done="reviewed" />
    </template>
  </div>
</template>
