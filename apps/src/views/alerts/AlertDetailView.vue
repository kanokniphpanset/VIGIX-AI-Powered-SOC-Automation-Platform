<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { alertsApi, incidentsApi, type AlertView, type TimelineEntry } from '@/api/vigix'
import AlertReviewDialog from '@/components/alerts/AlertReviewDialog.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { useSessionStore } from '@/stores/session'
import { available, reviewDecisions, STATUS_LABEL } from '@/utils/triage'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { statusLabel, toSeverity } from '@/utils/vigix'
import { timelineText } from '@/utils/systemText'
import { workflowError } from '@/utils/workflow'
import { useUiStore } from '@/stores/ui'
import { feedback } from '@/utils/feedback'
import { useI18n } from '@/i18n'

/** Alert Detail — every stored Wazuh field ("Not available" when absent). Severity is the Wazuh rule-level mapping. */
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
const fields = computed(() => {
  const x = a.value
  if (!x) return []
  return Object.entries({
    [t('ad.f.id')]: x.externalAlertId, [t('ad.f.vigixId')]: x.id, [t('ad.f.timestamp')]: view.value?.rawPayload.timestamp ?? null,
    [t('ad.f.received')]: date(x.receivedAt), [t('ad.f.source')]: x.siemSource, [t('ad.f.ruleId')]: x.summary.ruleId, [t('ad.f.ruleDesc')]: x.summary.ruleDescription,
    [t('ad.f.ruleLevel')]: x.summary.ruleLevel, [t('ad.f.severity')]: SEVERITY_LABEL[toSeverity(x.severity)], [t('ad.f.fired')]: x.firedTimes,
    [t('ad.f.status')]: STATUS_LABEL[x.displayState] ?? x.displayState, [t('ad.f.decision')]: x.disposition ? statusLabel(x.disposition) : null, [t('ad.f.reason')]: x.triage?.note,
    [t('ad.f.decidedBy')]: x.triage?.triagedBy, [t('ad.f.decidedAt')]: date(x.triage?.triagedAt), [t('ad.f.closedAt')]: date(x.closedAt),
    [t('ad.f.slaDue')]: date(x.slaDueAt), [t('ad.f.slaStatus')]: x.slaStatus ? statusLabel(x.slaStatus) : null, [t('ad.f.age')]: x.ageMinutes, [t('ad.f.incident')]: x.incident?.title,
    [t('ad.f.srcIp')]: x.summary.sourceIp, [t('ad.f.dstIp')]: x.summary.destinationIp, [t('ad.f.host')]: x.summary.host,
    [t('ad.f.agentIp')]: x.summary.agentIp, [t('ad.f.user')]: x.summary.user, [t('ad.f.mitre')]: x.summary.mitreTechniques.join(', '),
  })
})
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
        </div>
        <div class="flex gap-3 text-sm">
          <RouterLink v-if="a.incident" :to="`/incidents/${a.incident.id}`" class="rounded border border-slate-300 px-3 py-2">{{ t('ad.openIncident') }}</RouterLink>
          <button v-else-if="canReview" type="button" class="rounded bg-navy-800 px-3 py-2 text-white" @click="reviewId = a.id">{{ t('al.review') }}</button>
        </div>
      </header>
      <section class="rounded-xl border border-slate-200 bg-white p-5"><h2 class="mb-4 font-semibold">{{ t('ad.details') }}</h2><dl class="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-3"><div v-for="[label, value] in fields" :key="label"><dt class="text-xs text-slate-500">{{ label }}</dt><dd class="mt-1 break-words text-slate-800">{{ available(value) }}</dd></div></dl></section>
      <section class="mt-4 rounded-xl border border-slate-200 bg-white p-5"><h2 class="mb-3 font-semibold">{{ t('ad.evidence') }}</h2><p v-if="!view.iocs.length" class="text-sm text-slate-500">{{ t('ad.noIndicators') }}</p><ul v-else class="space-y-1 text-sm"><li v-for="ioc in view.iocs" :key="ioc.path + ioc.value"><span class="font-mono">{{ ioc.iocType }}: {{ ioc.value }}</span><span class="ml-2 text-xs text-slate-500">{{ ioc.path }}</span></li></ul><details class="mt-4"><summary class="cursor-pointer text-sm font-medium">{{ t('ad.payload') }}</summary><pre class="mt-3 max-h-[36rem] overflow-auto whitespace-pre-wrap break-all rounded bg-slate-50 p-4 text-xs">{{ JSON.stringify(view.rawPayload, null, 2) }}</pre></details></section>
      <section class="mt-4 rounded-xl border border-slate-200 bg-white p-5 text-sm"><h2 class="mb-3 font-semibold">{{ t('ad.activity') }}</h2><p v-if="!timeline.length">{{ t('c.notAvailable') }}</p><ol v-else class="space-y-2"><li v-for="entry in timeline" :key="entry.id"><span class="text-xs text-slate-500">{{ date(entry.occurredAt) }} · {{ entry.actor }}</span><p>{{ timelineText(entry.eventType, entry.description) }}</p></li></ol></section>
      <AlertReviewDialog :alert-id="reviewId" @close="reviewId = null" @done="reviewed" />
    </template>
  </div>
</template>
