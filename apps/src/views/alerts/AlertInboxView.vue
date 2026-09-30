<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import PageHeader from '@/components/layout/PageHeader.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import AlertReviewDialog from '@/components/alerts/AlertReviewDialog.vue'
import { alertsApi, type InboxAlert, type InboxFilters } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { agoText, available, DECISION_LABEL, reviewDecisions, reviewSla, STATUS_LABEL, STATUS_TABS } from '@/utils/triage'
import { toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { useUiStore } from '@/stores/ui'
import { feedback } from '@/utils/feedback'
import { useI18n } from '@/i18n'

/**
 * Alert Inbox — Wazuh alerts that enter the SOC workflow (MEDIUM / HIGH / CRITICAL; LOW never appears).
 * HIGH / CRITICAL already opened their incident automatically → "Open incident". MEDIUM waits for SOC review → "Review".
 * No claim and no owner: any SOC analyst reviews an open alert. Filters, ordering and paging run on the server.
 */
const router = useRouter()
const route = useRoute()
const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()
const pageSize = 50
const items = ref<InboxAlert[]>([])
const total = ref(0)
const offset = ref(0)
// Deep links (e.g. the Dashboard's "ตรวจ Alert" → /alerts?status=needs-review) open on that tab; unknown values fall back to All.
const initialStatus = STATUS_TABS.find(([value]) => value === route.query.status)?.[0] ?? 'all'
const filters = ref<InboxFilters>({ status: initialStatus, sort: 'urgency', severity: '', source: '', search: '' })
const loading = ref(false)
const error = ref('')
const reviewId = ref<string | null>(null)
let requestNumber = 0
async function load() {
  const request = ++requestNumber
  loading.value = true
  error.value = ''
  try {
    const response = await alertsApi.inbox({ ...filters.value, limit: pageSize, offset: offset.value })
    if (request !== requestNumber) return
    items.value = response.items
    total.value = response.total
    now.value = new Date()
  } catch (e) {
    if (request === requestNumber) error.value = workflowError(e)
  } finally {
    if (request === requestNumber) loading.value = false
  }
}
let debounce: ReturnType<typeof setTimeout> | undefined
watch(filters, () => { clearTimeout(debounce); offset.value = 0; debounce = setTimeout(load, 250) }, { deep: true })
function page(delta: number) { offset.value = Math.max(0, offset.value + delta * pageSize); void load() }
const range = computed(() => (total.value ? t('al.range', { from: offset.value + 1, to: Math.min(offset.value + pageSize, total.value), total: total.value }) : t('al.none')))
const canReview = (a: InboxAlert) => session.canTriage && reviewDecisions(a).length > 0
/** One status line per alert: what happened to it (closed → which decision) — the review SLA is shown only while it waits. */
function statusText(a: InboxAlert): string {
  if (a.displayState === 'CLOSED' && (a.disposition === 'FALSE_POSITIVE' || a.disposition === 'INFORMATIONAL')) return DECISION_LABEL[a.disposition]
  return STATUS_LABEL[a.displayState] ?? a.displayState
}
const STATUS_TONE: Record<string, string> = {
  NEEDS_REVIEW: 'bg-amber-50 text-amber-800 ring-amber-200',
  MONITORING: 'bg-amber-50 text-amber-800 ring-amber-200',
  IN_INCIDENT: 'bg-sky-50 text-sky-800 ring-sky-200',
  CLOSED: 'bg-slate-100 text-slate-600 ring-slate-200',
}
const now = ref(new Date())
async function reviewed(incidentId: string | null) {
  reviewId.value = null
  // Say what happened and what is next: a new incident opens on its "Next step" card; a closed alert → the next alert.
  ui.notify(feedback(incidentId ? 'alertIncident' : 'alertClosed', locale.value))
  if (incidentId) await router.push(`/incidents/${incidentId}`)
  else await load()
}
let refresh: ReturnType<typeof setInterval> | undefined
onMounted(() => { void load(); refresh = setInterval(() => { if (!reviewId.value) void load() }, 30000) })
onUnmounted(() => { clearInterval(refresh); clearTimeout(debounce); requestNumber++ })
</script>

<template>
  <div>
    <PageHeader :title="t('ui.page.alerts')" :description="t('al.subtitle')" />
    <div class="mb-4 flex flex-wrap gap-2" role="tablist" :aria-label="t('al.tabsAria')">
      <button v-for="[value, label] in STATUS_TABS" :key="value" type="button" role="tab" :aria-selected="filters.status === value" class="rounded-lg px-4 py-2 text-sm font-semibold" :class="filters.status === value ? 'bg-navy-800 text-white' : 'bg-white text-slate-600 ring-1 ring-slate-200'" @click="filters.status = value">{{ label }}</button>
    </div>
    <div class="mb-4 grid gap-3 rounded-xl border border-slate-200 bg-white p-4 sm:grid-cols-2 lg:grid-cols-4">
      <label class="text-xs text-slate-500">{{ t('al.search') }}<input v-model="filters.search" type="search" :placeholder="t('al.searchPlaceholder')" class="mt-1 w-full rounded border border-slate-300 p-2 text-sm text-slate-800" /></label>
      <label class="text-xs text-slate-500">{{ t('al.severity') }}<select v-model="filters.severity" class="mt-1 w-full rounded border border-slate-300 p-2 text-sm text-slate-800"><option value="">{{ t('al.sevAll') }}</option><option v-for="s in ['critical', 'high', 'medium']" :key="s" :value="s">{{ SEVERITY_LABEL[toSeverity(s)] }}</option></select></label>
      <label class="text-xs text-slate-500">{{ t('al.source') }}<input v-model="filters.source" :placeholder="t('al.sourceAll')" class="mt-1 w-full rounded border border-slate-300 p-2 text-sm text-slate-800" /></label>
      <label class="text-xs text-slate-500">{{ t('al.order') }}<select v-model="filters.sort" class="mt-1 w-full rounded border border-slate-300 p-2 text-sm text-slate-800"><option value="urgency">{{ t('al.order.urgency') }}</option><option value="severity">{{ t('al.order.severity') }}</option><option value="oldest">{{ t('al.order.oldest') }}</option><option value="newest">{{ t('al.order.newest') }}</option></select></label>
    </div>
    <p v-if="error" role="alert" class="mb-3 rounded bg-rose-50 p-3 text-sm text-rose-700">{{ error }}</p>
    <div class="overflow-x-auto rounded-xl border border-slate-200 bg-white" :aria-busy="loading">
      <table class="w-full text-left text-sm">
        <thead class="bg-slate-50 text-xs uppercase text-slate-500">
          <tr><th class="p-3">{{ t('al.col.id') }}</th><th class="p-3">{{ t('al.col.severity') }}</th><th class="p-3">{{ t('al.col.rule') }}</th><th class="p-3">{{ t('al.col.time') }}</th><th class="p-3">{{ t('al.col.source') }}</th><th class="p-3">{{ t('al.col.status') }}</th><th class="p-3">{{ t('al.col.action') }}</th></tr>
        </thead>
        <tbody class="divide-y divide-slate-100">
          <tr v-for="a in items" :key="a.id" class="align-top hover:bg-slate-50">
            <td class="max-w-[10rem] p-3"><RouterLink :to="`/alerts/${a.id}`" class="break-all font-mono text-xs text-accent-700 hover:underline">{{ a.externalAlertId }}</RouterLink></td>
            <td class="p-3"><SeverityBadge :severity="toSeverity(a.severity)" size="sm" /></td>
            <td class="max-w-sm p-3"><p class="font-medium text-slate-800">{{ available(a.summary.ruleDescription) }}</p><p class="mt-1 text-xs text-slate-500">{{ t('al.ruleLevel', { rule: available(a.summary.ruleId), level: available(a.summary.ruleLevel) }) }}</p></td>
            <td class="whitespace-nowrap p-3 text-xs">{{ formatDateTime(a.receivedAt) }}<p class="text-slate-400">{{ agoText(a.ageMinutes) }}</p></td>
            <td class="p-3"><p>{{ available(a.siemSource) }}</p><p class="text-xs text-slate-500">{{ available(a.summary.host) }}</p></td>
            <td class="p-3">
              <span class="inline-block whitespace-nowrap rounded px-2 py-1 text-xs font-medium ring-1" :class="STATUS_TONE[a.displayState] ?? STATUS_TONE.CLOSED">{{ statusText(a) }}</span>
              <template v-for="sla in [reviewSla(a, now)]" :key="a.id">
                <template v-if="sla">
                  <p class="mt-1 whitespace-nowrap text-xs text-slate-700">{{ sla.text }}</p>
                  <p class="whitespace-nowrap text-xs" :class="sla.late ? 'font-semibold text-rose-700' : 'text-slate-400'">{{ t('tri.tgt.due', { at: formatDateTime(sla.dueAt) }) }}</p>
                </template>
              </template>
              <p v-if="a.triage?.note && a.displayState === 'CLOSED'" class="mt-1 max-w-[14rem] truncate text-xs text-slate-500" :title="a.triage.note">{{ a.triage.note }}</p>
            </td>
            <td class="p-3">
              <div class="flex flex-col items-start gap-2 whitespace-nowrap">
                <RouterLink v-if="a.incident" :to="`/incidents/${a.incident.id}`" class="font-semibold text-accent-700 hover:underline">{{ t('al.openIncident') }}</RouterLink>
                <button v-else-if="canReview(a)" type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700" @click="reviewId = a.id">{{ t('al.review') }}</button>
              </div>
            </td>
          </tr>
          <tr v-if="!items.length"><td colspan="7" class="p-8 text-center text-slate-500">{{ loading ? t('al.loading') : t('al.empty') }}</td></tr>
        </tbody>
      </table>
    </div>
    <div class="mt-4 flex items-center justify-between text-sm text-slate-600"><span>{{ range }}</span><div class="flex gap-3"><button :disabled="loading || offset === 0" class="disabled:opacity-40" @click="page(-1)">{{ t('c.previous') }}</button><button :disabled="loading || offset + pageSize >= total" class="disabled:opacity-40" @click="page(1)">{{ t('c.next') }}</button><button :disabled="loading" @click="load">{{ t('c.refresh') }}</button></div></div>
    <AlertReviewDialog :alert-id="reviewId" @close="reviewId = null" @done="reviewed" />
  </div>
</template>
