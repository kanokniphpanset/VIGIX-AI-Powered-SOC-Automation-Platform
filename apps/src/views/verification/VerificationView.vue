<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ArrowUpRight, RotateCw, ScanSearch } from 'lucide-vue-next'
import PageHeader from '@/components/layout/PageHeader.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { api } from '@/api/http'
import { incidentsApi, slaApi, workflowApi, type RehuntHealth, type Verification } from '@/api/vigix'
import { workApi, type WorkTicket } from '@/api/work'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { feedback, rehuntKind } from '@/utils/feedback'
import { useI18n } from '@/i18n'
import { incidentLabel, toSeverity, timeAgo } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { describeWorkflowError } from '@/utils/ticket'

/**
 * Verification (IR). Response → Re-hunt Wazuh → Verification:
 *   NO MATCH → RESOLVED (terminal) · MATCH + rounds left → NOT_RESOLVED → new investigation cycle · MATCH at the last
 *   round / Policy → ESCALATED. A re-hunt error records NO verdict. Nothing here resolves an incident by hand.
 */
type VerificationRow = Verification & { incidentId: string }
const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()
const awaiting = ref<WorkTicket[]>([])
const escalated = ref<WorkTicket[]>([])
const verdicts = ref<VerificationRow[]>([])
const health = ref<RehuntHealth | null>(null)
const loading = ref(true)
const error = ref('')

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [a, e, v] = await Promise.all([
      workApi.tickets('awaiting-rehunt', 100),
      workApi.tickets('escalated', 100),
      api<{ items: VerificationRow[] }>('/api/verifications', { query: { limit: 50 } }),
    ])
    awaiting.value = a.items
    escalated.value = e.items
    verdicts.value = v.items
  } catch {
    error.value = t('vf.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(() => {
  void load()
  slaApi.rehuntHealth().then((h) => (health.value = h)).catch(() => (health.value = null))
})

const count = (r: string) => verdicts.value.filter((v) => v.result === r).length
const summary = computed(() => [
  { label: t('vf.awaiting'), value: awaiting.value.length },
  { label: t('vf.resolved'), value: count('RESOLVED') },
  { label: t('vf.notResolved'), value: count('NOT_RESOLVED') },
  { label: t('vf.spread'), value: verdicts.value.filter((v) => v.spreadDetected).length },
  { label: t('vf.escalated'), value: escalated.value.length },
])
const mock = computed(() => health.value?.provider === 'mock' || health.value?.clusterStatus === 'mock')

const busyId = ref<string | null>(null)
async function rehunt(ticket: WorkTicket) {
  if (busyId.value) return
  busyId.value = ticket.id
  try {
    const r = await workflowApi.rehunt(ticket.incidentId, ticket.id)
    const inc = await incidentsApi.get(ticket.incidentId)
    ui.notify(feedback(rehuntKind(r.verification.result, inc.status), locale.value, { inc: incidentLabel(inc.id), n: inc.investigationNumber, incidentId: inc.id }))
  } catch (e) {
    ui.error(t('tqv.rehuntFailed'), describeWorkflowError(e))
  } finally {
    busyId.value = null
    await load()
  }
}
</script>

<template>
  <div>
    <PageHeader :title="t('ui.page.verification')" :description="t('vf.description')">
      <template #actions>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" :disabled="loading" @click="load"><RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('c.refresh') }}</button>
      </template>
    </PageHeader>

    <p v-if="health" class="mb-4 rounded-lg bg-white px-3 py-2 text-xs text-slate-600 ring-1 ring-slate-200">
      {{ t('vf.source') }} <strong>{{ mock ? t('vf.mockSource') : t('tk.wazuhIndexer') }}</strong>
      <span class="font-mono text-slate-400 break-all"> {{ health.indexPattern }}</span>
      <span :class="health.reachable ? 'text-emerald-700' : 'text-rose-700'"> · {{ health.reachable ? t('tqv.reachable') : t('tqv.unreachable') }}</span>
    </p>
    <p v-if="error" class="mb-4 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }} <button type="button" class="underline" @click="load">{{ t('c.retry') }}</button></p>

    <div class="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <div v-for="s in summary" :key="s.label" class="rounded-xl border border-slate-200 bg-white p-3">
        <p class="text-xs text-slate-500">{{ s.label }}</p>
        <p class="mt-1 text-2xl font-bold text-slate-900">{{ loading && !verdicts.length ? '…' : s.value }}</p>
      </div>
    </div>
    <p class="-mt-4 mb-6 text-[11px] text-slate-400">{{ t('vf.countsNote') }}</p>

    <section class="mb-8">
      <h2 class="mb-2 text-sm font-semibold text-slate-800">{{ t('vf.awaiting') }}</h2>
      <p v-if="!loading && !awaiting.length" class="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-500">{{ t('vf.noneAwaiting') }}</p>
      <ul class="space-y-2">
        <li v-for="ticket in awaiting" :key="ticket.id" class="flex flex-wrap items-center gap-3 rounded-xl border border-slate-200 bg-white p-3">
          <div class="min-w-0 flex-1">
            <p class="flex flex-wrap items-center gap-2 text-xs text-slate-500"><span class="font-mono">{{ incidentLabel(ticket.incidentId) }}</span><SeverityBadge :severity="toSeverity(ticket.incidentPriority)" size="sm" /><span>{{ t('vf.cycle', { n: ticket.investigationNumber }) }}</span></p>
            <p class="text-sm font-medium text-slate-800">{{ ticket.stepTitle ?? ticket.actionName ?? t('vf.response') }}</p>
            <p class="text-xs text-slate-500">{{ t('vf.completedBy', { at: ticket.completedAt ? formatDateTime(ticket.completedAt) : '—', who: ticket.assignedToEmail ?? 'IR' }) }}</p>
          </div>
          <button v-if="session.canExecuteResponse" type="button" class="inline-flex items-center gap-1 rounded-lg bg-accent-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-700 disabled:opacity-50" :disabled="!!busyId" :aria-busy="busyId === ticket.id" @click="rehunt(ticket)">
            <ScanSearch class="size-3.5" /> {{ busyId === ticket.id ? t('vf.rehunting') : t('tk.runRehunt') }}
          </button>
          <span v-else class="text-xs text-slate-500">{{ t('vf.irRuns') }}</span>
          <router-link :to="`/tickets/${ticket.id}`" class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50">{{ t('vf.ticket') }} <ArrowUpRight class="size-3.5" /></router-link>
        </li>
      </ul>
    </section>

    <section>
      <h2 class="mb-2 text-sm font-semibold text-slate-800">{{ t('vf.recent') }}</h2>
      <p v-if="!loading && !verdicts.length" class="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-6 text-center text-sm text-slate-500">{{ t('vf.noneRecorded') }}</p>
      <div v-if="verdicts.length" class="overflow-x-auto rounded-xl border border-slate-200 bg-white">
        <table class="w-full min-w-[640px] text-sm">
          <thead class="border-b border-slate-100 text-left text-xs text-slate-400">
            <tr><th class="px-3 py-2">{{ t('vf.col.incident') }}</th><th class="px-3 py-2">{{ t('vf.col.verdict') }}</th><th class="px-3 py-2">{{ t('vf.col.rehunt') }}</th><th class="px-3 py-2">{{ t('vf.col.matching') }}</th><th class="px-3 py-2">{{ t('vf.col.spread') }}</th><th class="px-3 py-2">{{ t('vf.col.source') }}</th><th class="px-3 py-2">{{ t('vf.col.when') }}</th></tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="v in verdicts" :key="v.id">
              <td class="px-3 py-2"><router-link :to="`/incidents/${v.incidentId}?tab=verification`" class="font-mono text-xs text-accent-700 hover:underline">{{ incidentLabel(v.incidentId) }}</router-link></td>
              <td class="px-3 py-2"><StatusPill :status="v.result" /></td>
              <td class="px-3 py-2 text-xs font-semibold">{{ v.result === 'RESOLVED' ? t('tk.noMatch') : (v.matchingEvents ?? 0) > 0 ? t('tk.match') : t('vf.manual') }}</td>
              <td class="px-3 py-2 text-xs">{{ v.matchingEvents ?? '—' }}</td>
              <td class="px-3 py-2 text-xs">{{ v.spreadDetected ? t('c.yes') : t('c.no') }}</td>
              <td class="px-3 py-2 text-xs">{{ v.afterState?.evidenceSource ?? '—' }}</td>
              <td class="whitespace-nowrap px-3 py-2 text-xs text-slate-500" :title="v.verifiedAt ? formatDateTime(v.verifiedAt) : ''">{{ v.verifiedAt ? timeAgo(v.verifiedAt) : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>
