<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowUpRight, CheckCircle2, Database, Play, RotateCw, ScanSearch } from 'lucide-vue-next'
import PageHeader from '@/components/layout/PageHeader.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import { incidentsApi, slaApi, workflowApi, type RehuntHealth } from '@/api/vigix'
import { workApi, type TicketQueue, type WorkTicket } from '@/api/work'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { feedback, rehuntKind } from '@/utils/feedback'
import { useI18n } from '@/i18n'
import { incidentLabel, toSeverity, timeAgo } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { describeWorkflowError } from '@/utils/ticket'
import { TICKET_TABS, WORK_STAGE_LABEL } from '@/utils/workspace'

/**
 * Response Tickets (one ticket = one response plan = one RecommendationStep). Queues come from the backend and follow
 * backend assignment: Policy executor role, the user who started the response, the ACTIVE approval step — never who
 * received an email. Flow: Awaiting Approval → Ready → In Progress → Awaiting Re-hunt → Completed (or a new cycle /
 * Escalated). Every button calls the existing role-gated route; the backend re-checks state and role.
 */
const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()

const initial = String(route.query.queue ?? '') as TicketQueue
const queue = ref<TicketQueue>(TICKET_TABS.some((tab) => tab.queue === initial) ? initial : session.canExecuteResponse ? 'my-work' : 'all')
const incidentFilter = computed(() => (typeof route.query.incident === 'string' ? route.query.incident : undefined))
const PAGE = 25
const offset = ref(0)
const items = ref<WorkTicket[]>([])
const counts = ref<Partial<Record<TicketQueue, number>>>({})
const total = ref(0)
const loading = ref(true)
const error = ref('')
const rehuntSource = ref<RehuntHealth | null>(null)

async function load() {
  loading.value = true
  error.value = ''
  try {
    const r = await workApi.tickets(queue.value, PAGE, offset.value, incidentFilter.value)
    items.value = r.items
    counts.value = r.counts
    total.value = r.total
  } catch {
    error.value = t('tqv.loadFailed')
  } finally {
    loading.value = false
  }
}
onMounted(() => {
  void load()
  slaApi.rehuntHealth().then((h) => (rehuntSource.value = h)).catch(() => (rehuntSource.value = null))
})
watch(queue, () => {
  void router.replace({ query: { ...route.query, queue: queue.value } })
  if (offset.value) offset.value = 0
  else void load()
})
watch(offset, load)
watch(incidentFilter, () => (offset.value ? (offset.value = 0) : void load()))

const rehuntLabel = computed(() => (rehuntSource.value?.provider === 'mock' || rehuntSource.value?.clusterStatus === 'mock' ? t('tk.mockFixtures') : t('tqv.wazuhIndex')))
const isIr = computed(() => session.canExecuteResponse)
/** Only IR_TEAM decides (backend-enforced); the decision is taken on the ticket page, after reviewing the evidence. */
const canDecide = (ticket: WorkTicket) => !!ticket.currentApproval && session.role === 'IR_TEAM' && ticket.currentApproval.role === 'IR_TEAM'

// One action at a time (double-click protection); the list is always re-read from the backend afterwards.
const busyId = ref<string | null>(null)
async function run(ticket: WorkTicket, label: string, fn: () => Promise<unknown>, done?: 'started' | 'completed') {
  if (busyId.value) return
  busyId.value = ticket.id
  try {
    await fn()
    const where = `${incidentLabel(ticket.incidentId)} · ${ticket.stepTitle ?? t('tk.ticketWord')}`
    if (done) ui.notify(feedback(done, locale.value, {}, where))
    else ui.success(label, where)
  } catch (e) {
    ui.error(t('tqv.failedSuffix', { label }), describeWorkflowError(e))
  } finally {
    busyId.value = null
    await load()
  }
}
const eradicateFor = ref<string | null>(null)
const eradicateNote = ref('')
const start = (ticket: WorkTicket) => run(ticket, t('tqv.started'), () => workflowApi.start(ticket.id), 'started')
async function complete(ticket: WorkTicket) {
  const note = eradicateNote.value.trim()
  eradicateFor.value = null
  eradicateNote.value = ''
  await run(ticket, t('tqv.markedCompleted'), () => workflowApi.complete(ticket.id, { outcome: 'eradicated', note: note || null, by: session.session?.email ?? null }), 'completed')
}
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
async function reloadAfterAction() {
  await load()
  if (error.value) throw new Error('Reload failed')
}
</script>

<template>
  <div>
    <PageHeader :title="t('ui.page.tickets')" :description="t('tqv.description')">
      <template #actions>
        <button v-if="incidentFilter" type="button" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" @click="router.push({ path: '/tickets', query: { queue } })">{{ t('tqv.allIncidents') }}</button>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" :disabled="loading" @click="load"><RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('c.refresh') }}</button>
      </template>
    </PageHeader>

    <p v-if="rehuntSource" class="mb-3 inline-flex flex-wrap items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-xs text-slate-600 ring-1 ring-slate-200">
      <Database class="size-3.5 text-slate-400" /> {{ t('tqv.rehuntQueries') }} <strong>{{ rehuntLabel }}</strong>
      <span class="font-mono text-slate-400 break-all">{{ rehuntSource.indexPattern }}</span>
      <span :class="rehuntSource.reachable ? 'text-emerald-700' : 'text-rose-700'">· {{ rehuntSource.reachable ? t('tqv.reachable') : t('tqv.unreachable') }}</span>
    </p>
    <p v-if="incidentFilter" class="mb-3 text-sm text-slate-600">{{ t('tqv.ticketsOf') }} <strong>{{ incidentLabel(incidentFilter) }}</strong></p>

    <div class="mb-4 -mx-1 flex gap-1.5 overflow-x-auto px-1 pb-1" role="tablist">
      <button v-for="tab in TICKET_TABS" :key="tab.queue" type="button" role="tab" :aria-selected="queue === tab.queue" class="shrink-0 rounded-full px-3 py-1.5 text-xs font-semibold" :class="queue === tab.queue ? 'bg-navy-800 text-white' : 'bg-white text-slate-600 ring-1 ring-slate-200 hover:bg-slate-50'" @click="queue = tab.queue">
        {{ tab.label }} <span class="ml-1 opacity-70">{{ counts[tab.queue] ?? '·' }}</span>
      </button>
    </div>
    <p class="mb-3 text-[11px] text-slate-500">{{ t('tqv.myWorkHint') }}</p>

    <p v-if="error" class="mb-4 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }} <button type="button" class="underline" @click="load">{{ t('c.retry') }}</button></p>
    <p v-if="loading && !items.length" class="rounded-xl border border-slate-200 bg-white px-4 py-10 text-center text-sm text-slate-500">{{ t('tqv.loading') }}</p>
    <p v-else-if="!loading && !error && !items.length" class="rounded-xl border border-dashed border-slate-200 bg-white px-4 py-10 text-center text-sm text-slate-500">{{ t('tqv.empty') }}</p>

    <ul class="space-y-3">
      <li v-for="ticket in items" :key="ticket.id" class="rounded-xl border border-slate-200 bg-white p-4">
        <div class="flex flex-wrap items-start gap-3">
          <div class="min-w-0 flex-1">
            <p class="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span class="font-mono">{{ incidentLabel(ticket.incidentId) }}</span>
              <SeverityBadge :severity="toSeverity(ticket.incidentPriority)" size="sm" />
              <StatusPill :status="ticket.incidentStatus" />
              <span class="text-slate-400">{{ t('tqv.cycle', { n: ticket.investigationNumber }) }}</span>
            </p>
            <h2 class="mt-1 text-sm font-semibold text-slate-900 sm:text-base">
              <router-link :to="`/tickets/${ticket.id}`" class="hover:text-accent-700 hover:underline">{{ ticket.stepTitle ?? ticket.actionName ?? t('tk.responseTicket') }}</router-link>
            </h2>
            <p class="mt-0.5 line-clamp-1 text-xs text-slate-500">{{ ticket.incidentTitle }}</p>
            <p class="mt-1 text-xs text-slate-600">
              {{ t('tqv.target') }} <span class="font-mono break-all">{{ ticket.target ?? '—' }}</span> ·
              {{ t('tqv.executor') }} <strong>{{ ticket.assignedRole }}</strong> ·
              {{ t('tqv.assigned') }} <strong>{{ ticket.assignedToMe ? t('tqv.me') : ticket.assignedToEmail ?? t('tqv.unclaimed') }}</strong>
            </p>
          </div>
          <div class="text-right text-xs">
            <span class="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700 ring-1 ring-inset ring-slate-200">{{ WORK_STAGE_LABEL[ticket.stage] }}</span>
            <p class="mt-1 text-[11px] text-slate-400">{{ t('tqv.backend') }} <span class="font-mono">{{ ticket.status }}</span></p>
            <p v-if="ticket.verification" class="mt-1">{{ t('tqv.rehunt') }} <StatusPill :status="ticket.verification.result" /><span v-if="ticket.verification.spreadDetected" class="ml-1 text-rose-700">{{ t('tqv.spread') }}</span></p>
          </div>
        </div>


        <div class="mt-3 flex flex-wrap items-center gap-2">
          <template v-if="ticket.stage === 'AWAITING_IR_DECISION'">
            <RouterLink v-if="canDecide(ticket)" :to="`/tickets/${ticket.id}`" class="inline-flex items-center gap-1 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700">{{ t('tqv.reviewDecide') }}</RouterLink>
            <span v-else class="text-xs text-amber-700">{{ t('tqv.waitingDecision') }}</span>
          </template>

          <button v-if="ticket.stage === 'READY_FOR_EXECUTION' && isIr" type="button" class="inline-flex items-center gap-1 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:opacity-50" :disabled="!!busyId" :aria-busy="busyId === ticket.id" @click="start(ticket)"><Play class="size-3.5" /> {{ busyId === ticket.id ? t('tqv.starting') : t('tqv.start') }}</button>

          <template v-if="ticket.stage === 'IN_PROGRESS' && isIr">
            <button type="button" class="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-emerald-700" :disabled="!!busyId" @click="eradicateFor = ticket.id"><CheckCircle2 class="size-3.5" /> {{ t('tqv.markCompleted') }}</button>
            <WorkflowAction :label="t('tqv.markFailed')" reason-required :disabled="!!busyId" :action="(reason) => workflowApi.fail(ticket.id, { outcome: 'failed', reason, by: session.session?.email })" :reload="reloadAfterAction" />
          </template>

          <button v-if="ticket.stage === 'AWAITING_REHUNT' && isIr" type="button" class="inline-flex items-center gap-1 rounded-lg bg-accent-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-accent-700 disabled:opacity-50" :disabled="!!busyId" :aria-busy="busyId === ticket.id" @click="rehunt(ticket)">
            <ScanSearch class="size-3.5" /> {{ busyId === ticket.id ? t('tqv.rehunting', { source: rehuntLabel }) : t('tqv.runRehunt', { source: rehuntLabel }) }}
          </button>

          <p v-if="!isIr && ['READY_FOR_EXECUTION', 'IN_PROGRESS', 'AWAITING_REHUNT'].includes(ticket.stage)" class="text-xs text-slate-500">{{ t('tqv.irOnly') }}</p>

          <router-link :to="`/tickets/${ticket.id}`" class="inline-flex items-center gap-1 rounded-lg border border-accent-200 bg-accent-50 px-3 py-1.5 text-xs font-semibold text-accent-700 hover:bg-accent-100">{{ t('tqv.openTicket') }} <ArrowUpRight class="size-3.5" /></router-link>
          <router-link :to="`/incidents/${ticket.incidentId}?tab=recommendation`" class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50">{{ t('tqv.incident') }} <ArrowUpRight class="size-3.5" /></router-link>
          <span class="ml-auto text-[11px] text-slate-400" :title="formatDateTime(ticket.updatedAt)">{{ t('tqv.updated', { ago: timeAgo(ticket.updatedAt) }) }}</span>
        </div>

        <div v-if="eradicateFor === ticket.id" class="mt-3 flex flex-wrap items-center gap-2">
          <input v-model="eradicateNote" :placeholder="t('tqv.notePlaceholder')" :aria-label="t('tqv.noteAria')" class="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-1.5 text-sm sm:min-w-64" />
          <button type="button" class="rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-semibold text-white disabled:opacity-50" :disabled="!!busyId" @click="complete(ticket)">{{ t('tqv.confirmCompleted') }}</button>
          <button type="button" class="text-xs text-slate-500" @click="eradicateFor = null">{{ t('c.cancel') }}</button>
        </div>
      </li>
    </ul>

    <div v-if="total > PAGE" class="mt-3 flex flex-wrap items-center gap-2 text-xs text-slate-500">
      <span>{{ t('c.pageOf', { from: offset + 1, to: Math.min(offset + PAGE, total), total }) }}</span>
      <button class="rounded border border-slate-200 bg-white px-2 py-1 disabled:opacity-40" :disabled="loading || offset === 0" @click="offset = Math.max(0, offset - PAGE)">{{ t('c.previous') }}</button>
      <button class="rounded border border-slate-200 bg-white px-2 py-1 disabled:opacity-40" :disabled="loading || offset + PAGE >= total" @click="offset += PAGE">{{ t('c.next') }}</button>
    </div>
  </div>
</template>
