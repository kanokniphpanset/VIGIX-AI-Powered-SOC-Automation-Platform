<script setup lang="ts">
import MarkdownText from '@/components/common/MarkdownText.vue'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  AlertTriangle, ArrowLeft, ArrowUpRight, CheckCircle2, CircleDashed, Clock3, Crosshair, Database, Loader2, Play,
  RotateCw, ScanSearch, ShieldAlert, ShieldCheck, XCircle,
} from 'lucide-vue-next'
import StatusPill from '@/components/common/StatusPill.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import Modal from '@/components/common/Modal.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import { approvalChainFor, canDecideApproval, currentApproval } from '@/utils/workflow'
import { reasonNeededForDecision } from '@/utils/ticket'
import ResponseGuidePanel from '@/components/ir/ResponseGuidePanel.vue'
import {
  alertsApi, incidentsApi, items, slaApi, workflowApi,
  type AiAnalysis, type AlertSummary, type Approval, type Incident, type IncidentSla, type Ioc, type MitreMapping,
  type RecommendationStep, type RehuntHealth, type ResponsePlan, type Verification,
} from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { feedback, rehuntKind } from '@/utils/feedback'
import { dateLocale, useI18n } from '@/i18n'
import { incidentLabel, toSeverity } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { describeWorkflowError, STAGE_CLASS, STAGE_LABEL, ticketStage } from '@/utils/ticket'

/**
 * IR Ticket detail (real data only). One ticket = one response plan. Every status shown here comes from the backend:
 * Start / Mark eradicated / Re-hunt call the backend and then reload; the page never advances a status itself.
 * The instruction checklist and the notes draft are the analyst's working state in this browser — they change no
 * backend status and prove no containment; they are stored in the ticket's executionResult on completion.
 */
type Plan = ResponsePlan & { incidentId: string; createdAt: string }

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()
const planId = computed(() => String(route.params.id))

const loading = ref(true)
const loadError = ref('')
const plan = ref<Plan | null>(null)
const incident = ref<Incident | null>(null)
const step = ref<RecommendationStep | null>(null)
const approval = ref<Approval | null>(null)
const chain = ref<Approval[]>([])
const verification = ref<Verification | null>(null)
const ai = ref<AiAnalysis | null>(null)
const mitre = ref<MitreMapping[]>([])
const iocs = ref<Ioc[]>([])
const alertRef = ref<{ externalAlertId: string; siemSource: string; summary: AlertSummary } | null>(null)
const sla = ref<IncidentSla | null>(null)
const rehuntSource = ref<RehuntHealth | null>(null)

const busy = ref<'start' | 'complete' | 'rehunt' | 'action' | null>(null)
const actionError = ref('')
const rehuntError = ref<{ code: string; message: string } | null>(null)
const confirmOpen = ref(false)
/** The IR decision note — mandatory for both APPROVE and REJECT. */
const decisionNote = ref('')
const recommendationSummary = ref<string | null>(null)

const settle = <T,>(p: Promise<T>, fallback: T) => p.catch(() => fallback)

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    const p = await workflowApi.response(planId.value)
    const [inc, rec, apps, vers, analysis, mm, ioc, s, health] = await Promise.all([
      incidentsApi.get(p.incidentId),
      settle(workflowApi.recommendation(p.recommendationId), null),
      workflowApi.approvalsFor(p.recommendationId).then((r) => r.items),
      incidentsApi.verifications(p.incidentId).then((r) => r.items),
      settle(incidentsApi.aiAnalysis(p.incidentId), null),
      settle(incidentsApi.mitre(p.incidentId).then(items), [] as MitreMapping[]),
      settle(incidentsApi.iocs(p.incidentId).then(items), [] as Ioc[]),
      settle(slaApi.incident(p.incidentId), null),
      settle(slaApi.rehuntHealth(), null),
    ])
    plan.value = p
    incident.value = inc
    step.value = rec?.steps.find((x) => x.id === p.recommendationStepId) ?? null
    recommendationSummary.value = rec?.summary ?? null
    chain.value = approvalChainFor(apps, p.id)
    approval.value = currentApproval(chain.value)
    verification.value = vers.find((v) => v.responseId === p.id) ?? null
    ai.value = analysis
    mitre.value = mm
    iocs.value = ioc
    sla.value = s
    rehuntSource.value = health
    seen.value = ticketFingerprint(p, inc, apps, vers)
    stale.value = false
    alertRef.value = inc ? await settle(alertsApi.view(inc.alertId).then((v) => v.alert), null) : null
  } catch {
    loadError.value = t('tk.loadFailed')
    plan.value = null
  } finally {
    loading.value = false
  }
}
onMounted(load)

// Others act on the same ticket / incident (IR colleague, SOC, re-hunt): check every 30 s and offer the change with a
// banner instead of reloading under the reader, who may be writing the decision note.
const seen = ref('')
const stale = ref(false)
function ticketFingerprint(p: Plan, inc: Incident | null, apps: Approval[], vers: Verification[]) {
  return JSON.stringify([p.status, inc?.status, inc?.investigationNumber, apps.map((a) => `${a.id}:${a.status}`).sort(), vers.map((v) => v.id).sort()])
}
async function checkForUpdates() {
  const p0 = plan.value
  if (!p0 || loading.value || stale.value || busy.value || document.hidden) return
  try {
    const p = await workflowApi.response(planId.value)
    const [inc, apps, vers] = await Promise.all([incidentsApi.get(p.incidentId), workflowApi.approvalsFor(p.recommendationId).then((r) => r.items), incidentsApi.verifications(p.incidentId).then((r) => r.items)])
    if (!loading.value && plan.value?.id === p.id && ticketFingerprint(p, inc, apps, vers) !== seen.value) stale.value = true
  } catch { /* offline for a moment — try again on the next tick */ }
}
const poll = setInterval(checkForUpdates, 30_000)
onUnmounted(() => clearInterval(poll))
async function reloadAfterAction() { await load(); if (loadError.value) throw new Error('Reload failed') }
watch(planId, load)

// ---------------------------------------------------------------- derived (backend state only)
const stage = computed(() => (plan.value ? ticketStage(plan.value.status, verification.value, incident.value?.status ?? null) : null))
const canExecute = computed(() => session.canExecuteResponse)
const canDecide = computed(() => !!approval.value && canDecideApproval(session.role, approval.value))
async function decide(kind: 'approve' | 'reject') {
  const note = decisionNote.value.trim()
  if (!approval.value || busy.value || reasonNeededForDecision(note)) return
  busy.value = 'action'
  actionError.value = ''
  try {
    if (kind === 'approve') await workflowApi.approve(approval.value.id, note)
    else await workflowApi.reject(approval.value.id, note)
    decisionNote.value = ''
    ui.notify(feedback(kind === 'approve' ? 'approved' : 'rejected', locale.value))
    await load()
  } catch (e) {
    actionError.value = describeWorkflowError(e)
    ui.error(kind === 'approve' ? t('tk.approveFailed') : t('tk.rejectFailed'), actionError.value)
  } finally {
    busy.value = null
  }
}
const instructions = computed(() => step.value?.instructions ?? [])
const severity = computed(() => toSeverity(incident.value?.priority))
const rehuntLabel = computed(() => (rehuntSource.value?.provider === 'mock' || rehuntSource.value?.clusterStatus === 'mock' ? t('tk.mockFixtures') : t('tk.wazuhIndexer')))
const indicators = computed(() => {
  const s = alertRef.value?.summary
  const byType = (...types: string[]) => [...new Set(iocs.value.filter((i) => types.includes(i.iocType.toUpperCase())).map((i) => i.iocValue))]
  return [
    [t('tk.ind.sourceIp'), s?.sourceIp ? [s.sourceIp] : []],
    [t('tk.ind.destIp'), s?.destinationIp ? [s.destinationIp] : []],
    [t('tk.ind.host'), s?.host ? [s.host] : []],
    [t('tk.ind.user'), s?.user ? [s.user] : byType('USERNAME')],
    [t('tk.ind.domain'), byType('DOMAIN')],
    [t('tk.ind.hash'), byType('MD5', 'SHA1', 'SHA256', 'HASH')],
  ].filter(([, v]) => (v as string[]).length) as [string, string[]][]
})

/** What the analyst submitted on completion (stored by the backend in executionResult). */
const submitted = computed(() => {
  const r = plan.value?.executionResult ?? null
  if (!r) return null
  const checklist = Array.isArray(r.checklist) ? (r.checklist as { order: number; instruction: string; done: boolean }[]) : null
  return { note: typeof r.note === 'string' ? r.note : null, outcome: typeof r.outcome === 'string' ? r.outcome : null, checklist }
})

// ---------------------------------------------------------------- analyst working state (this browser only)
const storeKey = (k: string) => `vigix.ticket.${k}.${planId.value}`
function readLocal<T>(k: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(storeKey(k))
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}
function writeLocal(k: string, v: unknown) {
  try {
    localStorage.setItem(storeKey(k), JSON.stringify(v))
  } catch {
    /* storage unavailable: the working state simply isn't remembered */
  }
}
const checked = ref<Set<number>>(new Set(readLocal<number[]>('checklist', [])))
const notes = ref(readLocal<string>('notes', ''))
watch(planId, () => {
  checked.value = new Set(readLocal<number[]>('checklist', []))
  notes.value = readLocal<string>('notes', '')
})
watch(notes, (v) => writeLocal('notes', v))
function toggleCheck(order: number) {
  const next = new Set(checked.value)
  if (next.has(order)) next.delete(order)
  else next.add(order)
  checked.value = next
  writeLocal('checklist', [...next])
}
const checklistEditable = computed(() => stage.value === 'IN_PROGRESS' && canExecute.value)
const isDone = (order: number) =>
  submitted.value?.checklist ? !!submitted.value.checklist.find((c) => c.order === order)?.done : checked.value.has(order)
const doneCount = computed(() => instructions.value.filter((i) => isDone(i.order)).length)
const progressPct = computed(() => (instructions.value.length ? Math.round((doneCount.value / instructions.value.length) * 100) : 0))

// ---------------------------------------------------------------- actions (backend only)
async function start() {
  if (!plan.value || busy.value) return
  busy.value = 'start'
  actionError.value = ''
  try {
    await workflowApi.start(plan.value.id)
    ui.notify(feedback('started', locale.value, {}, `${incidentLabel(plan.value.incidentId)} · ${step.value?.title ?? t('tk.ticketWord')}`))
    await load()
  } catch (e) {
    actionError.value = describeWorkflowError(e)
    ui.error(t('tk.startFailed'), actionError.value)
  } finally {
    busy.value = null
  }
}

async function complete() {
  if (!plan.value || busy.value) return
  confirmOpen.value = false
  busy.value = 'complete'
  actionError.value = ''
  try {
    await workflowApi.complete(plan.value.id, {
      outcome: 'eradicated',
      note: notes.value.trim() || null,
      by: session.session?.email ?? null,
      checklist: instructions.value.map((i) => ({ order: i.order, instruction: i.instruction, done: checked.value.has(i.order) })),
    })
    ui.notify(feedback('completed', locale.value))
    await load()
  } catch (e) {
    actionError.value = describeWorkflowError(e)
    ui.error(t('tk.completeFailed'), actionError.value)
  } finally {
    busy.value = null
  }
}

async function rehunt() {
  if (!plan.value || busy.value) return
  busy.value = 'rehunt'
  rehuntError.value = null
  try {
    await workflowApi.rehunt(plan.value.incidentId, plan.value.id)
    await load()
    const v = verification.value
    ui.notify(feedback(rehuntKind(v?.result, incident.value?.status), locale.value, { inc: incidentLabel(plan.value.incidentId), n: incident.value?.investigationNumber ?? '?', incidentId: plan.value.incidentId }))
  } catch (e) {
    rehuntError.value = { code: e instanceof Error ? e.message : 'UNKNOWN', message: describeWorkflowError(e) }
    ui.error(t('tk.rehuntFailed'), rehuntError.value.message)
  } finally {
    busy.value = null
  }
}

// ---------------------------------------------------------------- lifecycle stepper
type StepState = 'done' | 'current' | 'todo' | 'bad'
const lifecycle = computed(() => {
  const s = stage.value
  const order = ['READY_FOR_EXECUTION', 'IN_PROGRESS', 'AWAITING_REHUNT', 'VERDICT'] as const
  const reached = s === 'AWAITING_IR_DECISION' || s === 'REJECTED' || s === 'CLOSED' ? -1 : s === 'READY_FOR_EXECUTION' ? 0 : s === 'IN_PROGRESS' ? 1 : s === 'AWAITING_REHUNT' ? 2 : 3
  const state = (i: number): StepState => (i < reached ? 'done' : i === reached ? (i === 3 ? (s === 'COMPLETED' ? 'done' : 'bad') : 'current') : 'todo')
  const verdict = t(s === 'COMPLETED' ? 'tk.lc.resolved' : s === 'ESCALATED' ? 'tk.lc.escalated' : s === 'NOT_RESOLVED' ? 'tk.lc.newCycle' : 'tk.lc.verdict')
  const out: { key: string; label: string; state: StepState }[] = []
  if (plan.value) {
    out.push({ key: 'APPROVAL', label: t('tk.lc.approval'), state: s === 'AWAITING_IR_DECISION' ? 'current' : plan.value.status === 'REJECTED' || plan.value.approvalStatus === 'REJECTED' ? 'bad' : 'done' })
  }
  const labels = [t('tk.lc.ready'), t('tk.lc.inProgress'), t('tk.lc.awaitingRehunt'), verdict]
  order.forEach((k, i) => out.push({ key: k, label: labels[i], state: state(i) }))
  return out
})
const STEP_DOT: Record<StepState, string> = {
  done: 'bg-emerald-500 text-white ring-emerald-500',
  current: 'bg-white text-accent-700 ring-accent-500 ring-2',
  todo: 'bg-white text-slate-300 ring-slate-200',
  bad: 'bg-rose-500 text-white ring-rose-500',
}

function exact(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.toLocaleDateString(locale.value === 'th' ? dateLocale() : 'en-GB', { day: '2-digit', month: 'short', year: 'numeric', timeZone: 'UTC' })}, ${d.toISOString().slice(11, 19)} UTC`
}
const events = computed(() => verification.value?.afterState?.events ?? [])
const matched = computed(() => (verification.value?.matchingEvents ?? 0) > 0)
</script>

<template>
  <div class="mx-auto max-w-7xl">
    <p v-if="plan?.status === 'FAILED'" role="status" class="mb-3 rounded bg-rose-50 p-3 text-rose-700">{{ t('tk.couldNotComplete', { reason: String(plan.executionResult?.reason ?? plan.executionResult?.note ?? t('tk.noReason')) }) }}</p>
    <button type="button" class="mb-3 inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-900" @click="router.push('/tickets')">
      <ArrowLeft class="size-4" /> {{ t('ui.page.tickets') }}
    </button>

    <!-- loading / error states -->
    <div v-if="loading && !plan" class="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-10 text-sm text-slate-500" role="status">
      <Loader2 class="size-4 animate-spin" /> {{ t('tk.loading') }}
    </div>
    <div v-else-if="loadError" class="rounded-xl border border-rose-200 bg-rose-50 px-4 py-6 text-sm text-rose-700" role="alert">
      <p class="font-semibold">{{ loadError }}</p>
      <p class="mt-1 text-rose-600">{{ t('tk.maybeMissing') }}</p>
      <button type="button" class="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-xs font-semibold text-rose-700" @click="load"><RotateCw class="size-3.5" /> {{ t('c.retry') }}</button>
    </div>

    <template v-else-if="plan && stage">
      <div v-if="stale" class="mb-3 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm text-amber-900" role="status">
        <span>{{ t('tk.updatedBanner') }}</span>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-amber-900 ring-1 ring-amber-300 hover:bg-amber-100" @click="load"><RotateCw class="size-3.5" /> {{ t('tk.updatedShow') }}</button>
      </div>
      <!-- Header -->
      <header class="rounded-xl border border-slate-200 bg-white p-5">
        <div class="flex flex-wrap items-start gap-4">
          <div class="min-w-0 flex-1">
            <p class="flex flex-wrap items-center gap-2 text-xs text-slate-500">
              <span class="font-mono font-semibold text-slate-700">{{ incidentLabel(plan.incidentId) }}</span>
              <span>·</span><span>{{ t('inc.investigationN', { n: incident?.investigationNumber ?? '—' }) }}</span>
              <StatusPill v-if="incident" :status="incident.status" />
            </p>
            <h1 class="mt-1 text-xl font-semibold text-slate-900">{{ incident?.title ?? t('tk.responseTicket') }}</h1>
            <p class="mt-1 text-sm text-slate-600">{{ step?.title ?? t('tk.responseAction') }} <span v-if="plan.target && !step?.title?.includes(plan.target)" class="font-mono text-slate-800">→ {{ plan.target }}</span></p>
          </div>
          <div class="flex flex-col items-end gap-2">
            <span class="inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold uppercase tracking-wide ring-1 ring-inset" :class="STAGE_CLASS[stage]">
              <span class="size-1.5 rounded-full bg-current" /> {{ STAGE_LABEL[stage] }}
            </span>
            <span class="text-[11px] text-slate-400">{{ t('tk.backendStatus') }} <span class="font-mono">{{ plan.status }}</span></span>
          </div>
        </div>
        <dl class="mt-4 grid grid-cols-2 gap-3 border-t border-slate-100 pt-4 text-sm sm:grid-cols-4">
          <div><dt class="text-xs text-slate-400">{{ t('tk.severity') }}</dt><dd class="mt-1"><SeverityBadge v-if="incident" :severity="severity" size="sm" /><span v-else>—</span></dd></div>
          <div><dt class="text-xs text-slate-400">{{ t('tk.sourceAlert') }}</dt><dd class="mt-1 text-xs text-slate-700">{{ alertRef ? t('tk.ruleLevel', { rule: alertRef.summary.ruleId ?? '—', level: alertRef.summary.ruleLevel ?? '—' }) : '—' }}</dd></div>
          <div><dt class="text-xs text-slate-400">{{ t('tk.decidedBy') }}</dt><dd class="mt-1 font-semibold text-slate-900">{{ plan.assignedRole }}<span v-if="plan.assignedTo" class="font-normal text-slate-500"> · {{ plan.assignedTo }}</span></dd></div>
          <div class="flex items-end justify-end">
            <button type="button" class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-medium text-slate-700 hover:bg-slate-50" @click="router.push(`/incidents/${plan.incidentId}`)">{{ t('tk.viewIncident') }} <ArrowUpRight class="size-3.5" /></button>
          </div>
        </dl>
      </header>

      <!-- Lifecycle -->
      <nav :aria-label="t('tk.lifecycleAria')" class="mt-4 rounded-xl border border-slate-200 bg-white px-5 py-4">
        <ol class="flex flex-wrap items-center gap-y-3">
          <li v-for="(s, i) in lifecycle" :key="s.key" class="flex items-center">
            <span class="flex items-center gap-2" :aria-current="s.state === 'current' ? 'step' : undefined">
              <span class="flex size-6 items-center justify-center rounded-full text-[11px] font-bold ring-1" :class="STEP_DOT[s.state]">
                <CheckCircle2 v-if="s.state === 'done'" class="size-4" /><XCircle v-else-if="s.state === 'bad'" class="size-4" /><template v-else>{{ i + 1 }}</template>
              </span>
              <span class="text-xs font-semibold" :class="s.state === 'todo' ? 'text-slate-400' : s.state === 'bad' ? 'text-rose-700' : 'text-slate-800'">{{ s.label }}</span>
            </span>
            <span v-if="i < lifecycle.length - 1" class="mx-3 h-px w-8 bg-slate-200 sm:w-12" aria-hidden="true" />
          </li>
        </ol>
        <p v-if="stage === 'NOT_RESOLVED'" class="mt-3 text-xs text-slate-600">{{ t('tk.notResolvedFlow') }}<strong>{{ t('tk.newInvestigation', { n: incident?.investigationNumber ?? '—' }) }}</strong>{{ t('tk.notResolvedFlowTail') }}</p>
        <p v-else-if="stage === 'CLOSED'" class="mt-3 text-xs text-slate-600">{{ t('tk.closedNote', { status: plan.status }) }}</p>
      </nav>

      <div class="mt-4 grid gap-4 lg:grid-cols-3">
        <!-- ============ main column ============ -->
        <div class="min-w-0 space-y-4 lg:col-span-2">
          <!-- Response action + instructions -->
          <!-- What SOC sent: AI analysis (grounded in the Wazuh evidence) and the reviewed recommendation -->
          <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="ai-h">
            <h2 id="ai-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.aiAndRec') }}</h2>
            <div v-if="ai?.grounding?.status === 'UNGROUNDED'" role="alert" class="mt-2 rounded border border-rose-300 bg-rose-50 p-3 text-sm text-rose-800">
              <strong>{{ t('tk.ungrounded') }}</strong>
              <p v-for="issue in ai.grounding.ungrounded" :key="issue.kind + issue.value">{{ issue.kind }}: {{ issue.value }}</p>
            </div>
            <p v-if="ai?.summary && locale === 'th'" class="mt-2 inline-block rounded bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600">{{ t('ai.originalLang') }}</p>
            <MarkdownText v-if="ai?.summary" :text="ai.summary" class="mt-2" />
            <p v-else class="mt-2 text-sm text-slate-800">{{ t('tk.noAi') }}</p>
            <ul v-if="ai?.keyFindings.length" class="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-700"><li v-for="f in ai.keyFindings" :key="f">{{ f }}</li></ul>
            <h3 class="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.recReviewed') }}</h3>
            <p class="mt-1 text-sm text-slate-800">{{ recommendationSummary ?? t('c.notAvailable') }}</p>
            <p v-if="step" class="mt-2 text-xs text-slate-500">{{ t('tk.whyAction', { text: step.reason }) }}</p>
            <p v-if="step?.evidence.length" class="mt-1 text-[11px] text-slate-400">{{ t('inc.evidence', { text: step.evidence.join(' · ') }) }}</p>
          </section>

          <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="action-h">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="action-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.responseAction') }}</h2>
                <p class="mt-1 flex items-center gap-2 text-lg font-semibold text-slate-900"><Crosshair class="size-5 text-accent-600" /> {{ step?.title ?? t('tk.stepUnavailable') }}</p>
                <p class="mt-1 text-sm text-slate-600">{{ t('tk.target') }} <span class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-slate-900">{{ plan.target ?? '—' }}</span></p>
              </div>
              <div v-if="instructions.length" class="w-full sm:w-56">
                <p class="flex justify-between text-xs text-slate-500"><span>{{ t('tk.progress') }}</span><span class="font-semibold text-slate-800">{{ t('tk.stepsOf', { done: doneCount, total: instructions.length }) }}</span></p>
                <div class="mt-1.5 h-2 overflow-hidden rounded-full bg-slate-100" role="progressbar" :aria-valuenow="doneCount" aria-valuemin="0" :aria-valuemax="instructions.length">
                  <div class="h-full rounded-full bg-emerald-500 transition-all" :style="{ width: `${progressPct}%` }" />
                </div>
              </div>
            </div>
            <p v-if="step?.objective" class="mt-3 text-sm text-slate-700">{{ step.objective }}</p>
            <p v-if="plan.reason" class="mt-1 text-xs text-slate-500">{{ t('tk.why', { text: plan.reason }) }}</p>

            <h3 class="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.instructions') }}</h3>
            <p v-if="!instructions.length" class="mt-2 text-sm text-slate-500">{{ t('tk.noInstructions') }}</p>
            <ul v-else class="mt-2 divide-y divide-slate-100 rounded-lg border border-slate-200">
              <li v-for="ins in instructions" :key="ins.order">
                <label class="flex gap-3 px-3 py-2.5" :class="checklistEditable ? 'cursor-pointer hover:bg-slate-50' : ''">
                  <input type="checkbox" class="mt-0.5 size-4 shrink-0 accent-emerald-600" :checked="isDone(ins.order)" :disabled="!checklistEditable" @change="toggleCheck(ins.order)" />
                  <span class="min-w-0 text-sm" :class="isDone(ins.order) ? 'text-slate-500 line-through decoration-slate-300' : 'text-slate-800'">
                    <span class="mr-1 font-semibold text-slate-400">{{ ins.order }}.</span>{{ ins.instruction }}
                    <span v-if="ins.expectedResult" class="mt-0.5 block text-xs text-slate-400 no-underline">{{ t('tk.expected', { text: ins.expectedResult }) }}</span>
                  </span>
                </label>
              </li>
            </ul>
            <p v-if="step?.verificationCriteria" class="mt-3 rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-800">{{ t('tk.criteria', { text: step.verificationCriteria }) }}</p>
            <p v-if="stage === 'IN_PROGRESS'" class="mt-2 text-[11px] text-slate-400">{{ t('tk.checklistNote') }}</p>
          </section>

          <!-- Execution notes -->
          <section v-if="stage === 'READY_FOR_EXECUTION' || stage === 'IN_PROGRESS'" class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="notes-h">
            <h2 id="notes-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.notes') }}</h2>
            <textarea v-model="notes" rows="4" :disabled="!canExecute" :placeholder="t('tk.notesPlaceholder')" :aria-label="t('tk.notesAria')" class="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none disabled:bg-slate-50" />
            <p class="mt-1 text-[11px] text-slate-400">{{ t('tk.notesHint') }}</p>
          </section>

          <!-- Actions -->
          <section v-if="stage === 'READY_FOR_EXECUTION' || stage === 'IN_PROGRESS' || stage === 'AWAITING_IR_DECISION'" class="rounded-xl border border-slate-200 bg-white p-5">
            <div v-if="stage === 'AWAITING_IR_DECISION'" class="space-y-3">
              <p class="text-sm font-semibold text-slate-800">{{ t('tk.irDecision') }} <span class="font-normal text-slate-500">{{ t('tk.irDecisionHint') }}</span></p>
              <template v-if="canDecide">
                <label class="block text-xs font-semibold text-slate-600">
                  {{ t('tk.decisionNote') }}
                  <textarea v-model="decisionNote" rows="3" maxlength="4000" :placeholder="t('tk.decisionPlaceholder')" class="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm font-normal" />
                </label>
                <p v-if="actionError" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ actionError }}</p>
                <div class="flex flex-wrap gap-2">
                  <button type="button" class="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:opacity-50" :disabled="!!busy || reasonNeededForDecision(decisionNote)" @click="decide('approve')"><CheckCircle2 class="size-4" /> {{ t('tk.approve') }}</button>
                  <button type="button" class="inline-flex items-center gap-1 rounded-lg border border-rose-300 px-4 py-2 text-sm font-semibold text-rose-700 hover:bg-rose-50 disabled:opacity-50" :disabled="!!busy || reasonNeededForDecision(decisionNote)" @click="decide('reject')">{{ t('tk.reject') }}</button>
                </div>
                <p class="text-[11px] text-slate-400">{{ t('tk.decisionHelp') }}</p>
              </template>
              <p v-else-if="approval" class="text-sm text-amber-800">{{ t('tk.waitingDecision') }}</p>
              <WorkflowAction v-if="!approval && session.canRunAiAnalysis" :label="t('tk.reopenDecision')" :disabled="!!busy" @busy="busy = $event ? 'action' : null" :action="() => workflowApi.requestApproval(plan!.recommendationId, plan!.id)" :reload="reloadAfterAction" />
            </div>
            <template v-else>
              <p v-if="!canExecute" class="mb-3 flex items-center gap-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800" role="note"><ShieldAlert class="size-4 shrink-0" /> {{ t('tk.notAuthorized') }}</p>
              <p v-if="actionError" class="mb-3 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ actionError }}</p>
              <div class="flex flex-wrap items-center gap-3">
                <button v-if="stage === 'READY_FOR_EXECUTION'" type="button" class="inline-flex items-center gap-2 rounded-lg bg-navy-800 px-4 py-2 text-sm font-semibold text-white hover:bg-navy-700 disabled:cursor-not-allowed disabled:opacity-50" :disabled="!canExecute || !!busy" @click="start">
                  <Loader2 v-if="busy === 'start'" class="size-4 animate-spin" /><Play v-else class="size-4" /> {{ t('tk.start') }}
                </button>
                <button v-if="stage === 'IN_PROGRESS'" type="button" class="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white hover:bg-emerald-700 disabled:cursor-not-allowed disabled:opacity-50" :disabled="!canExecute || !!busy" @click="confirmOpen = true">
                  <Loader2 v-if="busy === 'complete'" class="size-4 animate-spin" /><ShieldCheck v-else class="size-4" /> {{ t('tk.markEradicated') }}
                </button>
                <span class="text-xs text-slate-400">{{ stage === 'READY_FOR_EXECUTION' ? t('tk.startHint') : t('tk.completeHint') }}</span>
              </div>
              <WorkflowAction v-if="stage === 'IN_PROGRESS' && canExecute" :label="t('tk.couldNotCompleteBtn')" reason-required :disabled="!!busy" :action="reason => workflowApi.fail(plan!.id, { outcome: 'failed', reason, by: session.session?.email })" :reload="reloadAfterAction" />
            </template>
          </section>

          <!-- Response completed / awaiting re-hunt -->
          <section v-if="plan.completedAt" class="rounded-xl border border-emerald-200 bg-white p-5" aria-labelledby="done-h">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="done-h" class="flex items-center gap-2 text-base font-semibold text-emerald-800"><CheckCircle2 class="size-5" /> {{ t('tk.completed') }}</h2>
                <p class="mt-1 text-sm text-slate-600">{{ t('tk.completedAt') }} <strong class="font-mono text-slate-900">{{ exact(plan.completedAt) }}</strong></p>
                <p v-if="submitted?.note" class="mt-2 whitespace-pre-line rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">{{ submitted.note }}</p>
              </div>
            </div>
            <div v-if="stage === 'AWAITING_REHUNT'" class="mt-4 rounded-lg border border-accent-200 bg-accent-50 p-4">
              <p class="text-sm font-semibold text-slate-900">{{ t('tk.verification') }}</p>
              <p class="mt-1 text-sm text-slate-700">{{ t('tk.rehuntIntro') }} <strong>{{ rehuntLabel }}</strong><span v-if="rehuntSource" class="font-mono text-xs text-slate-500"> {{ rehuntSource.indexPattern }}</span> {{ t('tk.rehuntIntroTail') }}</p>
              <p v-if="!canExecute" class="mt-2 flex items-center gap-2 text-sm text-amber-800"><ShieldAlert class="size-4" /> {{ t('tk.notAuthorized') }}</p>
              <button type="button" class="mt-3 inline-flex items-center gap-2 rounded-lg bg-accent-600 px-4 py-2 text-sm font-semibold text-white hover:bg-accent-700 disabled:cursor-not-allowed disabled:opacity-50" :disabled="!canExecute || !!busy" @click="rehunt">
                <Loader2 v-if="busy === 'rehunt'" class="size-4 animate-spin" /><ScanSearch v-else class="size-4" /> {{ busy === 'rehunt' ? t('tk.rehunting', { source: rehuntLabel }) : t('tk.runRehunt') }}
              </button>
            </div>
            <div v-if="rehuntError" class="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-4" role="alert">
              <p class="flex items-center gap-2 text-sm font-bold text-rose-800"><AlertTriangle class="size-4" /> {{ t('tk.rehuntError') }}</p>
              <p class="mt-1 text-sm text-rose-700">{{ rehuntError.message }}</p>
              <p class="mt-1 font-mono text-[11px] text-rose-500">{{ rehuntError.code }}</p>
            </div>
          </section>

          <!-- Re-hunt result -->
          <section v-if="verification" class="rounded-xl border bg-white p-5" :class="matched ? 'border-rose-200' : 'border-emerald-200'" aria-labelledby="rehunt-h">
            <div class="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 id="rehunt-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.rehuntResult') }}</h2>
                <p class="mt-1 text-2xl font-black tracking-wide" :class="matched ? 'text-rose-700' : 'text-emerald-700'">{{ matched ? t('tk.match') : t('tk.noMatch') }}</p>
                <p class="mt-1 text-sm text-slate-700">{{ matched ? t('tk.matchBody') : t('tk.noMatchBody') }}</p>
              </div>
              <div class="text-right">
                <StatusPill :status="verification.result" />
                <p class="mt-1 text-xs text-slate-500">{{ t('tk.verifiedAt', { at: exact(verification.verifiedAt) }) }}</p>
              </div>
            </div>
            <dl class="mt-4 grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <div><dt class="text-xs text-slate-400">{{ t('tk.matchingEvents') }}</dt><dd class="font-semibold">{{ verification.matchingEvents ?? 0 }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('tk.source') }}</dt><dd class="flex items-center gap-1 font-semibold"><Database class="size-3.5 text-slate-400" />{{ verification.afterState?.evidenceSource ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('tk.index') }}</dt><dd class="truncate font-mono text-xs">{{ verification.wazuhIndex ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('tk.hosts') }}</dt><dd class="truncate">{{ verification.affectedHosts?.length ? verification.affectedHosts.join(', ') : '—' }}</dd></div>
            </dl>
            <p v-if="verification.timeRangeStart" class="mt-2 text-xs text-slate-500">{{ t('tk.window', { from: exact(verification.timeRangeStart), to: exact(verification.timeRangeEnd) }) }}</p>
            <!-- What the re-hunt actually covered. Skipped / excluded IOCs were NOT searched — they are not a NO MATCH. -->
            <dl v-if="verification.afterState?.searchedIocs || verification.afterState?.skippedIocs?.length || verification.afterState?.excludedIocs?.length" class="mt-3 space-y-2 rounded-lg bg-slate-50 p-3 text-xs">
              <div v-if="verification.afterState?.searchedIocs">
                <dt class="font-semibold text-slate-600">{{ t('tk.searched') }}</dt>
                <dd class="mt-0.5 flex flex-wrap gap-1.5">
                  <span v-for="i in verification.afterState.searchedIocs" :key="'s' + i.type + i.value" class="rounded bg-white px-1.5 py-0.5 font-mono text-slate-800 ring-1 ring-slate-200">{{ i.type.toUpperCase() }}:{{ i.value }}</span>
                  <span v-if="!verification.afterState.searchedIocs.length" class="text-slate-400">—</span>
                </dd>
              </div>
              <div v-if="verification.afterState?.skippedIocs?.length">
                <dt class="font-semibold text-amber-700">{{ t('tk.skipped') }}</dt>
                <dd v-for="i in verification.afterState.skippedIocs" :key="'k' + i.type + i.value" class="mt-0.5"><span class="font-mono text-slate-800">{{ i.type.toUpperCase() }}:{{ i.value }}</span> <span class="text-slate-500">— {{ i.reason }}</span></dd>
              </div>
              <div v-if="verification.afterState?.excludedIocs?.length">
                <dt class="font-semibold text-slate-600">{{ t('tk.excluded') }}</dt>
                <dd v-for="i in verification.afterState.excludedIocs" :key="'x' + i.type + i.value" class="mt-0.5"><span class="font-mono text-slate-800">{{ i.type.toUpperCase() }}:{{ i.value }}</span> <span class="text-slate-500">— {{ i.reason }}</span></dd>
              </div>
            </dl>
            <div class="mt-2 flex flex-wrap gap-2 text-[11px]">
              <span v-if="verification.iocRecurrence" class="rounded bg-amber-50 px-1.5 py-0.5 font-semibold text-amber-700">{{ t('tk.iocRecurrence') }}</span>
              <span v-if="verification.spreadDetected" class="rounded bg-rose-50 px-1.5 py-0.5 font-semibold text-rose-700">{{ t('tk.spread') }}</span>
              <span class="rounded bg-slate-100 px-1.5 py-0.5 text-slate-600">{{ t('tk.contained', { v: verification.threatContained ? t('c.yes') : t('c.no') }) }}</span>
            </div>
            <div v-if="events.length" class="mt-4 overflow-x-auto">
              <table class="w-full min-w-[560px] text-sm">
                <thead class="text-left text-xs text-slate-400"><tr><th class="pb-2 pr-3">{{ t('tk.ev.timestamp') }}</th><th class="pb-2 pr-3">{{ t('tk.ev.host') }}</th><th class="pb-2 pr-3">{{ t('tk.ev.rule') }}</th><th class="pb-2 pr-3">{{ t('tk.ev.ioc') }}</th><th class="pb-2">{{ t('tk.ev.event') }}</th></tr></thead>
                <tbody class="divide-y divide-slate-100">
                  <tr v-for="ev in events" :key="ev.id">
                    <td class="py-2 pr-3 font-mono text-xs">{{ exact(ev.timestamp) }}</td>
                    <td class="py-2 pr-3">{{ ev.host ?? '—' }}</td>
                    <td class="py-2 pr-3 text-xs"><span class="font-mono">{{ ev.ruleId ?? '—' }}</span><span v-if="ev.ruleDescription" class="block text-slate-500">{{ ev.ruleDescription }}</span></td>
                    <td class="py-2 pr-3 font-mono text-xs">{{ [...new Set(ev.matchedIocValues ?? [])].join(', ') || '—' }}</td>
                    <td class="py-2 font-mono text-[11px] text-slate-500">{{ ev.id }}</td>
                  </tr>
                </tbody>
              </table>
              <p v-if="verification.afterState?.truncated" class="mt-1 text-[11px] text-slate-400">{{ t('tk.truncated') }}</p>
            </div>
            <div v-if="stage === 'NOT_RESOLVED' || stage === 'ESCALATED'" class="mt-4 rounded-lg p-3 text-sm" :class="stage === 'ESCALATED' ? 'bg-rose-50 text-rose-800' : 'bg-amber-50 text-amber-900'">
              <template v-if="stage === 'ESCALATED'">{{ t('tk.escalatedBody') }} <strong>{{ t('tk.escalatedWord') }}</strong>{{ t('tk.escalatedTail') }}</template>
              <template v-else>{{ t('tk.notResolvedBody') }} <strong>{{ t('tk.investigationN', { n: incident?.investigationNumber ?? '—' }) }}</strong>{{ t('tk.notResolvedTail') }}</template>
              <button type="button" class="ml-2 inline-flex items-center gap-1 font-semibold underline" @click="router.push(`/incidents/${plan.incidentId}?tab=recommendation`)">{{ t('tk.openNewRec') }} <ArrowUpRight class="size-3.5" /></button>
            </div>
          </section>
        </div>

        <!-- ============ side column ============ -->
        <aside class="min-w-0 space-y-4">
          <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="inc-h">
            <h2 id="inc-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.incidentSummary') }}</h2>
            <p v-if="!incident" class="mt-2 text-sm text-slate-500">{{ t('tk.incidentUnavailable') }}</p>
            <dl v-else class="mt-3 space-y-2.5 text-sm">
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.incidentId') }}</dt><dd class="truncate font-mono text-xs text-slate-700" :title="incident.id">{{ incident.id }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.severity') }}</dt><dd><SeverityBadge :severity="severity" size="sm" /></dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.priority') }}</dt><dd class="font-semibold">{{ sla?.priority ?? '—' }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">MITRE</dt><dd class="text-right">
                <span v-if="!mitre.length">—</span>
                <span v-for="m in mitre" :key="m.techniqueId" class="ml-1 inline-block rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-white" :title="m.tactic">{{ m.techniqueId }}</span>
              </dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.investigation') }}</dt><dd class="font-semibold">#{{ incident.investigationNumber }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.sourceAlert') }}</dt><dd class="text-right text-xs">
                <template v-if="alertRef"><span class="font-mono">{{ alertRef.externalAlertId }}</span><span class="block text-slate-500">{{ alertRef.siemSource }}<template v-if="alertRef.summary.ruleId"> · {{ t('tk.rule', { id: alertRef.summary.ruleId }) }}</template></span></template>
                <template v-else>—</template>
              </dd></div>
            </dl>
            <template v-if="indicators.length">
              <h3 class="mt-4 border-t border-slate-100 pt-3 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.indicators') }}</h3>
              <dl class="mt-2 space-y-2 text-sm">
                <div v-for="[label, vals] in indicators" :key="label" class="flex justify-between gap-3"><dt class="shrink-0 text-slate-400">{{ label }}</dt><dd class="min-w-0 text-right font-mono text-xs text-slate-800"><span v-for="v in vals" :key="v" class="block truncate" :title="v">{{ v }}</span></dd></div>
              </dl>
            </template>
            <template v-if="iocs.length">
              <h3 class="mt-4 border-t border-slate-100 pt-3 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.iocsN', { n: iocs.length }) }}</h3>
              <ul class="mt-2 space-y-1.5 text-xs">
                <li v-for="i in iocs" :key="i.id" class="flex items-center justify-between gap-2">
                  <span class="min-w-0 truncate"><span class="mr-1 rounded bg-slate-100 px-1 py-0.5 font-semibold text-slate-600">{{ i.iocType }}</span><span class="font-mono text-slate-800">{{ i.iocValue }}</span></span>
                  <span class="shrink-0 text-slate-400">{{ i.source }}</span>
                </li>
              </ul>
            </template>
          </section>

          <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="plan-h">
            <h2 id="plan-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.plan') }}</h2>
            <dl class="mt-3 space-y-2.5 text-sm">
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.planId') }}</dt><dd class="truncate font-mono text-xs text-slate-700" :title="plan.id">{{ plan.id }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.status') }}</dt><dd><StatusPill :status="plan.status" /></dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.irDecision') }}</dt><dd class="text-right">
                <StatusPill :status="approval?.status ?? plan.approvalStatus" />
                <span v-if="approval?.decidedAt" class="block text-xs text-slate-500">{{ approval.decidedBy ?? 'IR' }} · {{ formatDateTime(approval.decidedAt) }}</span>
                <span v-if="approval?.comment" class="block text-xs italic text-slate-500">“{{ approval.comment }}”</span>
              </dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.executor') }}</dt><dd class="font-semibold">{{ plan.assignedRole }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.created') }}</dt><dd class="text-xs">{{ exact(plan.createdAt) }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.started') }}</dt><dd class="text-xs">{{ exact(plan.executedAt) }}</dd></div>
              <div class="flex justify-between gap-3"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ t('tk.completedLabel') }}</dt><dd class="text-xs">{{ exact(plan.completedAt) }}</dd></div>
            </dl>
          </section>

          <section v-if="sla && (sla.firstResponse || sla.resolution)" class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="sla-h">
            <h2 id="sla-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.slaTitle', { p: sla.priority ?? '—' }) }}</h2>
            <dl class="mt-3 space-y-2 text-sm">
              <div v-for="[label, c] in ([[t('tk.firstResponse'), sla.firstResponse], [t('tk.resolution'), sla.resolution]] as const)" :key="label" class="flex justify-between gap-3">
                <template v-if="c"><dt class="shrink-0 whitespace-nowrap text-slate-400">{{ label }}</dt><dd class="text-right"><StatusPill :status="c.status" /><span class="block text-xs text-slate-500">{{ t('tk.due', { at: formatDateTime(c.dueAt) }) }}</span></dd></template>
              </div>
            </dl>
          </section>

          <section class="rounded-xl border border-slate-200 bg-white p-5" aria-labelledby="guide-h">
            <h2 id="guide-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('tk.irTeam') }}</h2>
            <p class="mb-3 mt-1 text-xs text-slate-500">{{ t('tk.guideHint') }}</p>
            <ResponseGuidePanel :incident-id="plan.incidentId" :response-id="plan.id" compact />
          </section>

          <button type="button" class="inline-flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" @click="load"><RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('tk.refresh') }}</button>
        </aside>
      </div>

      <!-- Mark eradicated confirmation -->
      <Modal :open="confirmOpen" :title="t('tk.confirmTitle')" size="sm" @close="confirmOpen = false">
        <p class="text-sm text-slate-700">{{ t('tk.confirmBody') }}</p>
        <ul class="mt-3 space-y-1 text-xs text-slate-500">
          <li class="flex items-center gap-1.5"><CircleDashed class="size-3.5" /> {{ t('tk.confirmChecklist', { done: doneCount, total: instructions.length }) }}</li>
          <li class="flex items-center gap-1.5"><CircleDashed class="size-3.5" /> {{ notes.trim() ? t('tk.confirmNotesSaved') : t('tk.confirmNotesNone') }}</li>
          <li class="flex items-center gap-1.5"><CircleDashed class="size-3.5" /> {{ t('tk.confirmNoExec') }}</li>
        </ul>
        <p v-if="instructions.length && doneCount < instructions.length" class="mt-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">{{ t('tk.notAllTicked') }}</p>
        <template #footer>
          <button type="button" class="rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50" @click="confirmOpen = false">{{ t('c.cancel') }}</button>
          <button type="button" class="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-emerald-700" @click="complete">{{ t('c.confirm') }}</button>
        </template>
      </Modal>
    </template>
  </div>
</template>
