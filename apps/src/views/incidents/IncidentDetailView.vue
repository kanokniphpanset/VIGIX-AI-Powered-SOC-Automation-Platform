<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Bot, Loader2, RotateCw, Sparkles, Ticket } from 'lucide-vue-next'
import ResponseTicketAction from '@/components/incidents/ResponseTicketAction.vue'
import InvestigationForms from '@/components/incidents/InvestigationForms.vue'
import ManualVerification from '@/components/incidents/ManualVerification.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import IncidentLifecycle from '@/components/incidents/IncidentLifecycle.vue'
import AuditTimeline from '@/components/incidents/AuditTimeline.vue'
import ContextEmailPanel from '@/components/incidents/ContextEmailPanel.vue'
import SeverityValidationPanel from '@/components/incidents/SeverityValidationPanel.vue'
import { workApi, type AiJob, type AuditEntry, type WorkTicket } from '@/api/work'
import type { LifecycleFacts } from '@/utils/workspace'
import { workflowApi } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import WorkflowSummary from '@/components/incidents/WorkflowSummary.vue'
import NextStepCard from '@/components/incidents/NextStepCard.vue'
import RelatedAlertEvidence from '@/components/incidents/RelatedAlertEvidence.vue'
import MarkdownText from '@/components/common/MarkdownText.vue'
import { nextStep } from '@/utils/nextStep'
import { feedback } from '@/utils/feedback'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'
import { timelineText } from '@/utils/systemText'
import {
  incidentsApi,
  items as asItems,
  type AiAnalysis,
  type Evidence,
  type Incident,
  type Investigation,
  type Ioc,
  type MitreMapping,
  type RawAlert,
  type Recommendation,
  type ResponsePlan,
  type TimelineEntry,
  type Verification,
} from '@/api/vigix'
import { incidentLabel, statusLabel, toSeverity } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { aiButtonLabel, hasAiAnalysis, initialAiRunState, runAiAnalysis, type AiRunState } from '@/utils/aiAnalysis'
import { canGenerateRecommendation, generateButtonLabel, initialGenerateState, runGenerate, type GenerateState } from '@/utils/recommendation'

/**
 * Incident 360 — the ONE shared incident every role sees (RBAC decides actions, not which incident exists):
 * overview, investigation, evidence, AI analysis (+ AI jobs), recommendation, Policy & approval chain, response,
 * verification and the full audit trail. Approval / response / re-hunt actions stay on their backend-gated routes.
 */
const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id))

const loading = ref(true)
const error = ref('')
const incident = ref<Incident | null>(null)
const alerts = ref<RawAlert[]>([])
const timeline = ref<TimelineEntry[]>([])
const investigations = ref<Investigation[]>([])
const evidence = ref<Record<string, Evidence[]>>({})
const iocs = ref<Ioc[]>([])
const mitre = ref<MitreMapping[]>([])
const ai = ref<AiAnalysis | null>(null)
const recommendations = ref<Recommendation[]>([])
const responses = ref<ResponsePlan[]>([])
const verifications = ref<Verification[]>([])
// Incident 360 extras (read-only): tickets with their approval chains, the audit trail and the AI analysis jobs.
const tickets = ref<WorkTicket[]>([])
const audit = ref<AuditEntry[]>([])
const auditError = ref('')
const aiJobs = ref<AiJob[]>([])

const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()

type Tab = 'overview' | 'investigation' | 'evidence' | 'ai' | 'recommendation' | 'verification' | 'email' | 'audit'
const ALL_TABS: Tab[] = ['overview', 'investigation', 'evidence', 'ai', 'recommendation', 'verification', 'email', 'audit']
// Re-hunt verification is IR work; the IR decision and response execution live on the Response Tickets.
const HIDDEN_TABS: Record<string, Tab[]> = { SOC: ['verification'] }
const tabs = computed(() => ALL_TABS.filter((k) => !(HIDDEN_TABS[session.role ?? ''] ?? []).includes(k)))
const requestedTab = typeof route.query.tab === 'string' ? (route.query.tab as Tab) : 'overview'
const tab = ref<Tab>(tabs.value.includes(requestedTab) ? requestedTab : 'overview')


const settle = <T,>(p: Promise<T>, fallback: T) => p.catch(() => { error.value = t('inc.loadPartial'); return fallback })

async function load() {
  loading.value = true
  error.value = ''
  try {
    incident.value = await incidentsApi.get(id.value)
  } catch {
    error.value = t('inc.notFound')
    loading.value = false
    return
  }
  const [al, tl, inv, io, mi, an, rec, rsp, ver] = await Promise.all([
    settle(incidentsApi.alerts(id.value), { items: [] }),
    settle(incidentsApi.timeline(id.value), []),
    settle(incidentsApi.investigations(id.value), { items: [] }),
    settle(incidentsApi.iocs(id.value), []),
    settle(incidentsApi.mitre(id.value), []),
    settle(incidentsApi.aiAnalysis(id.value), null),
    settle(incidentsApi.recommendations(id.value), { items: [] }),
    settle(incidentsApi.responses(id.value), { items: [] }),
    settle(incidentsApi.verifications(id.value), { items: [] }),
  ])
  alerts.value = al.items
  timeline.value = [...tl].reverse()
  investigations.value = inv.items
  iocs.value = asItems(io)
  mitre.value = asItems(mi)
  ai.value = an
  recommendations.value = [...rec.items].sort((a, b) => b.recommendationNumber - a.recommendationNumber)
  responses.value = rsp.items
  verifications.value = ver.items
  const ev = await Promise.all(inv.items.map((i) => settle(incidentsApi.evidence(i.id), [] as Evidence[])))
  evidence.value = Object.fromEntries(inv.items.map((i, n) => [i.id, asItems(ev[n])]))
  loading.value = false
  void loadExtras()
}
async function loadExtras() {
  const [tk, au, jobs] = await Promise.all([
    workApi.tickets('all', 200, 0, id.value).catch(() => null),
    workApi.audit(id.value).catch(() => null),
    workApi.aiJobs(id.value).catch(() => null),
  ])
  tickets.value = tk?.items ?? []
  audit.value = au?.items ?? []
  auditError.value = au ? '' : t('inc.auditLoadFailed')
  aiJobs.value = jobs?.items ?? []
}
onMounted(load)
async function reloadWorkflow() {
  const [rec, rsp] = await Promise.all([incidentsApi.recommendations(id.value), incidentsApi.responses(id.value)])
  await load()
  if (error.value) throw new Error('Reload failed')
  recommendations.value = [...rec.items].sort((a, b) => b.recommendationNumber - a.recommendationNumber)
  responses.value = rsp.items
}

const currentRecommendation = computed(() => recommendations.value.find((r) => r.status === 'VALIDATED') ?? recommendations.value[0] ?? null)
/** Tickets that ended without executing can be sent again (mirrors the backend). */
const REPLACEABLE = ['REJECTED', 'FAILED', 'CANCELLED', 'MORE_EVIDENCE_REQUESTED']
const liveTicket = (stepId: string) => responses.value.find((p) => p.recommendationStepId === stepId && !REPLACEABLE.includes(p.status)) ?? responses.value.find((p) => p.recommendationStepId === stepId)
const unsentSteps = computed(() => (currentRecommendation.value?.steps ?? []).filter((s) => s.actionId && !responses.value.some((p) => p.recommendationStepId === s.id && !REPLACEABLE.includes(p.status))).length)

// Run / Re-run AI Analysis: POST .../ai-analysis/run (the existing pipeline, analysis only), then reload everything the
// analysis feeds (AI tab, IOCs/MITRE, investigation, recommendations). The AI never produces a severity.
const aiRun = ref<AiRunState>(initialAiRunState())
async function runAnalysis() {
  if (aiRun.value.status === 'running') return
  const final = await runAiAnalysis(() => incidentsApi.runAiAnalysis(id.value), (s) => (aiRun.value = s))
  if (final.status === 'success') {
    await load() // reload first, so the page already shows what the message says
    ui.notify(feedback('aiDone', locale.value, {}, final.message))
  } else {
    ui.notify(feedback('aiFailed', locale.value, {}, final.message))
  }
}

// Generate (first) / Regenerate Recommendation — both the existing POST /api/recommendations/generate, validated by the
// backend (nothing is saved on failure). A click while one is running is ignored.
const genState = ref<GenerateState>(initialGenerateState())
const regenerating = computed(() => genState.value.status === 'running')
const canGenerate = computed(() => canGenerateRecommendation(session.role))
async function regenerate() {
  const hadRecommendation = !!currentRecommendation.value
  const final = await runGenerate(genState.value, () => workflowApi.regenerate(id.value), (s) => (genState.value = s))
  if (!final) return
  if (final.status === 'success') {
    await load()
    ui.notify(feedback('recDone', locale.value, {}, hadRecommendation ? final.message : null))
  } else {
    ui.notify(feedback('recFailed', locale.value, {}, final.message))
  }
}

/** Where the incident is in the VIGIX Core Flow, from stored records only. */
/** Incident severity (incidents.priority, analyst-validated when corrected) — the Policy classification. */
const severity = computed(() => toSeverity(incident.value?.priority))
// The SOC confirms / sets the severity from the Wazuh evidence (backend: requireRole("SOC")).
const canValidateSeverity = computed(() => ['SOC', 'admin'].includes(session.role ?? ''))
async function severityDone(_message: string, result?: { changed: boolean; severity: string }) {
  const sev = result?.severity?.toUpperCase() ?? ''
  await load()
  ui.notify(feedback(result?.changed ? 'severityChanged' : 'severityConfirmed', locale.value, { sev }))
}

// "ขั้นต่อไป": whose turn, what is next, one button — from the records this page already loaded.
const next = computed(() =>
  incident.value
    ? nextStep({
        role: session.role,
        incidentId: incident.value.id,
        incidentStatus: incident.value.status,
        investigationNumber: incident.value.investigationNumber,
        // A confirmation without a change is recorded only in the audit log; a change also writes a timeline entry.
        severityConfirmed: audit.value.some((a) => a.action === 'SEVERITY_VALIDATED') || timeline.value.some((e) => e.eventType === 'SEVERITY_VALIDATED'),
        hasAiAnalysis: hasAiAnalysis(ai.value),
        recommendation: currentRecommendation.value ? { status: currentRecommendation.value.status } : null,
        unsentSteps: unsentSteps.value,
        ticketStatuses: responses.value.map((r) => r.status),
        awaitingRehunt: responses.value.some((r) => r.status === 'COMPLETED' && !verifications.value.some((v) => v.responseId === r.id)),
      })
    : null,
)
const nextBusy = computed(() => aiRun.value.status === 'running' || regenerating.value)
async function doNext() {
  const a = next.value?.action
  if (!a) return
  if (a.kind === 'route') return void router.push(a.to)
  if (a.kind === 'run-ai') { tab.value = 'ai'; return void runAnalysis() }
  if (a.kind === 'generate') { tab.value = 'recommendation'; return void regenerate() }
  tab.value = a.tab as Tab
  await nextTick()
  document.getElementById(a.anchor ?? 'incident-tabs')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
}
const lifecycleFacts = computed<LifecycleFacts>(() => ({
  hasAlert: alerts.value.length > 0,
  incidentStatus: incident.value?.status ?? '',
  hasInvestigation: investigations.value.length > 0,
  hasAiAnalysis: !!ai.value?.summary,
  hasRecommendation: recommendations.value.some((r) => r.status === 'VALIDATED' || r.status === 'SUPERSEDED'),
  ticketCount: responses.value.length,
  approvalPending: responses.value.some((r) => r.status === 'PENDING_IR_DECISION' || r.status === 'PENDING_APPROVAL'),
  approvalBlocked: responses.value.some((r) => r.status === 'REJECTED' || r.status === 'MORE_EVIDENCE_REQUESTED'),
  anyReadyOrLater: responses.value.some((r) => ['READY_FOR_EXECUTION', 'APPROVED', 'IN_PROGRESS', 'COMPLETED', 'FAILED'].includes(r.status)),
  anyCompleted: responses.value.some((r) => r.status === 'COMPLETED'),
  anyVerification: verifications.value.length > 0,
}))
/** Policy owner from the latest INCIDENT_ASSIGNED audit (never derived in the UI). */
/** Threat Intelligence verdict of an IOC (as recorded by the AI pipeline): label and badge tone. */
const TI_TONE: Record<string, string> = {
  MALICIOUS: 'bg-rose-50 text-rose-700 ring-rose-200',
  SUSPICIOUS: 'bg-amber-50 text-amber-800 ring-amber-200',
  BENIGN: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  UNKNOWN: 'bg-slate-100 text-slate-600 ring-slate-200',
}
const tiLabel = (v: string) => (hasMsg(`inc.ioc.v.${v}`) ? t(`inc.ioc.v.${v}` as MsgKey) : v)
const jobTrigger = (v: string | null) => (v && hasMsg(`inc.trigger.${v}`) ? t(`inc.trigger.${v}` as MsgKey) : v ?? '—')
const assignment = computed(() => {
  const e = audit.value.find((a) => a.action === 'INCIDENT_ASSIGNED')
  const m = e?.metadata ?? null
  return m ? { responsibleRole: String(m.responsibleRole ?? ''), executorRole: m.executorRole ? String(m.executorRole) : null, matched: Array.isArray(m.matchedPolicies) ? (m.matchedPolicies as string[]) : [] } : null
})
</script>

<template>
  <div>
    <button type="button" class="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800" @click="router.back()">
      <ArrowLeft class="size-4" /> {{ t('c.back') }}
    </button>

    <p v-if="loading && !incident" class="text-sm text-slate-500">{{ t('inc.loading') }}</p>
    <div v-else-if="error" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }} <button type="button" class="underline" @click="load">{{ t('c.retry') }}</button></div>

    <template v-else-if="incident">
      <div class="mb-5">
        <p class="font-mono text-xs text-slate-500">{{ incidentLabel(incident.id) }}</p>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900 [overflow-wrap:anywhere]">{{ incident.title }}</h1>
        <p class="mt-2 flex flex-wrap items-center gap-2 text-sm text-slate-600">
          <SeverityBadge :severity="toSeverity(incident.priority)" size="sm" />
          <StatusPill :status="incident.status" />
          <span>{{ t('inc.investigationN', { n: incident.investigationNumber }) }}</span>
          <span v-if="assignment" class="text-xs">· {{ t('inc.responsible') }} <strong>{{ assignment.responsibleRole }}</strong><template v-if="assignment.executorRole"> · {{ t('inc.executor', { role: assignment.executorRole }) }}</template></span>
          <span class="text-slate-400">· {{ t('inc.opened', { at: formatDateTime(incident.openedAt) }) }}</span>
        </p>
        <div v-if="session.canRunAiAnalysis" class="mt-3 flex flex-wrap gap-2">
          <!-- RESOLVED is produced only by Verification (re-hunt NO MATCH); it is never a manual action. -->
          <WorkflowAction v-for="status in ['dismissed', 'escalated'].filter(s => s !== incident!.status && incident!.status !== 'resolved')" :key="`${incident.id}-${status}`" :label="status === 'dismissed' ? t('inc.dismiss') : t('inc.escalate')" :action="() => incidentsApi.updateStatus(id, status)" :reload="reloadWorkflow">
            <p class="text-sm text-amber-800">{{ t('inc.manualStatusNote') }}</p>
          </WorkflowAction>
        </div>
        <IncidentLifecycle :facts="lifecycleFacts" :investigation-number="incident.investigationNumber" :max-rounds="3" />
      </div>
      <NextStepCard v-if="next" :step="next" :role="session.role" :busy="nextBusy" @act="doNext" />

      <div class="grid gap-5 lg:grid-cols-[300px_1fr]">
        <aside class="h-fit min-w-0 rounded-xl border border-slate-200 bg-white p-4">
          <h2 class="mb-3 text-sm font-semibold text-slate-800">{{ t('inc.alertsN', { n: alerts.length }) }}</h2>
          <ul class="space-y-2">
            <li v-for="a in alerts" :key="a.id">
              <button type="button" class="w-full rounded-lg border border-slate-100 px-2.5 py-2 text-left hover:bg-slate-50" @click="router.push(`/alerts/${a.id}`)">
                <span class="flex items-center justify-between gap-2">
                  <span class="truncate font-mono text-[11px] text-slate-500">{{ a.externalAlertId }}</span>
                  <StatusPill status="in_incident" />
                </span>
                <span class="mt-0.5 block truncate text-xs text-slate-700">{{ (a.rawPayload.rule as { description?: string } | undefined)?.description ?? '—' }}</span>
              </button>
            </li>
          </ul>
        </aside>

        <div class="min-w-0">
          <div id="incident-tabs" class="mb-4 flex scroll-mt-4 gap-1 overflow-x-auto border-b border-slate-200" role="tablist">
            <button
              v-for="key in tabs"
              :key="key"
              type="button"
              role="tab"
              :aria-selected="tab === key"
              class="whitespace-nowrap border-b-2 px-3 py-2 text-sm"
              :class="tab === key ? 'border-accent-500 font-semibold text-slate-900' : 'border-transparent text-slate-500 hover:text-slate-800'"
              @click="tab = key"
            >
              {{ t(`inc.tab.${key}`) }}
            </button>
          </div>

          <section class="rounded-xl border border-slate-200 bg-white p-5 text-sm">
            <!-- Overview -->
            <div v-if="tab === 'overview'" class="space-y-5">
              <div class="grid gap-3 sm:grid-cols-4">
                <div class="rounded-lg bg-slate-50 p-3"><p class="text-xs text-slate-400">{{ t('inc.severity') }}</p><p class="mt-1"><SeverityBadge :severity="severity" size="sm" /></p></div>
                <div class="rounded-lg bg-slate-50 p-3"><p class="text-xs text-slate-400">{{ t('inc.iocs') }}</p><p class="text-lg font-bold">{{ iocs.length }}</p></div>
                <div class="rounded-lg bg-slate-50 p-3"><p class="text-xs text-slate-400">{{ t('inc.responsePlans') }}</p><p class="text-lg font-bold">{{ responses.length }}</p></div>
                <div class="rounded-lg bg-slate-50 p-3"><p class="text-xs text-slate-400">{{ t('inc.verifications') }}</p><p class="text-lg font-bold">{{ verifications.length }}</p></div>
              </div>
              <WorkflowSummary :incident-status="incident.status" :investigation-number="incident.investigationNumber" :tickets="tickets" :verifications="verifications" />
              <SeverityValidationPanel id="severity" class="scroll-mt-4" :key="`sev-${incident.priority}`" :incident-id="incident.id" :incident-status="incident.status" :can-validate="canValidateSeverity" @done="severityDone" />
              <p class="text-xs text-slate-500">{{ t('inc.ownerByPolicy') }} <strong>{{ assignment?.responsibleRole || t('inc.notAssigned') }}</strong><template v-if="assignment?.executorRole"> · {{ t('inc.executor', { role: assignment.executorRole }) }}</template></p>
              <div v-if="session.canTriage" class="rounded-lg border border-slate-200 p-3">
                <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.notification') }}</h3>
                  <p class="mt-1 text-xs text-slate-500"><template v-if="severity === 'LOW'">{{ t('inc.notifyLow') }}</template>{{ t('inc.notifyHint') }}</p>
                  <div class="mt-2 flex flex-wrap gap-2">
                    <WorkflowAction :label="t('inc.sendNotify')" :success-label="t('inc.sendNotifyDone')" :action="(note) => incidentsApi.notificationDecision(id, 'SEND', note || null)" :reload="reloadWorkflow" />
                    <WorkflowAction :label="t('inc.skipNotify')" :success-label="t('inc.skipNotifyDone')" :action="(note) => incidentsApi.notificationDecision(id, 'SKIP', note || null)" :reload="reloadWorkflow" />
                  </div>
              </div>
              <div>
                <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.latestActivity') }}</h3>
                <ol class="space-y-1.5">
                  <li v-for="entry in timeline.slice(0, 5)" :key="entry.id" class="flex gap-3"><span class="w-36 shrink-0 text-xs text-slate-400">{{ formatDateTime(entry.occurredAt) }}</span><span>{{ timelineText(entry.eventType, entry.description) }}</span></li>
                </ol>
              </div>
            </div>

            <!-- Investigation -->
            <div v-else-if="tab === 'investigation'">
              <p v-if="!investigations.length" class="text-slate-500">{{ t('inc.noInvestigation') }}</p>
              <ul v-else class="space-y-2">
                <li v-for="i in investigations" :key="i.id" class="flex flex-wrap items-center gap-3 rounded-lg border border-slate-100 px-3 py-2">
                  <span class="font-semibold">{{ t('inc.investigationN', { n: i.investigationNumber }) }}</span>
                  <StatusPill :status="i.status" />
                  <span class="text-slate-500">{{ t('inc.evidenceCount', { e: i.evidenceCount, i: i.iocCount }) }}</span>
                  <span v-if="i.isCurrent" class="rounded bg-sky-50 px-1.5 py-0.5 text-[11px] font-semibold text-sky-700">{{ t('inc.current') }}</span>
                  <span class="ml-auto text-xs text-slate-400">{{ formatDateTime(i.startedAt) }}</span>
                </li>
              </ul>
            </div>

            <!-- Evidence / IOC / MITRE -->
            <div v-else-if="tab === 'evidence'" class="space-y-5">
              <template v-if="session.canRunAiAnalysis"><InvestigationForms v-for="i in investigations.filter(i => i.isCurrent && i.status === 'ACTIVE')" :key="i.id" :investigation-id="i.id" :reload="reloadWorkflow" /></template>
              <RelatedAlertEvidence :incident-id="incident.id" :investigation-id="investigations.find(i => i.isCurrent && i.status === 'ACTIVE')?.id ?? null" :can-add="session.canTriage" :reload="load" />
              <div v-for="i in investigations" :key="i.id">
                <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.evidenceOf', { n: i.investigationNumber }) }}</h3>
                <ul class="space-y-1.5">
                  <li v-for="e in evidence[i.id] ?? []" :key="e.id" class="rounded-lg border border-slate-100 px-3 py-2">
                    <span class="mr-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold text-slate-600">{{ e.type }}</span>
                    <span class="text-slate-800">{{ e.title }}</span>
                    <span class="ml-2 text-xs text-slate-400">{{ e.source }} · {{ e.origin }} · {{ formatDateTime(e.timestamp) }}</span>
                  </li>
                  <li v-if="!(evidence[i.id] ?? []).length" class="text-slate-500">{{ t('inc.noEvidence') }}</li>
                </ul>
              </div>
              <div>
                <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.iocs') }}</h3>
                <div class="overflow-x-auto">
                <table class="w-full min-w-[640px]">
                  <thead class="text-left text-[11px] text-slate-400">
                    <tr><th class="pb-1 pr-3 font-medium">{{ t('inc.ioc.type') }}</th><th class="pb-1 pr-3 font-medium">{{ t('inc.ioc.value') }}</th><th class="pb-1 pr-3 font-medium">{{ t('inc.ioc.source') }}</th><th class="pb-1 font-medium">{{ t('inc.ioc.ti') }}</th></tr>
                  </thead>
                  <tbody class="divide-y divide-slate-100">
                    <tr v-for="i in iocs" :key="i.id ?? i.iocType + i.iocValue">
                      <td class="py-1.5 pr-3 align-top text-xs text-slate-500">{{ i.iocType }}</td>
                      <td class="py-1.5 pr-3 align-top font-mono break-all">{{ i.iocValue }}</td>
                      <td class="py-1.5 align-top text-xs text-slate-400">
                        {{ i.source }}
                        <!-- Related-alert provenance: which other Wazuh alert, why, and when the SOC linked it -->
                        <span v-if="i.sourceAlertId" class="mt-0.5 block text-slate-600">
                          {{ t('inc.fromAlert') }} <router-link :to="`/alerts/${i.sourceAlertId}`" class="font-mono text-accent-700 hover:underline">{{ i.sourceExternalAlertId ?? i.sourceAlertId }}</router-link>
                          · “{{ i.addedReason }}”<template v-if="i.createdAt"> · {{ formatDateTime(i.createdAt) }}</template>
                        </span>
                      </td>
                      <!-- Threat Intelligence verdict recorded by the AI pipeline (display only) -->
                      <td class="py-1.5 align-top text-xs">
                        <template v-if="i.threatIntel?.verdict">
                          <span class="inline-flex rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="TI_TONE[i.threatIntel.verdict] ?? TI_TONE.UNKNOWN">{{ tiLabel(i.threatIntel.verdict) }}</span>
                          <span v-if="i.threatIntel.confidence != null" class="ml-1.5 text-slate-500">{{ t('inc.ioc.confidence', { n: Math.round(i.threatIntel.confidence * 100) }) }}</span>
                          <span v-if="i.threatIntel.providers.length" class="mt-0.5 block text-slate-500">{{ t('inc.ioc.checkedBy') }} {{ i.threatIntel.providers.map((p) => `${p.provider.toUpperCase()} · ${p.status}`).join(', ') }}</span>
                          <span v-for="(e, n) in i.threatIntel.evidence" :key="n" class="mt-0.5 block text-slate-600">
                            {{ e.summary }}
                            <a v-if="e.reference" :href="e.reference" target="_blank" rel="noopener noreferrer" class="ml-1 text-accent-700 hover:underline">{{ t('inc.ioc.reference', { provider: e.provider.toUpperCase() }) }} ↗</a>
                          </span>
                        </template>
                        <span v-else class="text-slate-400">{{ t('inc.ioc.tiNone') }}</span>
                      </td>
                    </tr>
                  </tbody>
                </table>
                </div>
              </div>
              <div>
                <h3 class="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">MITRE ATT&CK</h3>
                <span v-for="m in mitre" :key="m.techniqueId" class="mr-2 rounded bg-indigo-50 px-2 py-1 font-mono text-indigo-700">{{ m.techniqueId }} · {{ m.tactic }}</span>
                <span v-if="!mitre.length" class="text-slate-500">{{ t('inc.noMitre') }}</span>
              </div>
            </div>

            <!-- AI Analysis -->
            <div v-else-if="tab === 'ai'">
              <p class="mb-3 flex items-center gap-1.5 text-xs text-slate-500">
                <Bot class="size-4" /> {{ t('inc.aiDisclaimer') }}
                <button
                  v-if="session.canRunAiAnalysis"
                  type="button"
                  class="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:cursor-not-allowed disabled:opacity-60"
                  :disabled="aiRun.status === 'running'"
                  :aria-busy="aiRun.status === 'running'"
                  @click="runAnalysis"
                >
                  <Loader2 v-if="aiRun.status === 'running'" class="size-3.5 animate-spin" /><Sparkles v-else class="size-3.5" /> {{ aiButtonLabel(aiRun, ai) }}
                </button>
                <button type="button" class="inline-flex items-center gap-1 rounded border border-slate-200 px-2 py-1 text-xs text-slate-600 hover:bg-slate-50" :class="session.canRunAiAnalysis ? '' : 'ml-auto'" :title="t('inc.aiReloadTitle')" @click="load"><RotateCw class="size-3" /> {{ t('c.reload') }}</button>
              </p>
              <p v-if="aiRun.status === 'running'" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.aiRunning') }}</p>
              <p v-else-if="aiRun.status === 'success'" class="mb-3 rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-800" role="status">{{ aiRun.message }}</p>
              <p v-else-if="aiRun.status === 'error'" class="mb-3 rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ aiRun.message }}</p>
              <p v-if="!hasAiAnalysis(ai) && aiRun.status !== 'running'" class="mb-3 text-xs text-slate-500">{{ t('inc.aiNoneYet') }}</p>
              <div v-if="ai?.grounding?.status === 'UNGROUNDED'" role="alert" class="mb-3 rounded border border-rose-300 bg-rose-50 p-3 text-sm text-rose-800"><strong>{{ t('inc.ungroundedTitle') }}</strong><p>{{ t('inc.ungroundedBody') }}</p><p v-for="issue in ai.grounding.ungrounded" :key="issue.kind + issue.value">{{ issue.kind }}: {{ issue.value }}</p></div>
              <template v-if="ai?.summary">
                <p class="mb-2 text-[11px] text-slate-500">{{ t('inc.generatedBy') }}<template v-if="ai.model"> · <span class="font-mono">{{ ai.model }}</span></template><template v-if="ai.generatedAt"> · {{ formatDateTime(ai.generatedAt) }}</template></p>
                <p v-if="locale === 'th'" class="mb-2 inline-block rounded bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600">{{ t('ai.originalLang') }}</p>
                <MarkdownText :text="ai.summary" class="mb-3" />
              </template>
              <p v-if="ai?.latestRun?.source === 'FAILED'" class="mb-3 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900" role="status">{{ t('inc.aiLatestFailed', { at: formatDateTime(ai.latestRun.generatedAt) }) }}{{ ai?.summary ? t('inc.aiLatestFailedKept') : '' }}{{ t('inc.aiLatestFailedTail') }}</p>
              <p v-else-if="ai?.latestRun?.source === 'HEURISTIC_FALLBACK'" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.aiHeuristic', { at: formatDateTime(ai.latestRun.generatedAt) }) }}</p>
              <p v-else-if="ai?.latestRun?.source === 'UNVERIFIED_LEGACY'" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.aiLegacy', { at: formatDateTime(ai.latestRun.generatedAt) }) }}</p>
              <ul v-if="ai?.keyFindings.length" class="list-disc space-y-1 pl-5 text-slate-700"><li v-for="f in ai.keyFindings" :key="f">{{ f }}</li></ul>
              <p v-if="!ai?.summary" class="text-slate-500">{{ t('inc.aiNone') }}</p>
              <h3 class="mb-2 mt-5 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.aiJobs') }}</h3>
              <p v-if="!aiJobs.length" class="text-xs text-slate-500">{{ t('inc.aiJobsNone') }}</p>
              <div v-else class="overflow-x-auto">
                <table class="w-full min-w-[520px] text-xs">
                  <thead class="text-left text-slate-400"><tr><th class="pb-1">{{ t('inc.job.status') }}</th><th class="pb-1">{{ t('inc.job.trigger') }}</th><th class="pb-1">{{ t('inc.job.attempt') }}</th><th class="pb-1">{{ t('inc.job.queued') }}</th><th class="pb-1">{{ t('inc.job.completed') }}</th><th class="pb-1">{{ t('inc.job.error') }}</th></tr></thead>
                  <tbody class="divide-y divide-slate-100">
                    <tr v-for="j in aiJobs" :key="j.id">
                      <td class="py-1 font-semibold" :class="j.status === 'FAILED' ? 'text-rose-700' : j.status === 'PARTIAL_SUCCESS' ? 'text-amber-700' : j.status === 'SUCCESS' ? 'text-emerald-700' : 'text-violet-700'">{{ statusLabel(j.status) }}</td>
                      <td class="py-1">{{ jobTrigger(j.trigger) }}</td>
                      <td class="py-1">{{ j.attempt }}</td>
                      <td class="py-1">{{ formatDateTime(j.queuedAt ?? j.startedAt) }}</td>
                      <td class="py-1">{{ j.completedAt ? formatDateTime(j.completedAt) : '—' }}</td>
                      <td class="py-1 text-rose-700">{{ j.errorCode ?? '' }}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Recommendation -->
            <div v-else-if="tab === 'recommendation'">
              <div v-if="!currentRecommendation">
                <p class="text-slate-500">{{ t('inc.noRec') }}</p>
                <button
                  v-if="canGenerate"
                  type="button"
                  class="mt-3 inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:cursor-not-allowed disabled:opacity-50"
                  :disabled="regenerating || incident.status === 'resolved' || incident.status === 'escalated'"
                  :aria-busy="regenerating"
                  @click="regenerate"
                >
                  <Loader2 v-if="regenerating" class="size-3.5 animate-spin" /><Sparkles v-else class="size-3.5" /> {{ generateButtonLabel(genState, false) }}
                </button>
                <p v-else class="mt-2 text-xs text-slate-400">{{ t('inc.recRoleOnly') }}</p>
                <p v-if="regenerating" class="mt-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.recRunning') }}</p>
                <p v-else-if="genState.status === 'error'" class="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ genState.message }} {{ t('inc.tryAgain') }}</p>
              </div>
              <template v-else>
                <p class="mb-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  {{ t('inc.recHeader', { n: currentRecommendation.recommendationNumber, i: currentRecommendation.investigationNumber }) }}
                  <StatusPill :status="currentRecommendation.status" /> · {{ currentRecommendation.createdBy }}
                </p>
                <p v-if="locale === 'th'" class="mb-2 inline-block rounded bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600">{{ t('ai.originalLang') }}</p>
                <p class="mb-4 text-slate-800">{{ currentRecommendation.summary }}</p>
                <div class="mb-4 flex flex-wrap gap-2">
                  <button v-if="canGenerate" type="button" class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50 disabled:opacity-50" :disabled="regenerating || incident.status === 'resolved' || incident.status === 'escalated'" :aria-busy="regenerating" @click="regenerate">
                    <Loader2 v-if="regenerating" class="size-3.5 animate-spin" /><RotateCw v-else class="size-3.5" /> {{ generateButtonLabel(genState, true) }}
                  </button>
                  <button v-if="responses.length" type="button" class="inline-flex items-center gap-1 rounded-lg border border-slate-200 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50" @click="router.push(`/tickets?incident=${incident.id}`)">
                    <Ticket class="size-3.5" /> {{ t('inc.openTickets') }}
                  </button>
                </div>
                <div v-if="session.canSendToIr" class="mb-4 rounded-lg border border-slate-200 p-3">
                  <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.sendToIr') }}</h3>
                  <p class="mt-1 text-xs text-slate-500">{{ t('inc.sendToIrHint') }}</p>
                  <WorkflowAction
                    v-if="unsentSteps > 0 && currentRecommendation.status === 'VALIDATED'"
                    class="mt-2"
                    :label="unsentSteps > 1 ? t('inc.sendToIrN', { n: unsentSteps }) : t('inc.sendToIr1')"
                    :success-label="t('inc.sentToIrDone')"
                    :feedback="feedback('sentToIr', locale)"
                    :action="() => workflowApi.sendToIr(currentRecommendation!.id)"
                    :reload="reloadWorkflow"
                  >
                    <p class="text-sm text-slate-600">{{ t('inc.sendConfirm') }}</p>
                  </WorkflowAction>
                  <p v-else-if="currentRecommendation.status !== 'VALIDATED'" class="mt-2 text-xs text-amber-800">{{ t('inc.recInvalid') }}</p>
                  <p v-else class="mt-2 text-xs text-emerald-700">{{ t('inc.allSent') }}</p>
                </div>
                <article v-for="s in currentRecommendation.steps" :key="s.id" class="mb-4 rounded-lg border border-slate-200 p-4">
                  <h3 class="font-semibold text-slate-900">{{ s.stepOrder }}. {{ s.title }}</h3>
                  <p v-if="s.objective" class="mt-1 text-slate-600">{{ s.objective }}</p>
                  <p class="mt-1 text-xs text-slate-500">{{ t('inc.reason', { text: s.reason }) }}</p>
                  <ResponseTicketAction :key="s.id" :step="s" :ticket="liveTicket(s.id)" />
                  <ol class="mt-3 space-y-1.5">
                    <li v-for="ins in s.instructions" :key="ins.order" class="flex gap-2">
                      <span class="flex size-5 shrink-0 items-center justify-center rounded-full bg-slate-100 text-[11px] font-semibold">{{ ins.order }}</span>
                      <span>{{ ins.instruction }} <span v-if="ins.expectedResult" class="text-xs text-slate-400">→ {{ ins.expectedResult }}</span></span>
                    </li>
                  </ol>
                  <p v-if="s.verificationCriteria" class="mt-3 rounded bg-emerald-50 px-2 py-1 text-xs text-emerald-800">{{ t('inc.verify', { text: s.verificationCriteria }) }}</p>
                  <p v-if="s.evidence.length" class="mt-2 text-[11px] text-slate-400">{{ t('inc.evidence', { text: s.evidence.join(' · ') }) }}</p>
                </article>
                <p v-if="recommendations.length > 1" class="text-xs text-slate-400">{{ t('inc.superseded', { n: recommendations.length - 1 }) }}</p>
              </template>
            </div>

            <!-- Verification -->
            <div v-else-if="tab === 'verification'">
              <p class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600">{{ t('inc.verifyNote') }}</p>
              <ManualVerification v-if="session.canExecuteResponse" :incident-id="id" :responses="responses.filter(r => r.status === 'COMPLETED' && !verifications.some(v => v.responseId === r.id))" :reload="reloadWorkflow" />
              <p v-if="!verifications.length" class="text-slate-500">{{ t('inc.noVerification') }}</p>
              <ul v-else class="space-y-2">
                <li v-for="v in verifications" :key="v.id" class="flex flex-wrap items-center gap-2 rounded-lg border border-slate-100 px-3 py-2">
                  <StatusPill :status="v.result" />
                  <span class="text-slate-600">{{ t('inc.matchingEvents', { n: v.matchingEvents ?? 0 }) }}</span>
                  <span v-if="v.spreadDetected" class="rounded bg-rose-50 px-1.5 py-0.5 text-[11px] font-semibold text-rose-700">{{ t('inc.spread') }}</span>
                  <span v-if="v.iocRecurrence" class="rounded bg-amber-50 px-1.5 py-0.5 text-[11px] font-semibold text-amber-700">{{ t('inc.iocRecurrence') }}</span>
                  <span class="text-xs text-slate-400">{{ t('inc.contained', { v: v.threatContained ? t('c.yes') : t('c.no') }) }}</span>
                </li>
              </ul>
            </div>

            <!-- Email (content follows the sender's role) -->
            <div v-else-if="tab === 'email'">
              <ContextEmailPanel :incident-id="incident.id" />
            </div>

            <!-- Audit (audit log of the incident + its alerts / recommendations / tickets / approvals / verifications, and the timeline) -->
            <div v-else-if="tab === 'audit'">
              <AuditTimeline :entries="audit" :error="auditError" :loading="loading" />
            </div>
          </section>
        </div>
      </div>
    </template>
  </div>
</template>
