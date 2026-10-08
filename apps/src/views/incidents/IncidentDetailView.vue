<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ArrowLeft, Loader2, RotateCw, Sparkles, Ticket } from 'lucide-vue-next'
import ResponseTicketAction from '@/components/incidents/ResponseTicketAction.vue'
import ManualVerification from '@/components/incidents/ManualVerification.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import AuditTimeline from '@/components/incidents/AuditTimeline.vue'
import ContextEmailPanel from '@/components/incidents/ContextEmailPanel.vue'
import IncidentGroupPolicy from '@/components/incidents/IncidentGroupPolicy.vue'
import { workApi, type AuditEntry, type WorkTicket } from '@/api/work'
import { workflowApi } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import WorkflowSummary from '@/components/incidents/WorkflowSummary.vue'
import OpenIncidents from '@/components/incidents/OpenIncidents.vue'
import SimilarCases from '@/components/incidents/SimilarCases.vue'
import IncidentAlertFactsTable from '@/components/incidents/IncidentAlertFactsTable.vue'
import IncidentRecommendation from '@/components/incidents/IncidentRecommendation.vue'
import PreviewEvidenceBasis from '@/components/incidents/PreviewEvidenceBasis.vue'
import { nextStep } from '@/utils/nextStep'
import { INCIDENT_TABS, resolveTab, tabForStep, type IncidentTab } from '@/utils/incidentTabs'
import { feedback } from '@/utils/feedback'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'
import { incidentSla } from '@/utils/triage'
import {
  incidentsApi,
  slaApi,
  type IncidentSla,
  items as asItems,
  type AiAnalysis,
  type Evidence,
  type Incident,
  type Investigation,
  type Ioc,
  type MitreMapping,
  type RawAlert,
  type Recommendation,
  type RecommendationPreview,
  type ResponsePlan,
  type TimelineEntry,
  type Verification,
} from '@/api/vigix'
import { incidentLabel, statusLabel, toSeverity } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { hasAiAnalysis, initialAiRunState, runAiAnalysis, type AiRunState } from '@/utils/aiAnalysis'
import { canGenerateRecommendation, initialGenerateState, runGenerate, type GenerateState } from '@/utils/recommendation'

/**
 * Incident 360 — the ONE shared incident every role sees (RBAC decides actions, not which incident exists).
 * Progress is shown once, in the "ขั้นต่อไป" card (8 steps). Four tabs: overview · evidence (investigations, evidence,
 * IOC, MITRE) · AI & recommendation (analysis, AI jobs, recommendation, send to IR) · history (re-hunt results,
 * email, audit). The page opens on the tab that holds the current step's work. Approval / response / re-hunt actions
 * stay on their backend-gated routes.
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
/** Preview loaded by IncidentRecommendation; its evidence basis is shown at the top of the AI tab. */
const recPreview = ref<RecommendationPreview | null>(null)
const responses = ref<ResponsePlan[]>([])
const verifications = ref<Verification[]>([])
// Incident 360 extras (read-only): tickets with their approval chains, the audit trail and the AI analysis jobs.
const tickets = ref<WorkTicket[]>([])
const audit = ref<AuditEntry[]>([])
const auditError = ref('')
// Incident SLA (Policy) as targets under the title: "start responding within 4 h", "resolve within 3 days" + deadlines.
const sla = ref<IncidentSla | null>(null)
const slaTargets = computed(() => incidentSla(sla.value, new Date()))

const session = useSessionStore()
const ui = useUiStore()
const { locale, t } = useI18n()

// ?tab= (current or former tab names) wins; otherwise the tab of the current step is chosen once the data is in.
const requested = resolveTab(route.query.tab)
const tab = ref<IncidentTab>(requested?.tab ?? 'overview')
let tabSettled = !!requested
function selectTab(key: IncidentTab) {
  tab.value = key
  tabSettled = true
}
// Re-hunt verification is IR work (the SOC sees the round summary in History, not the re-hunt controls).
const showVerification = computed(() => session.role !== 'SOC')
/** Small counters on the tabs (they replace the overview's number tiles). */
const tabCount = computed<Partial<Record<IncidentTab, number>>>(() => ({ evidence: iocs.value.length, history: verifications.value.length }))


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
  seen.value = fingerprint(incident.value, tl.length, rsp.items, ver.items)
  stale.value = false
  loading.value = false
  await loadExtras()
  if (!tabSettled && next.value) selectTab(tabForStep(next.value.key))
  if (requested?.anchor && !anchorDone) {
    anchorDone = true
    await nextTick()
    document.getElementById(requested.anchor)?.scrollIntoView({ block: 'start' })
  }
}
let anchorDone = false
async function loadExtras() {
  const [tk, au, s] = await Promise.all([
    workApi.tickets('all', 200, 0, id.value).catch(() => null),
    workApi.audit(id.value).catch(() => null),
    slaApi.incident(id.value).catch(() => null),
  ])
  sla.value = s
  tickets.value = tk?.items ?? []
  audit.value = au?.items ?? []
  auditError.value = au ? '' : t('inc.auditLoadFailed')
}
onMounted(load)

// Someone else (IR / SOC) may move the case while this page is open: check every 30 s and offer the new data with a
// banner instead of swapping it under the reader (who may be filling in a form).
const seen = ref('')
const stale = ref(false)
function fingerprint(i: Incident | null, timelineLength: number, plans: ResponsePlan[], rounds: Verification[]) {
  return JSON.stringify([i?.status, i?.priority, i?.investigationNumber, timelineLength, plans.map((p) => `${p.id}:${p.status}`).sort(), rounds.map((v) => v.id).sort()])
}
async function checkForUpdates() {
  if (loading.value || stale.value || document.hidden || !incident.value) return
  try {
    const [inc, tl, rsp, ver] = await Promise.all([incidentsApi.get(id.value), incidentsApi.timeline(id.value), incidentsApi.responses(id.value), incidentsApi.verifications(id.value)])
    if (!loading.value && fingerprint(inc, tl.length, rsp.items, ver.items) !== seen.value) stale.value = true
  } catch { /* offline for a moment — try again on the next tick */ }
}
const poll = setInterval(checkForUpdates, 30_000)
onUnmounted(() => clearInterval(poll))
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
/** SOC Validation REJECT -> Close Incident: only before anything of this recommendation reached IR, on an open incident. */
const canRejectRecommendation = computed(() => {
  const rec = currentRecommendation.value
  if (!rec || !incident.value || ['SUPERSEDED', 'REJECTED'].includes(rec.status) || ['resolved', 'dismissed'].includes(incident.value.status)) return false
  return !responses.value.some((p) => p.recommendationId === rec.id && !REPLACEABLE.includes(p.status))
})
const unsentSteps = computed(() => (currentRecommendation.value?.steps ?? []).filter((s) => s.actionId && !responses.value.some((p) => p.recommendationStepId === s.id && !REPLACEABLE.includes(p.status))).length)

// Run / Re-run AI Analysis: POST .../ai-analysis/run (the existing pipeline, analysis only), then reload everything the
// analysis feeds (AI tab, IOCs/MITRE, investigation, recommendations). The AI never produces a severity.
const aiRun = ref<AiRunState>(initialAiRunState())

// Generate (first) / Regenerate Recommendation — both the existing POST /api/recommendations/generate, validated by the
// backend (nothing is saved on failure). A click while one is running is ignored.
const genState = ref<GenerateState>(initialGenerateState())
const regenerating = computed(() => genState.value.status === 'running')
const canGenerate = computed(() => canGenerateRecommendation(session.role))
/** Re-run AI Analysis + generate Recommendation as one action. Same gates as the two backend routes (SOC / IR_TEAM; admin passes). */
const canAnalyzeAndRecommend = computed(() => session.canRunAiAnalysis && canGenerate.value)
const analyzeBusy = computed(() => aiRun.value.status === 'running' || genState.value.status === 'running')
async function analyzeAndRecommend() {
  if (analyzeBusy.value) return
  genState.value = initialGenerateState()
  // The page does not report which agents of the pipeline returned errors (PARTIAL_SUCCESS shows as a plain success).
  const plain = (s: AiRunState): AiRunState => (s.message ? { ...s, message: s.message.replace(t('ai.done.partial'), '') } : s)
  const analysis = plain(await runAiAnalysis(() => incidentsApi.runAiAnalysis(id.value), (s) => (aiRun.value = plain(s))))
  ui.notify(feedback(analysis.status === 'success' ? 'aiDone' : 'aiFailed', locale.value, {}, analysis.message))
  // The recommendation is generated even when this AI run failed (the backend builds its context from the evidence and the
  // analysis it classifies as trusted); the notification above says the run failed.
  await regenerate()
  if (genState.value.status !== 'success') await load() // regenerate() reloads only on success
}
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
// Bumped after the severity / type is confirmed: both setup panels reload (the group may have changed).
const setupVersion = ref(0)
/** Group panel saved something: a severity move goes through severityDone (Policy re-assignment, reload); else reload + toast. */
async function groupChanged(message: string, result?: { changed: boolean; severity: string }) {
  if (result) return severityDone(message, result)
  setupVersion.value++
  await load()
  ui.notify({ type: 'success', title: message, message: '', link: null })
}
async function severityDone(_message: string, result?: { changed: boolean; severity: string }) {
  const sev = result?.severity?.toUpperCase() ?? ''
  setupVersion.value++
  await load()
  ui.notify(feedback(result?.changed ? 'severityChanged' : 'severityConfirmed', locale.value, { sev }))
}

// Next workflow step (from the records this page already loaded); only used to open the matching tab first.
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
/** Policy owner from the latest INCIDENT_ASSIGNED audit (never derived in the UI). */
/** Threat Intelligence verdict of an IOC (as recorded by the AI pipeline): label and badge tone. */
const TI_TONE: Record<string, string> = {
  MALICIOUS: 'bg-rose-50 text-rose-700 ring-rose-200',
  SUSPICIOUS: 'bg-amber-50 text-amber-800 ring-amber-200',
  BENIGN: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  UNKNOWN: 'bg-slate-100 text-slate-600 ring-slate-200',
}
const tiLabel = (v: string) => (hasMsg(`inc.ioc.v.${v}`) ? t(`inc.ioc.v.${v}` as MsgKey) : v)
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
        <section v-if="slaTargets.length" class="mt-3 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm" :aria-label="t('tri.tgt.title')">
          <p class="text-xs font-semibold uppercase tracking-wide text-slate-400">
            {{ t('tri.tgt.title') }}<span v-if="sla?.priority" class="ml-1 font-normal normal-case tracking-normal">· {{ t('tri.tgt.hint', { p: sla.priority }) }}</span>
          </p>
          <ul class="mt-1 space-y-1">
            <li v-for="s in slaTargets" :key="s.text" class="flex flex-wrap items-baseline gap-x-3">
              <span class="font-medium text-slate-800">{{ s.text }}</span>
              <span v-if="s.doneAt" class="text-xs text-emerald-700">{{ t('tri.tgt.done', { at: formatDateTime(s.doneAt) }) }}</span>
              <span v-else class="text-xs" :class="s.late ? 'font-semibold text-rose-700' : 'text-slate-500'">{{ t('tri.tgt.due', { at: formatDateTime(s.dueAt) }) }}</span>
            </li>
          </ul>
        </section>
      </div>
      <div v-if="stale" class="mb-5 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm text-amber-900" role="status">
        <span>{{ t('inc.updatedBanner') }}</span>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-white px-3 py-1.5 text-xs font-semibold text-amber-900 ring-1 ring-amber-300 hover:bg-amber-100" @click="load"><RotateCw class="size-3.5" /> {{ t('inc.updatedShow') }}</button>
      </div>

      <!-- single column: the former sidebar content now lives in the tabs (alerts -> Evidence, knowledge cases -> Overview) -->
      <div>

        <div class="min-w-0">
          <div id="incident-tabs" class="mb-4 flex scroll-mt-4 gap-1 overflow-x-auto border-b border-slate-200" role="tablist">
            <button
              v-for="key in INCIDENT_TABS"
              :key="key"
              type="button"
              role="tab"
              :aria-selected="tab === key"
              class="whitespace-nowrap border-b-2 px-3 py-2 text-sm"
              :class="tab === key ? 'border-accent-500 font-semibold text-slate-900' : 'border-transparent text-slate-500 hover:text-slate-800'"
              @click="selectTab(key)"
            >
              {{ t(`inc.tab.${key}`) }}<span v-if="tabCount[key]" class="ml-1.5 rounded-full bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold text-slate-600">{{ tabCount[key] }}</span>
            </button>
          </div>

          <section class="rounded-xl border border-slate-200 bg-white p-5 text-sm">
            <!-- Overview -->
            <div v-if="tab === 'overview'" class="space-y-5">
              <SimilarCases :incident-id="incident.id" class="rounded-xl border border-slate-200 bg-white p-4" />
              <!-- the incident's group (type + severity) and the group's Response Policy; replaces the severity / guidance panels -->
              <IncidentGroupPolicy id="severity" class="scroll-mt-4" :key="`grp-${incident.priority}-${setupVersion}`" :incident-id="incident.id" :incident-status="incident.status" :can-edit="canValidateSeverity" @changed="groupChanged" />
              <!-- every incident not closed yet (replaces the latest-activity list; the audit trail stays in History) -->
              <OpenIncidents :current-id="incident.id" :can-group="canValidateSeverity" @grouped="groupChanged" />
            </div>

            <!-- Evidence: what happened (alert facts), each investigation round with its evidence, then IOC / MITRE -->
            <div v-else-if="tab === 'evidence'" class="space-y-5">
              <!-- the incident's alerts, before the investigation rounds -->
              <section>
                <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('inc.alertsN', { n: alerts.length }) }}</h3>
                <ul class="space-y-2">
                  <li v-for="a in alerts" :key="a.id">
                    <button type="button" class="flex w-full flex-wrap items-center gap-x-3 gap-y-1 rounded-lg border border-slate-200 px-3 py-2 text-left hover:bg-slate-50" @click="router.push(`/alerts/${a.id}`)">
                      <span class="min-w-0 flex-1">
                        <span class="block text-sm text-slate-800">{{ (a.rawPayload.rule as { description?: string } | undefined)?.description ?? '—' }}</span>
                        <span class="block break-all font-mono text-[11px] text-slate-500">{{ a.externalAlertId }}</span>
                      </span>
                      <StatusPill status="in_incident" />
                    </button>
                  </li>
                </ul>
              </section>
              <h3 id="sec-investigation" class="-mb-2 scroll-mt-4 text-sm font-semibold text-slate-800">{{ t('inc.sec.investigation') }}</h3>
              <p v-if="!investigations.length" class="text-slate-500">{{ t('inc.noInvestigation') }}</p>
              <div v-for="i in investigations" :key="i.id" class="rounded-lg border border-slate-200 p-3" :class="i.isCurrent ? 'border-sky-200' : ''">
                <div class="mb-2 flex flex-wrap items-center gap-3">
                  <h3 class="font-semibold text-slate-900">{{ t('inc.investigationN', { n: i.investigationNumber }) }}</h3>
                  <StatusPill :status="i.status" />
                  <span class="text-slate-500">{{ t('inc.evidenceCount', { e: i.evidenceCount, i: i.iocCount }) }}</span>
                  <span v-if="i.isCurrent" class="rounded bg-sky-50 px-1.5 py-0.5 text-[11px] font-semibold text-sky-700">{{ t('inc.current') }}</span>
                  <span class="ml-auto text-xs text-slate-400">{{ formatDateTime(i.startedAt) }}</span>
                </div>
                <ul class="space-y-1.5">
                  <li v-for="e in evidence[i.id] ?? []" :key="e.id" class="rounded-lg border border-slate-100 px-3 py-2">
                    <span class="mr-2 rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-semibold text-slate-600">{{ e.type }}</span>
                    <span class="text-slate-800">{{ e.title }}</span>
                    <span class="ml-2 text-xs text-slate-400">{{ e.source }} · {{ e.origin }} · {{ formatDateTime(e.timestamp) }}</span>
                  </li>
                  <li v-if="!(evidence[i.id] ?? []).length" class="text-slate-500">{{ t('inc.noEvidence') }}</li>
                </ul>
              </div>
              <IncidentAlertFactsTable :incident-id="incident.id" :incident-label="incidentLabel(incident.id)" :incident-title="incident.title" />
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
                      <td class="py-1.5 pr-3 align-top text-xs text-slate-400">
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

            <!-- AI analysis + recommendation -->
            <div v-else-if="tab === 'ai'">
              <PreviewEvidenceBasis v-if="recPreview?.evidenceBasis" :preview="recPreview" class="mb-6" />
              <!-- Recommendation only (the AI analysis text and job table were removed as duplicate); the one action re-runs the AI
                   analysis and then generates the Recommendation (SOC and IR team). -->
              <div class="mt-6 border-t border-slate-100 pt-5">
              <div class="mb-3 flex flex-wrap items-center gap-2">
                <h3 id="sec-recommendation" class="scroll-mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.sec.recommendation') }}</h3>
                <button
                  v-if="canAnalyzeAndRecommend"
                  type="button"
                  class="ml-auto inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:cursor-not-allowed disabled:opacity-60"
                  :disabled="analyzeBusy || ['resolved', 'escalated', 'dismissed'].includes(incident.status)"
                  :aria-busy="analyzeBusy"
                  @click="analyzeAndRecommend"
                >
                  <Loader2 v-if="analyzeBusy" class="size-3.5 animate-spin" /><Sparkles v-else class="size-3.5" />
                  {{ aiRun.status === 'running' ? t('inc.aiRec.runningAi') : genState.status === 'running' ? t('inc.aiRec.runningRec') : t('inc.aiRec.btn') }}
                </button>
              </div>
              <p v-if="aiRun.status === 'running'" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.aiRunning') }}</p>
              <p v-else-if="aiRun.status === 'success'" class="mb-3 rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-800" role="status">{{ aiRun.message }}</p>
              <p v-else-if="aiRun.status === 'error'" class="mb-3 rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ aiRun.message }}</p>
              <p v-if="genState.status === 'running'" class="mb-3 rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600" role="status">{{ t('inc.recRunning') }}</p>
              <p v-else-if="genState.status === 'success'" class="mb-3 rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-800" role="status">{{ genState.message }}</p>
              <p v-else-if="genState.status === 'error'" class="mb-3 rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ genState.message }}</p>
              <IncidentRecommendation @preview="recPreview = $event" :incident-id="incident.id" :revision="JSON.stringify([incident.investigationNumber, alerts.map(a => [a.id, a.rawPayload]), ai?.generatedAt])" />

              </div>
              <!-- notification email, at the bottom of the Recommendation tab -->
              <div class="mt-6 border-t border-slate-100 pt-5">
              <h3 id="sec-email" class="mb-2 scroll-mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.sec.email') }}</h3>
              <ContextEmailPanel :incident-id="incident.id" />
              </div>

            </div>

            <!-- History: re-hunt rounds, email, audit -->
            <div v-else-if="tab === 'history'" class="space-y-6">
              <section v-if="currentRecommendation" class="mt-6 rounded-xl border border-slate-200 bg-slate-50 p-4">
                <h3 class="text-sm font-medium text-slate-600">ประวัติคำแนะนำที่บันทึกไว้และ Ticket เดิม</h3>
                <p class="my-3 text-xs text-slate-500">ข้อมูลย้อนหลังสำหรับติดตามงานเดิม ไม่ใช่คำแนะนำจากหลักฐานล่าสุด</p>
              <template v-if="currentRecommendation">
                <p class="mb-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                  {{ t('inc.recHeader', { n: currentRecommendation.recommendationNumber, i: currentRecommendation.investigationNumber }) }}
                  <StatusPill :status="currentRecommendation.status" /> · {{ currentRecommendation.createdBy }}
                </p>
                <p v-if="locale === 'th'" class="mb-2 inline-block rounded bg-slate-100 px-2 py-0.5 text-[11px] text-slate-600">{{ t('ai.originalLang') }}</p>
                <p class="mb-4 text-slate-800">{{ currentRecommendation.summary }}</p>
                <div class="mb-4 flex flex-wrap gap-2">

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
                  <div v-if="canRejectRecommendation" class="mt-3 border-t border-slate-100 pt-3">
                    <p class="mb-2 text-xs text-slate-500">{{ t('inc.rejectRecHint') }}</p>
                    <WorkflowAction
                      :label="t('inc.rejectRec')"
                      reason-required
                      :success-label="t('inc.rejectRecDone')"
                      :action="(reason) => workflowApi.rejectRecommendation(currentRecommendation!.id, reason)"
                      :reload="reloadWorkflow"
                    />
                  </div>
                </div>
                <div v-if="currentRecommendation.recommendationText" class="mb-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm">
                  <p class="text-xs font-semibold text-slate-600">{{ t('inc.recText') }}</p>
                  <pre class="mt-2 whitespace-pre-wrap font-sans text-sm text-slate-800">{{ currentRecommendation.recommendationText }}</pre>
                </div>
                <article v-for="s in currentRecommendation.steps" :key="s.id" class="mb-4 rounded-lg border border-slate-200 p-4">
                  <h3 class="font-semibold text-slate-900">
                    {{ s.stepOrder }}. {{ s.title }}
                    <span v-if="s.stepType" class="ml-1 rounded px-1.5 py-0.5 align-middle text-[10px] font-semibold" :class="s.stepType === 'ACTION' ? 'bg-accent-50 text-accent-700' : s.stepType === 'MANUAL' ? 'bg-amber-50 text-amber-800' : 'bg-slate-100 text-slate-600'">{{ t(`inc.stepType.${s.stepType}`) }}</span>
                  </h3>
                  <p v-if="s.objective" class="mt-1 text-slate-600">{{ s.objective }}</p>
                  <p v-if="s.precondition" class="mt-1 rounded bg-amber-50 px-2 py-1 text-xs text-amber-900">{{ t('inc.condition', { text: s.precondition }) }}</p>
                  <p class="mt-1 text-xs text-slate-500">{{ t('inc.reason', { text: s.reason }) }}</p>
                  <ResponseTicketAction :key="s.id" :step="s" :ticket="liveTicket(s.id)" />
                  <ol class="mt-3 space-y-1.5">
                    <li v-for="ins in s.instructions" :key="ins.order" class="flex gap-2">
                      <span class="flex size-5 shrink-0 items-center justify-center rounded-full bg-slate-100 text-[11px] font-semibold">{{ ins.order }}</span>
                      <span>{{ ins.instruction }} <span v-if="ins.expectedResult" class="text-xs text-slate-400">→ {{ ins.expectedResult }}</span>
                        <span v-if="ins.method" class="block text-xs text-slate-600">{{ t(ins.methodKind === 'detail' ? 'inc.detail' : 'inc.method', { text: ins.method }) }}</span>
                        <span v-if="ins.preconditions?.length" class="block text-xs text-slate-600">{{ t('inc.before', { text: ins.preconditions.join(' / ') }) }}</span>
                        <span v-if="ins.impact" class="block text-xs italic text-amber-700">{{ t('inc.impact', { text: ins.impact }) }}</span>
                        <span v-if="ins.verify" class="block text-xs italic text-emerald-700">{{ t('inc.verify', { text: ins.verify }) }}</span>
                        <span v-if="ins.rollback" class="block text-xs text-slate-600">{{ t('inc.rollback', { text: ins.rollback }) }}</span>
                        <span v-if="ins.note" class="block text-xs text-rose-700">{{ t('inc.note', { text: ins.note }) }}</span>
                      </span>
                    </li>
                  </ol>
                  <p v-if="s.verificationCriteria" class="mt-3 rounded bg-emerald-50 px-2 py-1 text-xs text-emerald-800">{{ t('inc.verify', { text: s.verificationCriteria }) }}</p>
                  <p v-if="s.evidence.length" class="mt-2 text-[11px] text-slate-400">{{ t('inc.evidence', { text: s.evidence.join(' · ') }) }}</p>
                </article>
                <p v-if="recommendations.length > 1" class="text-xs text-slate-400">{{ t('inc.superseded', { n: recommendations.length - 1 }) }}</p>
              </template>
              </section>
              <div>
              <h3 id="sec-verification" class="mb-2 scroll-mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.sec.verification') }}</h3>
                <WorkflowSummary :incident-status="incident.status" :investigation-number="incident.investigationNumber" :tickets="tickets" :verifications="verifications" />
                <div v-if="showVerification" class="mt-4">
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
              </div>
              <div>
              <h3 id="sec-audit" class="mb-2 scroll-mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('inc.sec.audit') }}</h3>
              <AuditTimeline :entries="audit" :error="auditError" :loading="loading" />
              </div>
            </div>
          </section>
        </div>
      </div>
    </template>
  </div>
</template>
