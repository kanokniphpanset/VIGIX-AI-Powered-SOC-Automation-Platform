<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ArrowRight, Bot, CheckCircle2, ChevronRight, CircleAlert, FileBarChart2, RotateCw, TriangleAlert } from 'lucide-vue-next'
import StackedBarChart from '@/components/charts/StackedBarChart.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import HelpTip from '@/components/common/HelpTip.vue'
import { SEVERITY_COLORS } from '@/components/charts/chartTheme'
import { alertsApi, dashboardApi, type DashboardSummary, type HealthItem } from '@/api/vigix'
import { workApi, type WorkIncident } from '@/api/work'
import { useSessionStore } from '@/stores/session'
import { useI18n, type MsgKey } from '@/i18n'
import { incidentLabel, toSeverity } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { activityText, attention, caseFlow, caseStep, dueText, glossary, healthSummary, myWork, slaText, thaiAgo, thaiDuration, type Tone, type Who } from '@/utils/dashboard'

/**
 * Dashboard. Top to bottom = most to least urgent for the signed-in role:
 *   1. my work now — what waits for THIS role, one button each
 *   2. needs attention — only what needs action now (SLA, escalations, failures, systems down)
 *   3. case flow — every stage of the SOC → IR flow, clickable
 *   4. SLA · 5. statistics · 6. trend · 7. threats & activity · 8. recent cases
 *   9. technical details (collapsed) — system health, AI queue, workload, raw counts
 * Every number comes from the backend; nothing is computed from guesses. Text follows the TH / EN switch.
 */
const router = useRouter()
const session = useSessionStore()
const { locale, t } = useI18n()
const data = ref<DashboardSummary | null>(null)
const loading = ref(true)
const loadFailed = ref(false)
const days = ref(14)
const recent = ref<WorkIncident[] | null>(null)
const recentFailed = ref(false)
/** Same number as the Alert Inbox "Needs review" tab (null while unknown). */
const needsReview = ref<number | null>(null)

async function load() {
  loading.value = true
  loadFailed.value = false
  try {
    const [summary] = await Promise.all([
      dashboardApi.summary(days.value),
      workApi
        .incidents({ limit: 8, status: 'open,investigating,escalated,resolved' })
        .then((r) => { recent.value = r.items; recentFailed.value = false })
        .catch(() => { recentFailed.value = true }),
      alertsApi
        .inbox({ status: 'needs-review', limit: 1 })
        .then((r) => { needsReview.value = r.total })
        .catch(() => { needsReview.value = null }),
    ])
    data.value = summary
  } catch {
    loadFailed.value = true
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(days, load)
const timer = setInterval(load, 60_000)
onUnmounted(() => clearInterval(timer))

const d = computed(() => data.value)
const L = computed(() => locale.value)
const role = computed(() => session.role)
const roleLabel = computed(() => (['SOC', 'IR_TEAM', 'admin'].includes(role.value ?? '') ? t(`role.${role.value}` as MsgKey) : t('role.unknown')))
const work = computed(() => (d.value ? myWork(role.value, d.value, needsReview.value, L.value) : []))
const waitingTotal = computed(() => work.value.reduce((a, c) => a + (c.value ?? 0), 0))
const flow = computed(() => (d.value ? caseFlow(d.value, needsReview.value, L.value) : []))
const alerts = computed(() => (d.value ? attention(d.value, L.value) : []))
const health = computed(() => (d.value ? healthSummary(d.value.systemHealth) : null))
const sum = (r: Record<string, number> | undefined) => Object.values(r ?? {}).reduce((a, b) => a + b, 0)
const verifTotal = computed(() => sum(d.value?.verifications.byResult))
const containment = computed(() => (verifTotal.value ? Math.round(((d.value?.verifications.byResult.RESOLVED ?? 0) / verifTotal.value) * 100) : null))
const ago = (iso: string) => thaiAgo(iso, Date.now(), L.value)
const dur = (min: number | null | undefined) => thaiDuration(min, L.value)

const TONE: Record<Tone, string> = {
  danger: 'bg-rose-50 text-rose-800 ring-rose-200',
  warning: 'bg-amber-50 text-amber-900 ring-amber-200',
  info: 'bg-sky-50 text-sky-800 ring-sky-200',
  ok: 'bg-emerald-50 text-emerald-800 ring-emerald-200',
}
const LANES: { who: Who; bg: string; text: string; title: MsgKey }[] = [
  { who: 'SOC', bg: 'bg-blue-50/70', text: 'text-blue-800', title: 'dash.lane.SOC' },
  { who: 'IR', bg: 'bg-orange-50/70', text: 'text-orange-800', title: 'dash.lane.IR' },
  { who: 'ผลลัพธ์', bg: 'bg-slate-100', text: 'text-slate-700', title: 'dash.lane.OUT' },
]
const flowLanes = computed(() => LANES.map((lane) => ({ ...lane, steps: flow.value.filter((s) => s.who === lane.who) })))

function go(to: string | null) {
  if (!to) return
  if (to.startsWith('#')) {
    const el = document.getElementById(to.slice(1))
    if (el instanceof HTMLDetailsElement) el.open = true // "technical details" is collapsed by default — open it for the user
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  } else void router.push(to)
}

// SLA: the most urgent first (breached, then at risk)
const SLA_ORDER: Record<string, number> = { BREACHED: 0, AT_RISK: 1, ON_TRACK: 2, NOT_STARTED: 3 }
const slaRows = computed(() => [...(d.value?.sla.watchlist ?? [])].sort((a, b) => (SLA_ORDER[a.slaStatus] ?? 9) - (SLA_ORDER[b.slaStatus] ?? 9) || a.dueAt.localeCompare(b.dueAt)))
const showAllSla = ref(false)
const SLA_TONE: Record<string, string> = { BREACHED: TONE.danger, AT_RISK: TONE.warning, ON_TRACK: TONE.ok, MET: TONE.ok }

// Trend + severity
const dailyLabels = computed(() => (d.value?.alerts.daily ?? []).map((x) => new Date(`${x.date}T00:00:00Z`).toLocaleDateString(L.value === 'th' ? 'th-TH' : 'en-GB', { month: 'short', day: 'numeric' })))
const dailySeries = computed(() => {
  const rows = d.value?.alerts.daily ?? []
  return [
    { label: 'Critical', color: SEVERITY_COLORS.CRITICAL, data: rows.map((r) => r.critical) },
    { label: 'High', color: SEVERITY_COLORS.HIGH, data: rows.map((r) => r.high) },
    { label: 'Medium', color: SEVERITY_COLORS.MEDIUM, data: rows.map((r) => r.medium) },
    { label: t('dash.trend.low'), color: SEVERITY_COLORS.LOW, data: rows.map((r) => r.low) },
  ]
})
const SEVERITY_ROWS = [
  { key: 'CRITICAL', bar: 'bg-rose-600' },
  { key: 'HIGH', bar: 'bg-orange-500' },
  { key: 'MEDIUM', bar: 'bg-amber-400' },
  { key: 'LOW', bar: 'bg-slate-400' },
] as const
const sevMax = computed(() => Math.max(1, ...SEVERITY_ROWS.map((r) => d.value?.severityDistribution[r.key] ?? 0)))
const techMax = computed(() => Math.max(1, ...(d.value?.topTechniques ?? []).map((x) => x.incidents)))
const srcMax = computed(() => Math.max(1, ...(d.value?.topSources ?? []).map((x) => x.incidents)))

// Technical details
const HEALTH_TONE: Record<HealthItem['status'], string> = {
  UP: TONE.ok, DEGRADED: TONE.warning, DOWN: TONE.danger,
  NOT_CONFIGURED: 'bg-slate-100 text-slate-600 ring-slate-200', UNKNOWN: 'bg-slate-50 text-slate-500 ring-slate-200',
}
/** Known status words are translated; anything else from the backend is shown as-is. */
const known = (prefix: string, value: string) => {
  const key = `${prefix}.${value}` as MsgKey
  const text = t(key)
  return text === key ? value : text
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <header class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 class="text-2xl font-bold tracking-tight text-slate-900">{{ t('dash.title') }}</h1>
        <p class="mt-1 text-sm text-slate-600">
          {{ session.session?.email ?? '' }} · {{ roleLabel }}
          <template v-if="d"> · {{ t('dash.updated', { ago: ago(d.generatedAt) }) }} <span class="text-slate-400">{{ t('dash.autoRefresh') }}</span></template>
        </p>
      </div>
      <div class="flex flex-wrap items-center gap-2">
        <button v-if="health" type="button" class="inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-semibold ring-1 ring-inset" :class="TONE[health.tone]" @click="go('#tech')">
          <CheckCircle2 v-if="health.tone === 'ok'" class="size-3.5" /><CircleAlert v-else class="size-3.5" />
          {{ health.tone === 'ok' ? t('dash.healthOk', { ok: health.ok, total: health.total }) : t('dash.healthProblem', { list: health.problems.join(', ') }) }}
        </button>
        <label class="flex items-center gap-2 text-sm text-slate-600">{{ t('dash.period') }}
          <select v-model.number="days" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
            <option v-for="n in [7, 14, 30]" :key="n" :value="n">{{ t('dash.periodDays', { n }) }}</option>
          </select>
        </label>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" @click="load">
          <RotateCw class="size-4" :class="loading ? 'animate-spin' : ''" /> {{ t('common.refresh') }}
        </button>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 hover:bg-slate-50" @click="router.push('/reports')">
          <FileBarChart2 class="size-4" /> {{ t('dash.export') }}
        </button>
      </div>
    </header>

    <p v-if="loadFailed" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ t('dash.loadError') }}</p>
    <div v-if="!d && loading" class="grid gap-4 md:grid-cols-3">
      <div v-for="i in 3" :key="i" class="h-36 animate-pulse rounded-2xl bg-white ring-1 ring-slate-200" />
    </div>

    <template v-if="d">
      <!-- 1. My work now -->
      <section aria-labelledby="work-h" data-tour="my-work">
        <div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="work-h" class="text-lg font-semibold text-slate-900">{{ t('dash.work.title') }}</h2>
          <p class="text-sm text-slate-500">{{ role === 'SOC' ? t('dash.work.soc') : role === 'IR_TEAM' ? t('dash.work.ir') : t('dash.work.admin') }}</p>
        </div>
        <div class="grid gap-4" :class="work.length >= 4 ? 'md:grid-cols-2 xl:grid-cols-4' : 'md:grid-cols-3'">
          <article v-for="c in work" :key="c.key" class="flex flex-col rounded-2xl bg-white p-5 ring-1" :class="c.value ? 'ring-slate-300' : 'ring-slate-200'">
            <h3 class="text-sm font-semibold text-slate-800">{{ c.title }}</h3>
            <p class="mt-2 text-4xl font-bold tabular-nums" :class="c.value ? 'text-slate-900' : 'text-slate-300'">{{ c.value ?? '—' }}</p>
            <p class="mt-2 flex-1 text-xs leading-relaxed text-slate-500">{{ c.hint }}</p>
            <button v-if="c.value" type="button" class="mt-4 inline-flex items-center justify-center gap-1.5 rounded-lg bg-navy-800 px-4 py-2.5 text-sm font-semibold text-white hover:bg-navy-700" @click="go(c.to)">
              {{ c.cta }} <ArrowRight class="size-4" />
            </button>
            <p v-else-if="c.value === 0" class="mt-4 inline-flex items-center gap-1.5 text-sm font-medium text-emerald-700"><CheckCircle2 class="size-4" /> {{ t('common.noPending') }}</p>
            <button v-else type="button" class="mt-4 text-left text-sm font-medium text-slate-600 hover:underline" @click="go(c.to)">{{ t('dash.work.unknownCount') }}</button>
          </article>
        </div>
        <p v-if="role !== 'admin' && waitingTotal === 0 && needsReview !== null" class="mt-3 text-sm text-slate-500">{{ t('dash.work.allClear') }}</p>
      </section>

      <!-- 2. Needs attention -->
      <section aria-labelledby="attn-h" class="rounded-2xl bg-white p-5 ring-1 ring-slate-200">
        <h2 id="attn-h" class="flex items-center gap-2 text-base font-semibold text-slate-900"><TriangleAlert class="size-5 text-amber-600" /> {{ t('dash.attn.title') }}</h2>
        <p v-if="!alerts.length" class="mt-2 inline-flex items-center gap-1.5 text-sm text-emerald-700"><CheckCircle2 class="size-4" /> {{ t('dash.attn.none') }}</p>
        <ul v-else class="mt-3 grid gap-2 md:grid-cols-2">
          <li v-for="a in alerts" :key="a.key">
            <button type="button" class="flex w-full items-center justify-between gap-3 rounded-xl px-4 py-3 text-left text-sm font-medium ring-1 ring-inset" :class="[TONE[a.tone], a.to ? 'hover:brightness-95' : 'cursor-default']" :disabled="!a.to" @click="go(a.to)">
              <span>{{ a.text }}</span><ChevronRight v-if="a.to" class="size-4 shrink-0" />
            </button>
          </li>
        </ul>
      </section>

      <!-- 3. Case flow -->
      <section aria-labelledby="flow-h" class="rounded-2xl bg-white p-5 ring-1 ring-slate-200">
        <div class="mb-4 flex flex-wrap items-baseline justify-between gap-2">
          <h2 id="flow-h" class="text-base font-semibold text-slate-900">{{ t('dash.flow.title') }}</h2>
          <p class="text-xs text-slate-500">{{ t('dash.flow.hint') }}</p>
        </div>
        <!-- Three lanes left → right: SOC work, IR work, outcome. Lanes stack on narrow screens; no sideways scrolling. -->
        <div class="grid gap-3 lg:grid-cols-[3fr_auto_3fr_auto_2fr] lg:items-stretch">
          <template v-for="(lane, li) in flowLanes" :key="lane.who">
            <div class="rounded-xl p-3" :class="lane.bg">
              <p class="mb-2 text-xs font-semibold" :class="lane.text">{{ t(lane.title) }}</p>
              <ol class="grid gap-2" :class="lane.steps.length === 3 ? 'grid-cols-3' : 'grid-cols-2'">
                <li v-for="s in lane.steps" :key="s.key">
                  <button type="button" class="flex h-full w-full flex-col rounded-lg bg-white px-3 py-2.5 text-left ring-1 ring-slate-200 hover:ring-slate-400" @click="go(s.to)">
                    <span class="text-2xl font-bold tabular-nums" :class="s.value ? 'text-slate-900' : 'text-slate-300'">{{ s.value ?? '—' }}</span>
                    <span class="mt-0.5 text-xs font-medium leading-snug text-slate-700">{{ s.label }}</span>
                  </button>
                </li>
              </ol>
            </div>
            <ChevronRight v-if="li < flowLanes.length - 1" class="hidden size-5 self-center text-slate-300 lg:block" aria-hidden="true" />
          </template>
        </div>
      </section>

      <!-- 4. SLA -->
      <section id="sla" aria-labelledby="sla-h" class="scroll-mt-4 rounded-2xl bg-white p-5 ring-1 ring-slate-200">
        <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 id="sla-h" class="flex items-center gap-2 text-base font-semibold text-slate-900">{{ t('dash.sla.title') }} <HelpTip :text="glossary('SLA', L)" /></h2>
          <p class="text-xs text-slate-500">{{ t('dash.sla.counts', { breached: d.sla.breached, atRisk: d.sla.atRisk, onTrack: d.sla.onTrack }) }}</p>
        </div>
        <p v-if="slaRows.length && d.sla.breached + d.sla.atRisk > slaRows.length" class="mb-2 text-xs text-slate-500">{{ t('dash.sla.partial', { n: slaRows.length }) }} <router-link to="/incidents?view=investigation" class="font-medium text-accent-700 hover:underline">{{ t('dash.sla.partialLink') }}</router-link></p>
        <p v-if="!slaRows.length" class="py-6 text-center text-sm text-slate-500">{{ t('dash.sla.none') }}</p>
        <ul v-else class="divide-y divide-slate-100">
          <li v-for="w in showAllSla ? slaRows : slaRows.slice(0, 5)" :key="w.incidentId + w.clock">
            <button type="button" class="flex w-full flex-wrap items-center gap-3 px-1 py-2.5 text-left hover:bg-slate-50" @click="go(`/incidents/${w.incidentId}`)">
              <span class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="SLA_TONE[w.slaStatus] ?? 'bg-slate-100 text-slate-600 ring-slate-200'">{{ slaText(w.slaStatus, L) }}</span>
              <span class="min-w-[12rem] flex-1 truncate text-sm font-medium text-slate-800" :title="w.title">{{ w.title }}</span>
              <span class="text-xs text-slate-500">{{ w.clock === 'firstResponse' ? t('dash.sla.firstResponse') : t('dash.sla.resolution') }}</span>
              <span class="text-xs tabular-nums text-slate-600" :title="formatDateTime(w.dueAt)">{{ dueText(w.dueAt, Date.now(), L) }}</span>
              <ChevronRight class="size-4 text-slate-300" />
            </button>
          </li>
        </ul>
        <button v-if="slaRows.length > 5" type="button" class="mt-2 text-sm font-medium text-accent-700 hover:underline" @click="showAllSla = !showAllSla">{{ showAllSla ? t('common.showLess') : t('dash.sla.more', { n: slaRows.length }) }}</button>
      </section>

      <!-- 5. Statistics -->
      <section aria-labelledby="kpi-h">
        <h2 id="kpi-h" class="mb-3 text-base font-semibold text-slate-900">{{ t('dash.kpi.title') }} <span class="text-sm font-normal text-slate-500">{{ t('dash.kpi.period', { n: days }) }}</span></h2>
        <div class="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-6">
          <button type="button" class="rounded-2xl bg-white p-4 text-left ring-1 ring-slate-200 hover:ring-slate-300" @click="go('/alerts')">
            <p class="text-xs text-slate-500">{{ t('dash.kpi.alerts24h') }}</p>
            <p class="mt-1 text-2xl font-bold tabular-nums text-slate-900">{{ d.alerts.last24h }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.alertsTotal', { n: d.alerts.total }) }}</p>
          </button>
          <button type="button" class="rounded-2xl bg-white p-4 text-left ring-1 ring-slate-200 hover:ring-slate-300" @click="go('/incidents?view=investigation')">
            <p class="text-xs text-slate-500">{{ t('dash.kpi.openIncidents') }}</p>
            <p class="mt-1 text-2xl font-bold tabular-nums text-slate-900">{{ (d.incidents.byStatus.open ?? 0) + (d.incidents.byStatus.investigating ?? 0) + (d.incidents.byStatus.escalated ?? 0) }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.opened7d', { n: d.incidents.openedLast7d }) }}</p>
          </button>
          <div class="rounded-2xl bg-white p-4 ring-1 ring-slate-200">
            <p class="flex items-center gap-1 text-xs text-slate-500">{{ t('dash.kpi.mttr') }} <HelpTip :text="glossary('MTTR', L)" /></p>
            <p class="mt-1 text-xl font-bold leading-8 text-slate-900">{{ dur(d.incidents.mttrMinutes) }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.resolved7d', { n: d.incidents.resolvedLast7d }) }}</p>
          </div>
          <div class="rounded-2xl bg-white p-4 ring-1 ring-slate-200">
            <p class="flex items-center gap-1 text-xs text-slate-500">{{ t('dash.kpi.containment') }} <HelpTip :text="glossary('CONTAINMENT', L)" /></p>
            <p class="mt-1 text-xl font-bold leading-8 text-slate-900">{{ containment == null ? t('common.noData') : `${containment}%` }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.containmentOf', { ok: d.verifications.byResult.RESOLVED ?? 0, total: verifTotal }) }}</p>
          </div>
          <div class="rounded-2xl bg-white p-4 ring-1 ring-slate-200">
            <p class="flex items-center gap-1 text-xs text-slate-500">{{ t('dash.kpi.investigation') }} <HelpTip :text="glossary('INVESTIGATION', L)" /></p>
            <p class="mt-1 text-xl font-bold leading-8 text-slate-900">{{ dur(d.kpi.investigationTimeMinutes) }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.fromCases', { n: d.kpi.investigationSamples }) }}</p>
          </div>
          <div class="rounded-2xl bg-white p-4 ring-1 ring-slate-200">
            <p class="flex items-center gap-1 text-xs text-slate-500">{{ t('dash.kpi.decision') }} <HelpTip :text="glossary('DECISION', L)" /></p>
            <p class="mt-1 text-xl font-bold leading-8 text-slate-900">{{ dur(d.kpi.timeToDecisionMinutes) }}</p>
            <p class="text-[11px] text-slate-500">{{ t('dash.kpi.fromTickets', { n: d.kpi.decisionSamples }) }}</p>
          </div>
        </div>
      </section>

      <!-- 6. Trend -->
      <section class="grid gap-4 lg:grid-cols-3">
        <div class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200 lg:col-span-2">
          <h2 class="text-base font-semibold text-slate-900">{{ t('dash.trend.title') }}</h2>
          <p class="mb-3 text-xs text-slate-500">{{ t('dash.trend.hint') }}</p>
          <StackedBarChart :labels="dailyLabels" :series="dailySeries" :height="240" />
        </div>
        <div class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200">
          <h2 class="flex items-center gap-2 text-base font-semibold text-slate-900">{{ t('dash.sev.title') }} <HelpTip :text="glossary('SEVERITY', L)" /></h2>
          <ul class="mt-4 space-y-3">
            <li v-for="r in SEVERITY_ROWS" :key="r.key">
              <div class="mb-1 flex justify-between text-xs"><SeverityBadge :severity="r.key" size="sm" /><strong class="tabular-nums">{{ d.severityDistribution[r.key] }}</strong></div>
              <div class="h-2 rounded-full bg-slate-100"><div class="h-2 rounded-full" :class="r.bar" :style="{ width: `${(d.severityDistribution[r.key] / sevMax) * 100}%` }" /></div>
            </li>
          </ul>
          <router-link to="/incidents?view=critical" class="mt-4 inline-block text-sm font-medium text-accent-700 hover:underline">{{ t('dash.sev.critical') }}</router-link>
        </div>
      </section>

      <!-- 7. Threats & activity -->
      <section class="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <div class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200">
          <h2 class="mb-4 flex items-center gap-2 text-base font-semibold text-slate-900">{{ t('dash.mitre.title') }} <HelpTip :text="glossary('MITRE', L)" /></h2>
          <p v-if="!d.topTechniques.length" class="text-sm text-slate-500">{{ t('dash.mitre.empty') }}</p>
          <ul class="space-y-3">
            <li v-for="tq in d.topTechniques" :key="tq.techniqueId">
              <div class="mb-1 flex justify-between text-xs"><span><span class="font-mono font-semibold text-slate-800">{{ tq.techniqueId }}</span> <span class="text-slate-500">{{ tq.tactic }}</span></span><span class="font-semibold tabular-nums">{{ t('common.cases', { n: tq.incidents }) }}</span></div>
              <div class="h-2 rounded-full bg-slate-100"><div class="h-2 rounded-full bg-[#2a78d6]" :style="{ width: `${(tq.incidents / techMax) * 100}%` }" /></div>
            </li>
          </ul>
        </div>
        <div class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200">
          <h2 class="mb-4 text-base font-semibold text-slate-900">{{ t('dash.src.title') }}</h2>
          <p v-if="!d.topSources.length" class="text-sm text-slate-500">{{ t('dash.src.empty') }}</p>
          <ul class="space-y-3">
            <li v-for="s in d.topSources" :key="s.value">
              <div class="mb-1 flex justify-between text-xs"><span class="font-mono text-slate-800">{{ s.value }}</span><span class="font-semibold tabular-nums">{{ t('common.cases', { n: s.incidents }) }}</span></div>
              <div class="h-2 rounded-full bg-slate-100"><div class="h-2 rounded-full bg-[#eb6834]" :style="{ width: `${(s.incidents / srcMax) * 100}%` }" /></div>
            </li>
          </ul>
        </div>
        <div class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200 md:col-span-2 lg:col-span-1">
          <h2 class="mb-4 flex items-center gap-1.5 text-base font-semibold text-slate-900"><Bot class="size-4 text-slate-400" /> {{ t('dash.activity.title') }}</h2>
          <p v-if="!d.activity.length" class="text-sm text-slate-500">{{ t('dash.activity.empty') }}</p>
          <ol class="space-y-3">
            <li v-for="a in d.activity.slice(0, 6)" :key="a.occurredAt + a.incidentId + a.eventType" class="text-xs">
              <button type="button" class="w-full text-left" @click="go(`/incidents/${a.incidentId}`)">
                <p class="text-slate-400">{{ ago(a.occurredAt) }}</p>
                <p class="mt-0.5 line-clamp-2 text-slate-700 hover:text-slate-900">{{ activityText(a.eventType, a.description, L) }}</p>
                <p class="truncate text-slate-400">{{ incidentLabel(a.incidentId) }} · {{ a.incidentTitle }}</p>
              </button>
            </li>
          </ol>
        </div>
      </section>

      <!-- 8. Recent cases -->
      <section class="min-w-0 rounded-2xl bg-white p-5 ring-1 ring-slate-200">
        <div class="mb-3 flex items-baseline justify-between"><h2 class="text-base font-semibold text-slate-900">{{ t('dash.recent.title') }}</h2><router-link to="/incidents" class="text-sm font-medium text-accent-700 hover:underline">{{ t('common.viewAll') }}</router-link></div>
        <p v-if="recentFailed" class="text-sm text-rose-700">{{ t('dash.recentError') }}</p>
        <p v-else-if="recent === null" class="text-sm text-slate-500">{{ t('common.loading') }}</p>
        <p v-else-if="!recent.length" class="text-sm text-slate-500">{{ t('dash.recent.empty') }}</p>
        <div v-else class="overflow-x-auto">
          <table class="w-full min-w-[640px] text-sm">
            <thead class="text-left text-xs text-slate-500">
              <tr><th class="pb-2 font-medium">{{ t('dash.recent.case') }}</th><th class="pb-2 font-medium">{{ t('dash.recent.severity') }}</th><th class="pb-2 font-medium">{{ t('dash.recent.step') }}</th><th class="pb-2 font-medium">{{ t('dash.recent.round') }}</th><th class="pb-2 font-medium">{{ t('dash.recent.updated') }}</th></tr>
            </thead>
            <tbody class="divide-y divide-slate-100">
              <tr v-for="i in recent" :key="i.id" class="cursor-pointer hover:bg-slate-50" tabindex="0" @click="go(`/incidents/${i.id}`)" @keydown.enter="go(`/incidents/${i.id}`)">
                <td class="max-w-[360px] py-2 pr-3"><p class="line-clamp-1 font-medium text-slate-800">{{ i.title }}</p><p class="font-mono text-[11px] text-slate-400">{{ incidentLabel(i.id) }}</p></td>
                <td class="py-2 pr-3"><SeverityBadge :severity="toSeverity(i.priority)" size="sm" /></td>
                <td class="py-2 pr-3"><span class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="TONE[caseStep(i, L).tone]">{{ caseStep(i, L).label }}</span></td>
                <td class="py-2 pr-3 text-xs tabular-nums">#{{ i.investigationNumber }}</td>
                <td class="whitespace-nowrap py-2 text-xs text-slate-500" :title="formatDateTime(i.updatedAt)">{{ ago(i.updatedAt) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <!-- 9. Technical details -->
      <details id="tech" class="scroll-mt-4 rounded-2xl bg-white ring-1 ring-slate-200">
        <summary class="cursor-pointer select-none px-5 py-4 text-base font-semibold text-slate-900">{{ t('dash.tech.title') }} <span class="text-sm font-normal text-slate-500">{{ t('dash.tech.hint') }}</span></summary>
        <div class="space-y-5 border-t border-slate-100 px-5 py-5">
          <div>
            <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('dash.tech.health') }}</h3>
            <ul class="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <li v-for="h in d.systemHealth" :key="h.key" class="rounded-xl bg-slate-50 px-3 py-2">
                <p class="flex items-center justify-between gap-2 text-xs"><span class="font-semibold text-slate-700">{{ h.label }}</span><span class="rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 ring-inset" :class="HEALTH_TONE[h.status]">{{ known('health', h.status) }}</span></p>
                <p class="mt-0.5 line-clamp-2 text-[11px] text-slate-500" :title="h.detail ?? ''">{{ [h.detail, h.latencyMs != null ? `${h.latencyMs} ms` : null].filter(Boolean).join(' · ') }}</p>
              </li>
            </ul>
          </div>
          <div class="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div class="rounded-xl bg-slate-50 p-4">
              <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('dash.tech.aiQueue') }}</h3>
              <p v-if="!d.aiJobs.total" class="text-xs text-slate-500">{{ t('dash.tech.aiNone') }}</p>
              <ul v-else class="space-y-1 text-xs">
                <li v-for="(v, k) in d.aiJobs.byStatus" :key="k" class="flex justify-between"><span class="text-slate-600">{{ known('aijob', String(k)) }}</span><strong class="tabular-nums" :class="k === 'FAILED' && v ? 'text-rose-700' : ''">{{ v }}</strong></li>
              </ul>
              <p class="mt-2 text-[11px] text-slate-500">{{ t('dash.tech.aiRate', { rate: d.kpi.automationSuccessRate == null ? '—' : `${d.kpi.automationSuccessRate}%`, n: d.kpi.automationFinished }) }}</p>
            </div>
            <div class="rounded-xl bg-slate-50 p-4">
              <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('dash.tech.tickets') }}</h3>
              <p v-if="!sum(d.responses.byStatus)" class="text-xs text-slate-500">{{ t('dash.tech.ticketsNone') }}</p>
              <ul v-else class="space-y-1 text-xs">
                <li v-for="(v, k) in d.responses.byStatus" :key="k" class="flex justify-between"><span class="text-slate-600">{{ known('ticket', String(k)) }}</span><strong class="tabular-nums">{{ v }}</strong></li>
              </ul>
            </div>
            <div class="rounded-xl bg-slate-50 p-4">
              <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('dash.tech.workload') }}</h3>
              <p v-if="!d.kpi.workload.length" class="text-xs text-slate-500">{{ t('common.noPending') }}</p>
              <ul v-else class="space-y-1 text-xs">
                <li v-for="w in d.kpi.workload" :key="w.assignee" class="flex justify-between gap-2"><span class="truncate text-slate-600">{{ w.assignee }}</span><strong class="tabular-nums">{{ w.open }}</strong></li>
              </ul>
            </div>
            <div class="rounded-xl bg-slate-50 p-4">
              <h3 class="mb-2 text-sm font-semibold text-slate-800">{{ t('dash.tech.results') }}</h3>
              <ul class="space-y-1 text-xs">
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.fp') }}</span><strong class="tabular-nums">{{ d.triage.byDisposition.FALSE_POSITIVE ?? 0 }}</strong></li>
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.info') }}</span><strong class="tabular-nums">{{ d.triage.byDisposition.INFORMATIONAL ?? 0 }}</strong></li>
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.rhResolved') }}</span><strong class="tabular-nums">{{ d.verifications.byResult.RESOLVED ?? 0 }}</strong></li>
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.rhNotResolved') }}</span><strong class="tabular-nums">{{ d.verifications.byResult.NOT_RESOLVED ?? 0 }}</strong></li>
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.spread') }}</span><strong class="tabular-nums">{{ d.verificationDetail.spread }}</strong></li>
                <li class="flex justify-between"><span class="text-slate-600">{{ t('dash.tech.escalations') }}</span><strong class="tabular-nums">{{ d.verificationDetail.escalationEvents }}</strong></li>
              </ul>
            </div>
          </div>
          <p class="text-[11px] text-slate-400">{{ t('dash.tech.source', { at: formatDateTime(d.generatedAt) }) }}</p>
        </div>
      </details>
    </template>
  </div>
</template>
