<script setup lang="ts">
// Body of a Recommendation Preview (incident or fixture): only sections with data are rendered; no send / execute control.
import { computed } from 'vue'
import { ShieldAlert } from 'lucide-vue-next'
import type { RecommendationPreview } from '@/api/vigix'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'
import PreviewEvidenceBasis from './PreviewEvidenceBasis.vue'

const props = defineProps<{ preview: RecommendationPreview; incidentPresentation?: boolean; hideBasis?: boolean }>()
const { t } = useI18n()

/** Continuous 1, 2, 3 … numbering across measures. */
const numbered = computed(() => {
  let n = 0
  return props.preview.measures.map((m) => ({ ...m, instructions: m.instructions.map((i) => ({ ...i, n: ++n })) }))
})
const basis = computed(() => props.preview.evidenceBasis ?? null)
const gap = computed(() => basis.value?.gap ?? null)
const targetGaps = computed(() => (gap.value?.targets ?? []).filter((g) => !g.ok && g.problems.length))
const CAT_CLASS: Record<string, string> = {
  effective: 'bg-emerald-50 text-emerald-800',
  pending: 'bg-slate-100 text-slate-700',
  unverified: 'bg-amber-50 text-amber-800',
  failed: 'bg-rose-50 text-rose-700',
}
</script>

<template>
  <div>
    <!-- Simulated data: never presented as the result of a real incident -->
    <div v-if="preview.source === 'FIXTURE_PREVIEW' && preview.fixture" class="mt-3 rounded-lg border-2 border-violet-400 bg-violet-50 px-3 py-2 text-sm text-violet-900" role="note">
      <p class="font-semibold">{{ t('inc.pv.fixtureBanner') }}</p>
      <p class="mt-0.5">{{ preview.fixture.title }}</p>
      <p class="text-xs">{{ preview.fixture.note }}</p>
    </div>
    <p class="mt-3 flex items-center gap-2 rounded-lg border border-amber-400 bg-amber-100 px-3 py-2 text-sm font-semibold text-amber-900" role="note">
      <ShieldAlert class="size-4 shrink-0" /> {{ preview.label }}
    </p>
    <p class="mt-2 text-[11px] text-slate-500">
      <template v-if="preview.source && !incidentPresentation">{{ t(`inc.pv.src.${preview.source}`) }}</template>
      <template v-if="preview.investigationNumber && preview.source !== 'FIXTURE_PREVIEW'"> · {{ t('inc.pv.at', { n: preview.investigationNumber, at: formatDateTime(preview.generatedAt) }) }}</template>
      <template v-if="preview.basis?.rehunt"> · {{ t('inc.pv.rehunt', { n: preview.basis.rehunt.round, result: preview.basis.rehunt.result }) }}</template>
    </p>
    <p v-if="preview.basis && !preview.basis.organizationContextComplete" class="mt-2 rounded bg-slate-100 px-3 py-2 text-xs text-slate-700">{{ t('inc.pv.orgIncomplete') }}</p>

    <!-- Stored shadow result: text only -->
    <div v-if="preview.source === 'STORED_SHADOW'" class="mt-4">
      <h4 class="mb-1 text-xs font-semibold text-slate-600">{{ incidentPresentation ? 'คำแนะนำจากหลักฐานของเคส' : t('inc.pv.storedText') }}</h4>
      <pre class="whitespace-pre-wrap rounded-lg border border-slate-200 bg-white p-3 font-sans text-sm text-slate-800">{{ preview.text }}</pre>
    </div>

    <template v-else>
      <p v-if="preview.summary" class="mt-3 text-sm text-slate-800">{{ preview.summary }}</p>
      <p v-for="e in preview.explain" :key="e" class="mt-2 rounded bg-white px-3 py-2 text-sm text-slate-700">{{ e }}</p>

      <!-- 4. status of earlier measures (re-hunt rounds) -->
      <div v-if="preview.priorStatus.length" class="mt-4">
        <h4 class="mb-2 text-sm font-semibold text-slate-900">{{ t('inc.pv.sec.prior') }}</h4>
        <ul class="space-y-1.5">
          <li v-for="s in preview.priorStatus" :key="s.label + s.category" class="rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm">
            <span class="mr-2 rounded px-1.5 py-0.5 text-[11px] font-semibold" :class="CAT_CLASS[s.category]">{{ t(`inc.pv.cat.${s.category}`) }}</span>
            <span class="font-medium text-slate-900">{{ s.label }}</span>
            <span class="block text-xs text-slate-600">{{ s.text }}</span>
          </li>
        </ul>
      </div>

      <!-- 1. containment steps -->
      <div v-if="numbered.length" class="mt-4">
        <h4 class="text-sm font-semibold text-slate-900">{{ t('inc.pv.sec.steps') }}</h4>
        <p class="mb-2 text-xs text-slate-500">{{ t('inc.pv.stepsNote') }}</p>
        <article v-for="m in numbered" :key="m.label + (m.target ?? '')" class="mb-3 rounded-lg border border-slate-200 bg-white p-3">
          <p class="text-xs font-semibold text-slate-600">{{ t('inc.pv.measure', { label: m.label }) }}</p>
          <p v-if="m.target" class="text-xs text-slate-600">{{ t('inc.pv.target', { target: m.target }) }}</p>
          <ol class="mt-2 space-y-3">
            <li v-for="i in m.instructions" :key="i.n" class="flex gap-2">
              <span class="flex size-6 shrink-0 items-center justify-center rounded-full bg-slate-100 text-xs font-semibold">{{ i.n }}</span>
              <div class="min-w-0 text-sm text-slate-800">
                <p class="font-semibold text-slate-900">{{ i.title }}</p>
                <p v-if="i.owner" class="text-xs text-amber-800">{{ t('inc.pv.owner', { role: i.owner }) }}</p>
                <p v-if="i.method" class="mt-0.5">{{ t(i.methodKind === 'detail' ? 'inc.detail' : 'inc.method', { text: i.method }) }}</p>
                <div v-if="i.preconditions.length" class="mt-0.5 text-xs text-slate-700">
                  {{ t('inc.before', { text: '' }) }}
                  <ul class="list-disc pl-5"><li v-for="p in i.preconditions" :key="p">{{ p }}</li></ul>
                </div>
                <p v-if="i.impact" class="mt-0.5 text-xs italic text-amber-700">{{ t('inc.impact', { text: i.impact }) }}</p>
                <p v-if="i.verify" class="mt-0.5 text-xs italic text-emerald-700">{{ t('inc.verify', { text: i.verify }) }}</p>
                <p v-if="i.rollback" class="mt-0.5 text-xs text-slate-600">{{ t('inc.rollback', { text: i.rollback }) }}</p>
                <p v-if="i.note" class="mt-0.5 text-xs text-rose-700">{{ t('inc.note', { text: i.note }) }}</p>
              </div>
            </li>
          </ol>
        </article>
        <div v-if="preview.overallVerify.length" class="rounded-lg bg-emerald-50 px-3 py-2 text-xs text-emerald-900">
          <p class="font-semibold">{{ t('inc.pv.overallVerify') }}</p>
          <ul class="list-disc pl-5"><li v-for="v in preview.overallVerify" :key="v">{{ v }}</li></ul>
        </div>
      </div>

      <!-- 2. approvals -->
      <div v-if="preview.approvals.length" class="mt-4">
        <h4 class="text-sm font-semibold text-slate-900">{{ t('inc.pv.sec.approvals') }}</h4>
        <p class="mb-2 text-xs text-slate-500">{{ t('inc.pv.approvalsNote') }}</p>
        <ul class="list-disc space-y-1 pl-5 text-sm text-slate-800"><li v-for="a in preview.approvals" :key="a.text">{{ a.text }}</li></ul>
      </div>

      <!-- 3. information still needed: composer items + specific target gaps + per-pattern evidence (only the parts that have data) -->
      <div v-if="preview.missingInfo.length || targetGaps.length || gap?.needed.length || basis?.familyNote" class="mt-4">
        <h4 class="mb-1 text-sm font-semibold text-slate-900">{{ t('inc.pv.sec.missing') }}</h4>
        <ul v-if="preview.missingInfo.length" class="list-disc space-y-1 pl-5 text-sm text-slate-800"><li v-for="m in preview.missingInfo" :key="m">{{ m }}</li></ul>
        <div v-if="targetGaps.length" class="mt-2">
          <p class="text-xs font-semibold text-slate-600">{{ t('inc.pv.needTargets') }}</p>
          <ul class="list-disc space-y-1 pl-5 text-sm text-slate-800">
            <li v-for="g in targetGaps" :key="g.label + g.value">{{ g.label }} <span class="font-mono text-xs">{{ g.value }}</span>: {{ g.problems.join(' · ') }}</li>
          </ul>
        </div>
        <p v-if="basis?.familyNote" class="mt-2 text-sm text-slate-800">{{ basis.familyNote }}</p>
        <div v-if="gap?.needed.length" class="mt-2">
          <p class="text-xs font-semibold text-slate-600">{{ t('inc.pv.needType') }}</p>
          <ul class="space-y-2 text-sm text-slate-800">
            <li v-for="n in gap.needed" :key="n.subtype" class="rounded border border-slate-200 bg-white px-3 py-2">
              <p class="font-medium text-slate-900">{{ n.subtype }}</p>
              <ul class="list-disc pl-5"><li v-for="i in n.items" :key="i">{{ i }}</li></ul>
              <p v-if="n.notEnough.length" class="mt-1 text-xs text-slate-500">{{ t('inc.pv.notEnough') }}: {{ n.notEnough.join(' · ') }}</p>
            </li>
          </ul>
        </div>
      </div>

      <!-- what the preview was computed from; the incident page shows it elsewhere (hideBasis) -->
      <PreviewEvidenceBasis v-if="!hideBasis" :preview="preview" class="mt-4" />

      <p v-if="preview.toolNote" class="mt-4 rounded bg-slate-100 px-3 py-2 text-xs text-slate-700"><span class="font-semibold">{{ t('inc.pv.toolNote') }}:</span> {{ preview.toolNote }}</p>
    </template>
  </div>
</template>
