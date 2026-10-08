<script setup lang="ts">
// What a recommendation preview was computed from: the incident's real alerts (event / ingest time, provenance, observed
// values, fields not mapped yet), the targets found and whether analyst assertions exist. Display only.
import { computed } from 'vue'
import type { RecommendationPreview } from '@/api/vigix'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'

const props = defineProps<{ preview: RecommendationPreview }>()
const { t } = useI18n()
const basis = computed(() => props.preview.evidenceBasis ?? null)
const gap = computed(() => basis.value?.gap ?? null)
</script>

<template>
    <div v-if="basis" class="rounded-lg border border-slate-200 bg-white p-3">
      <h4 class="mb-1 text-sm font-semibold text-slate-900">{{ t('inc.pv.basis') }}</h4>
      <p v-if="gap?.family" class="text-xs text-slate-600">{{ t('inc.pv.family', { label: gap.family.label, src: t(`inc.pv.familySrc.${gap.family.source}`) }) }}</p>
      <article v-for="a in basis.alerts" :key="a.ref" class="mt-2 rounded-lg border border-slate-200 bg-white p-3 text-sm">
        <p class="text-xs font-semibold text-slate-700">{{ t('inc.pv.alertRef', { ref: a.ref, id: a.externalAlertId ?? '—' }) }}</p>
        <p class="mt-0.5 flex flex-wrap gap-1.5 text-[11px]">
          <span v-if="a.provenanceClass" class="rounded px-1.5 py-0.5 font-semibold" :class="a.provenanceClass === 'REAL_TELEMETRY' ? 'bg-emerald-50 text-emerald-800' : 'bg-violet-100 text-violet-800'">{{ t(`inc.pv.prov.${a.provenanceClass}`) }}</span>
          <span class="rounded bg-slate-100 px-1.5 py-0.5 text-slate-700">{{ t(`inc.pv.map.${a.mapping}`) }}</span>
        </p>
        <p class="mt-1 text-[11px] text-slate-500">
          <template v-if="a.eventTime">{{ t('inc.pv.eventTime', { at: formatDateTime(a.eventTime) }) }}</template>
          <template v-if="a.ingestedAt"> · {{ t('inc.pv.ingestTime', { at: formatDateTime(a.ingestedAt) }) }}</template>
        </p>
        <dl v-if="a.observed.length" class="mt-2 grid grid-cols-1 gap-x-3 gap-y-0.5 text-xs sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
          <template v-for="o in a.observed" :key="o.label + o.value"><dt class="text-slate-500">{{ o.label }}</dt><dd class="break-all font-mono text-slate-800">{{ o.value }}</dd></template>
        </dl>
        <div v-if="a.unmapped.length" class="mt-2 text-xs">
          <p class="text-slate-500">{{ t('inc.pv.unmapped', { n: a.unmapped.length }) }}</p>
          <dl class="mt-1 grid grid-cols-1 gap-x-3 gap-y-0.5 sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)]">
            <template v-for="u in a.unmapped" :key="u.path"><dt class="text-slate-500">{{ u.label || u.path }}</dt><dd class="break-all font-mono text-slate-800">{{ u.value }}</dd></template>
          </dl>
        </div>
        <p v-if="a.error" class="mt-1 text-xs text-rose-700">{{ a.error }}</p>
      </article>
      <div v-if="gap" class="mt-3">
        <p class="text-xs font-semibold text-slate-600">{{ t('inc.pv.sec.targets') }}</p>
        <p v-if="!gap.targets.length" class="text-xs text-slate-600">{{ t('inc.pv.noTargets') }}</p>
        <ul v-else class="space-y-1 text-xs">
          <li v-for="g in gap.targets" :key="g.label + g.value">
            <span class="mr-1 rounded px-1.5 py-0.5 font-semibold" :class="g.ok ? 'bg-emerald-50 text-emerald-800' : 'bg-amber-50 text-amber-800'">{{ g.ok ? t('inc.pv.targetOk') : t('inc.pv.targetIncomplete') }}</span>
            {{ g.label }} <span class="font-mono">{{ g.value }}</span>
          </li>
        </ul>
      </div>
      <p class="mt-2 text-xs text-slate-600">{{ basis.analystAssertions ? t('inc.pv.assertions', { n: basis.analystAssertions }) : t('inc.pv.noAssertion') }}</p>
    </div>
</template>
