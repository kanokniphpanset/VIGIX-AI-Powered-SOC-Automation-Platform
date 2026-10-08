<script setup lang="ts">
import { ref, watch } from 'vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { incidentsApi, type IncidentAlertFacts } from '@/api/vigix'
import { toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

/**
 * Investigation tab: the incident's alerts, one card each — VIGIX alert ID, severity (Wazuh rule level), source /
 * destination IP, incident, incident type and the facts that matter for that type (e.g. the command line of a
 * PowerShell case). The type comes from the playbook the MITRE techniques match (backend, deterministic).
 */
const props = defineProps<{ incidentId: string; incidentLabel: string; incidentTitle: string }>()
const { t } = useI18n()
const data = ref<IncidentAlertFacts | null>(null)
const error = ref('')

async function load() {
  error.value = ''
  try {
    data.value = await incidentsApi.alertFacts(props.incidentId)
  } catch (e) {
    error.value = workflowError(e)
  }
}
watch(() => props.incidentId, load, { immediate: true })

const typeLabel = (type: string | null, short = false) => (!type ? t(short ? 'iaf.type.noneShort' : 'iaf.type.none') : hasMsg(`iaf.type.${type}`) ? t(`iaf.type.${type}` as MsgKey) : type)
const factLabel = (key: string) => (hasMsg(`iaf.f.${key}`) ? t(`iaf.f.${key}` as MsgKey) : key)
const dash = (v: string | number | null) => (v === null || v === '' ? '—' : String(v))
/** Long values (logs, script blocks, command lines) get their own wrapped block; short ones go in the label/value grid. */
type Fact = { key: string; value: string }
const isLong = (f: Fact) => ['log', 'scriptBlock', 'commandLine'].includes(f.key) || String(f.value).length > 120
const shortFacts = (facts: Fact[]) => facts.filter((f) => !isLong(f))
const longFacts = (facts: Fact[]) => facts.filter(isLong)
</script>

<template>
  <section class="mb-5">
    <div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
      <h3 class="text-sm font-semibold text-slate-800">{{ t('iaf.title') }}</h3>
      <p v-if="data" class="text-xs text-slate-500">
        {{ t('iaf.typeIs') }} <strong class="text-slate-800">{{ typeLabel(data.incidentType) }}</strong>
        <template v-if="data.playbook"> · {{ t('iaf.playbook', { code: data.playbook.code }) }} · {{ t('iaf.matched', { t: data.matchedTechniques.join(', ') }) }}</template>
      </p>
    </div>
    <p v-if="error" class="rounded bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ error }}</p>
    <p v-else-if="!data" class="text-xs text-slate-500">{{ t('iaf.loading') }}</p>
    <p v-else-if="!data.rows.length" class="text-slate-500">{{ t('iaf.empty') }}</p>
    <div v-else class="space-y-3">
      <!-- one readable card per alert (no horizontal scrolling) -->
      <article v-for="r in data.rows" :key="r.alertId" class="rounded-xl border border-slate-200 bg-white p-4">
        <header class="flex flex-wrap items-start gap-x-3 gap-y-1">
          <SeverityBadge :severity="toSeverity(r.severity)" size="sm" />
          <div class="min-w-0 flex-1">
            <p class="text-sm font-semibold text-slate-900">{{ r.ruleDescription ?? t('iaf.noFacts') }}</p>
            <p class="mt-0.5 text-[11px] text-slate-500">
              {{ t('iaf.level', { n: dash(r.ruleLevel) }) }} · {{ t('iaf.col.type') }}: <span :class="r.incidentType ? 'text-slate-700' : 'text-slate-400'">{{ typeLabel(r.incidentType, true) }}</span>
            </p>
          </div>
        </header>

        <dl class="mt-3 grid grid-cols-1 gap-2 rounded-lg bg-slate-50 p-3 text-xs sm:grid-cols-3">
          <div>
            <dt class="text-slate-500">{{ t('iaf.col.srcIp') }}</dt>
            <dd class="mt-0.5 font-mono text-slate-900">{{ dash(r.sourceIp) }}</dd>
          </div>
          <div>
            <dt class="text-slate-500">{{ t('iaf.col.dstIp') }}</dt>
            <dd class="mt-0.5 font-mono text-slate-900">{{ dash(r.destinationIp) }}</dd>
          </div>
          <div class="min-w-0">
            <dt class="text-slate-500">{{ t('iaf.col.alert') }}</dt>
            <dd class="mt-0.5">
              <RouterLink :to="`/alerts/${r.alertId}`" class="break-all font-mono text-accent-700 hover:underline">{{ r.alertId }}</RouterLink>
              <span class="block break-all font-mono text-[11px] text-slate-400">{{ r.externalAlertId }}</span>
            </dd>
          </div>
        </dl>

        <dl v-if="shortFacts(r.facts).length" class="mt-3 grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs sm:grid-cols-[minmax(0,9rem)_minmax(0,1fr)]">
          <template v-for="f in shortFacts(r.facts)" :key="f.key">
            <dt class="text-slate-500">{{ factLabel(f.key) }}</dt>
            <dd class="break-all font-mono text-slate-900">{{ f.value }}</dd>
          </template>
        </dl>
        <div v-for="f in longFacts(r.facts)" :key="f.key" class="mt-3">
          <p class="mb-1 text-xs text-slate-500">{{ factLabel(f.key) }}</p>
          <pre class="whitespace-pre-wrap break-all rounded-lg bg-slate-900 px-3 py-2 font-mono text-[11px] leading-relaxed text-slate-100">{{ f.value }}</pre>
        </div>

        <p v-if="r.mitreTechniques.length" class="mt-3 flex flex-wrap gap-1.5">
          <span v-for="m in r.mitreTechniques" :key="m" class="rounded bg-indigo-50 px-1.5 py-0.5 font-mono text-[11px] text-indigo-700">MITRE {{ m }}</span>
        </p>
      </article>
    </div>
  </section>
</template>
