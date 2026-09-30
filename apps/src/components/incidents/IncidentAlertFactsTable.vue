<script setup lang="ts">
import { ref, watch } from 'vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { incidentsApi, type IncidentAlertFacts } from '@/api/vigix'
import { toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

/**
 * Investigation tab: the incident's alerts as one table — VIGIX alert ID, severity (Wazuh rule level), source /
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
</script>

<template>
  <section class="mb-5">
    <div class="mb-2 flex flex-wrap items-baseline justify-between gap-2">
      <h3 class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('iaf.title') }}</h3>
      <p v-if="data" class="text-xs text-slate-500">
        {{ t('iaf.typeIs') }} <strong class="text-slate-800">{{ typeLabel(data.incidentType) }}</strong>
        <template v-if="data.playbook"> · {{ t('iaf.playbook', { code: data.playbook.code }) }} · {{ t('iaf.matched', { t: data.matchedTechniques.join(', ') }) }}</template>
      </p>
    </div>
    <p v-if="error" class="rounded bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ error }}</p>
    <p v-else-if="!data" class="text-xs text-slate-500">{{ t('iaf.loading') }}</p>
    <p v-else-if="!data.rows.length" class="text-slate-500">{{ t('iaf.empty') }}</p>
    <div v-else class="overflow-x-auto rounded-lg border border-slate-200">
      <table class="w-full text-left text-xs">
        <thead class="bg-slate-50 text-[11px] uppercase text-slate-500">
          <tr>
            <th class="p-2">{{ t('iaf.col.alert') }}</th>
            <th class="p-2">{{ t('iaf.col.severity') }}</th>
            <th class="p-2">{{ t('iaf.col.srcIp') }}</th>
            <th class="p-2">{{ t('iaf.col.dstIp') }}</th>
            <th class="p-2">{{ t('iaf.col.incident') }}</th>
            <th class="p-2">{{ t('iaf.col.type') }}</th>
            <th class="p-2">{{ t('iaf.col.details') }}</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-slate-100 align-top">
          <tr v-for="r in data.rows" :key="r.alertId">
            <td class="min-w-[10rem] p-2">
              <RouterLink :to="`/alerts/${r.alertId}`" class="break-all font-mono text-accent-700 hover:underline">{{ r.alertId }}</RouterLink>
              <p class="mt-0.5 break-all font-mono text-[11px] text-slate-400">{{ r.externalAlertId }}</p>
            </td>
            <td class="whitespace-nowrap p-2">
              <SeverityBadge :severity="toSeverity(r.severity)" size="sm" />
              <p class="mt-1 text-[11px] text-slate-500">{{ t('iaf.level', { n: dash(r.ruleLevel) }) }}</p>
            </td>
            <td class="whitespace-nowrap p-2 font-mono">{{ dash(r.sourceIp) }}</td>
            <td class="whitespace-nowrap p-2 font-mono">{{ dash(r.destinationIp) }}</td>
            <td class="min-w-[10rem] p-2"><p class="font-mono text-[11px] text-slate-500">{{ incidentLabel }}</p><p class="text-slate-800">{{ incidentTitle }}</p></td>
            <td class="whitespace-nowrap p-2 font-medium" :class="r.incidentType ? 'text-slate-800' : 'text-slate-400'">{{ typeLabel(r.incidentType, true) }}</td>
            <td class="min-w-[16rem] p-2">
              <p v-if="r.ruleDescription" class="mb-1 text-slate-800">{{ r.ruleDescription }}</p>
              <dl v-if="r.facts.length" class="space-y-0.5">
                <div v-for="f in r.facts" :key="f.key" class="flex gap-2">
                  <dt class="shrink-0 text-slate-500">{{ factLabel(f.key) }}</dt>
                  <dd class="break-all font-mono text-slate-800">{{ f.value }}</dd>
                </div>
              </dl>
              <p v-if="r.mitreTechniques.length" class="mt-1 text-[11px] text-slate-400">MITRE {{ r.mitreTechniques.join(', ') }}</p>
              <p v-if="!r.ruleDescription && !r.facts.length" class="text-slate-400">{{ t('iaf.noFacts') }}</p>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </section>
</template>
