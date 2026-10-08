<script setup lang="ts">
// Similar past cases: closed incidents that share an IOC / Wazuh rule / MITRE technique / host with this one, ranked
// deterministically on the backend (domain/incident/similarCases). Read-only reference for the analyst: why each case
// matched and how it was handled (response actions, re-hunt result, rounds, close note). No AI involved.
import { onMounted, ref, watch } from 'vue'
import { History, Loader2 } from 'lucide-vue-next'
import { workApi, type SimilarCase } from '@/api/work'
import { formatDateTime } from '@/utils/formatters'
import { incidentLabel, statusLabel } from '@/utils/vigix'
import { useI18n, type MsgKey } from '@/i18n'

const props = defineProps<{ incidentId: string }>()
const { t } = useI18n()

const items = ref<SimilarCase[] | null>(null)
const failed = ref(false)
async function load() {
  items.value = null
  failed.value = false
  try {
    items.value = (await workApi.similarCases(props.incidentId)).items
  } catch {
    failed.value = true
    items.value = []
  }
}
onMounted(load)
watch(() => props.incidentId, load)

const actionText = (a: SimilarCase['actions'][number]) => [a.name ?? a.code ?? '—', a.target].filter(Boolean).join(' → ')
/** Each distinct action once (the same step re-sent in a later round is one way the case was handled). */
const actionsOf = (c: SimilarCase) => [...new Set(c.actions.map(actionText))].join(' · ')
</script>

<template>
  <section :aria-label="t('sim.title')" data-testid="similar-cases">
    <h2 class="flex items-center gap-1.5 text-sm font-semibold text-slate-800"><History class="size-4 text-slate-400" />{{ t('sim.title') }}</h2>
    <p class="mt-0.5 text-[11px] leading-snug text-slate-500">{{ t('sim.hint') }}</p>

    <p v-if="items === null" class="mt-3 flex items-center gap-1.5 text-xs text-slate-500"><Loader2 class="size-3.5 animate-spin" /></p>
    <p v-else-if="failed" class="mt-3 text-xs text-rose-600">{{ t('sim.loadFailed') }}</p>
    <p v-else-if="!items.length" class="mt-3 text-xs text-slate-500">{{ t('sim.none') }}</p>

    <ul v-else class="mt-3 space-y-2">
      <li v-for="c in items" :key="c.id">
        <RouterLink :to="{ name: 'incident-detail', params: { id: c.id } }" class="block rounded-lg border border-slate-100 px-2.5 py-2 hover:bg-slate-50">
          <span class="flex items-center justify-between gap-2">
            <span class="font-mono text-[11px] text-slate-500">{{ incidentLabel(c.id) }}</span>
            <span
              class="rounded-full px-1.5 py-0.5 text-[10px] font-semibold ring-1 ring-inset"
              :class="c.status === 'resolved' ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-slate-200'"
            >{{ statusLabel(c.status) }}</span>
          </span>
          <span class="mt-0.5 block text-xs font-medium text-slate-800">{{ c.title }}</span>

          <span class="mt-1.5 flex flex-wrap gap-1">
            <span v-for="r in c.reasons" :key="r.kind" class="rounded bg-sky-50 px-1.5 py-0.5 text-[10px] text-sky-800" :title="r.values.join(', ')">
              {{ t(`sim.reason.${r.kind}` as MsgKey) }}: <span class="font-mono">{{ r.values.slice(0, 2).join(', ') }}<template v-if="r.values.length > 2"> +{{ r.values.length - 2 }}</template></span>
            </span>
          </span>

          <span class="mt-1.5 block text-[11px] text-slate-600">
            <span class="font-semibold">{{ t('sim.handled') }}:</span>
            <template v-if="c.actions.length">{{ actionsOf(c) }}</template>
            <template v-else>{{ t('sim.noAction') }}</template>
          </span>
          <span class="mt-0.5 block text-[11px] text-slate-500">
            {{ [c.lastVerification ? t('sim.verified', { r: statusLabel(c.lastVerification) }) : null, t('sim.rounds', { n: c.investigationNumber }), c.closedAt ? t('sim.closed', { at: formatDateTime(c.closedAt) }) : null].filter(Boolean).join(' · ') }}
          </span>
          <span v-if="c.closeNote" class="mt-0.5 block text-[11px] italic text-slate-500">{{ t('sim.note', { note: c.closeNote }) }}</span>
        </RouterLink>
      </li>
    </ul>
  </section>
</template>
