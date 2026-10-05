<script setup lang="ts">
// Recent re-hunt verdicts across all incidents (formerly the Verification page), shown collapsed under the
// "completed" tab of the Response Tickets page. Loaded only when opened. Display only — nothing here resolves a case.
import { ref } from 'vue'
import StatusPill from '@/components/common/StatusPill.vue'
import { api } from '@/api/http'
import type { Verification } from '@/api/vigix'
import { useI18n } from '@/i18n'
import { incidentLabel, timeAgo } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'

type VerificationRow = Verification & { incidentId: string }
const { t } = useI18n()
const rows = ref<VerificationRow[] | null>(null)
const error = ref('')

async function load() {
  error.value = ''
  try {
    rows.value = (await api<{ items: VerificationRow[] }>('/api/verifications', { query: { limit: 50 } })).items
  } catch {
    error.value = t('vf.loadFailed')
  }
}
function onToggle(e: Event) {
  if ((e.target as HTMLDetailsElement).open && rows.value === null) void load()
}
</script>

<template>
  <details class="mt-4 rounded-xl border border-slate-200 bg-white" @toggle="onToggle">
    <summary class="cursor-pointer select-none px-4 py-3 text-sm font-semibold text-slate-800">{{ t('vf.recent') }}</summary>
    <div class="border-t border-slate-100 p-4">
      <p v-if="error" class="text-sm text-rose-700" role="alert">{{ error }} <button type="button" class="underline" @click="load">{{ t('c.retry') }}</button></p>
      <p v-else-if="rows === null" class="text-sm text-slate-500">{{ t('c.loading') }}</p>
      <p v-else-if="!rows.length" class="text-sm text-slate-500">{{ t('vf.noneRecorded') }}</p>
      <div v-else class="overflow-x-auto">
        <table class="w-full min-w-[640px] text-sm">
          <thead class="border-b border-slate-100 text-left text-xs text-slate-400">
            <tr><th class="px-3 py-2">{{ t('vf.col.incident') }}</th><th class="px-3 py-2">{{ t('vf.col.verdict') }}</th><th class="px-3 py-2">{{ t('vf.col.rehunt') }}</th><th class="px-3 py-2">{{ t('vf.col.matching') }}</th><th class="px-3 py-2">{{ t('vf.col.spread') }}</th><th class="px-3 py-2">{{ t('vf.col.source') }}</th><th class="px-3 py-2">{{ t('vf.col.when') }}</th></tr>
          </thead>
          <tbody class="divide-y divide-slate-100">
            <tr v-for="v in rows" :key="v.id">
              <td class="px-3 py-2"><router-link :to="`/incidents/${v.incidentId}?tab=verification`" class="font-mono text-xs text-accent-700 hover:underline">{{ incidentLabel(v.incidentId) }}</router-link></td>
              <td class="px-3 py-2"><StatusPill :status="v.result" /></td>
              <td class="px-3 py-2 text-xs font-semibold">{{ v.result === 'RESOLVED' ? t('tk.noMatch') : (v.matchingEvents ?? 0) > 0 ? t('tk.match') : t('vf.manual') }}</td>
              <td class="px-3 py-2 text-xs">{{ v.matchingEvents ?? '—' }}</td>
              <td class="px-3 py-2 text-xs">{{ v.spreadDetected ? t('c.yes') : t('c.no') }}</td>
              <td class="px-3 py-2 text-xs">{{ v.afterState?.evidenceSource ?? '—' }}</td>
              <td class="whitespace-nowrap px-3 py-2 text-xs text-slate-500" :title="v.verifiedAt ? formatDateTime(v.verifiedAt) : ''">{{ v.verifiedAt ? timeAgo(v.verifiedAt) : '—' }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  </details>
</template>
