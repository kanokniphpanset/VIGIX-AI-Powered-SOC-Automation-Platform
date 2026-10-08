<script setup lang="ts">
// Incident audit trail (who · what · when · which entity · result), from GET /api/v1/incidents/:id/audit.
import { computed, ref } from 'vue'
import type { AuditEntry } from '@/api/work'
import { formatDateTime } from '@/utils/formatters'
import { actorName, auditGroup, auditLabel, auditOutcome, type AuditGroup } from '@/utils/workspace'
import { timelineText } from '@/utils/systemText'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

const props = defineProps<{ entries: AuditEntry[]; loading?: boolean; error?: string }>()
const { t } = useI18n()
const GROUPS: (AuditGroup | 'all')[] = ['all', 'triage', 'ai', 'policy', 'approval', 'response', 'verification', 'email', 'incident']
const group = ref<AuditGroup | 'all'>('all')
const hidePolicyNoise = ref(true)
const shown = computed(() =>
  props.entries.filter((e) => (group.value === 'all' || auditGroup(e.action) === group.value) && !(hidePolicyNoise.value && group.value === 'all' && e.action === 'POLICY_EVALUATED')),
)
const DOT: Record<string, string> = {
  triage: 'bg-sky-400', ai: 'bg-violet-400', policy: 'bg-slate-400', approval: 'bg-amber-400', response: 'bg-navy-700',
  verification: 'bg-emerald-500', email: 'bg-accent-500', incident: 'bg-slate-500',
}
</script>

<template>
  <div>
    <div class="mb-3 flex flex-wrap items-center gap-1.5">
      <button v-for="k in GROUPS" :key="k" type="button" class="rounded-full px-2.5 py-1 text-[11px] font-semibold" :class="group === k ? 'bg-navy-800 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'" @click="group = k">{{ t(`aud.g.${k}`) }}</button>
      <label v-if="group === 'all'" class="ml-auto flex items-center gap-1.5 text-[11px] text-slate-500"><input v-model="hidePolicyNoise" type="checkbox" class="size-3.5" /> {{ t('aud.hidePolicy') }}</label>
    </div>
    <p v-if="error" class="rounded-lg bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ error }}</p>
    <p v-else-if="loading && !entries.length" class="text-slate-500">{{ t('aud.loading') }}</p>
    <p v-else-if="!shown.length" class="text-slate-500">{{ t('aud.empty') }}</p>
    <ol class="relative space-y-3 border-l border-slate-200 pl-4">
      <li v-for="e in shown" :key="`${e.source}-${e.id}`" class="relative">
        <span class="absolute -left-[21px] top-1.5 size-2.5 rounded-full ring-2 ring-white" :class="DOT[auditGroup(e.action)]" />
        <p class="flex flex-wrap items-baseline gap-x-2 text-sm">
          <strong class="text-slate-900">{{ auditLabel(e.action) }}</strong>
          <span class="font-mono text-[10px] text-slate-400">{{ e.action }}</span>
        </p>
        <p class="text-xs text-slate-500">
          {{ formatDateTime(e.occurredAt) }} · <span class="text-slate-700">{{ actorName(e) }}</span>
          <template v-if="e.entity && e.entity !== 'Incident'"> · {{ hasMsg(`ent.${e.entity}`) ? t(`ent.${e.entity}` as MsgKey) : e.entity }} <span class="font-mono">{{ e.entityId?.slice(0, 8) }}</span></template>
        </p>
        <p v-if="e.description" class="mt-0.5 text-xs text-slate-700">{{ timelineText(e.action, e.description) }}</p>
        <p v-if="auditOutcome(e.metadata)" class="mt-0.5 text-xs text-slate-700">{{ auditOutcome(e.metadata) }}</p>
        <pre v-if="e.metadata && Object.keys(e.metadata).length" class="mt-1 whitespace-pre-wrap break-all rounded bg-slate-50 p-2 text-[11px] text-slate-600">{{ JSON.stringify(e.metadata, null, 2) }}</pre>
      </li>
    </ol>
  </div>
</template>
