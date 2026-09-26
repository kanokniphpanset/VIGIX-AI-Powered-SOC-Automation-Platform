<script setup lang="ts">
// IR decision history of a ticket (legacy tickets may hold several steps). Display only — decisions go through the backend.
import { CheckCircle2, Circle, Clock3, Hourglass, XCircle } from 'lucide-vue-next'
import type { ApprovalStep } from '@/api/work'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'
import { labelMap } from '@/i18n/locale'

defineProps<{ steps: ApprovalStep[] }>()
const { t } = useI18n()

const TONE: Record<string, string> = {
  approved: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  pending: 'bg-amber-50 text-amber-800 ring-amber-300',
  waiting: 'bg-slate-50 text-slate-500 ring-slate-200',
  rejected: 'bg-rose-50 text-rose-700 ring-rose-200',
  more_evidence_requested: 'bg-orange-50 text-orange-700 ring-orange-200',
  cancelled: 'bg-slate-100 text-slate-400 ring-slate-200',
}
const LABEL: Record<string, string> = labelMap({
  approved: 'ac.approved', pending: 'ac.pending', waiting: 'ac.waiting', rejected: 'ac.rejected', more_evidence_requested: 'ac.more_evidence_requested', cancelled: 'ac.cancelled',
})
const icon = (s: string) => (s === 'approved' ? CheckCircle2 : s === 'pending' ? Clock3 : s === 'waiting' ? Hourglass : s === 'rejected' || s === 'more_evidence_requested' ? XCircle : Circle)
</script>

<template>
  <p v-if="!steps.length" class="text-xs text-slate-500">{{ t('ac.none') }}</p>
  <ol v-else class="flex flex-wrap items-center gap-1.5" :aria-label="t('ac.aria')">
    <template v-for="(s, n) in [...steps].sort((a, b) => a.stepOrder - b.stepOrder)" :key="s.id">
      <li class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset" :class="TONE[s.status] ?? TONE.waiting" :title="s.decidedAt ? t('ac.decided', { at: formatDateTime(s.decidedAt) }) : undefined">
        <component :is="icon(s.status)" class="size-3" />
        {{ s.stepOrder }}. {{ s.role ?? '?' }} · {{ LABEL[s.status] ?? s.status }}
      </li>
      <li v-if="n < steps.length - 1" aria-hidden="true" class="text-slate-300">→</li>
    </template>
  </ol>
</template>
