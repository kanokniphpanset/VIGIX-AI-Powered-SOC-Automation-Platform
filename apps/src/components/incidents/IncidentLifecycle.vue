<script setup lang="ts">
// Incident 360 lifecycle (derived from stored records by utils/workspace.lifecycle) + the verification branches.
import { computed } from 'vue'
import { lifecycle, type LifecycleFacts } from '@/utils/workspace'
import { useI18n } from '@/i18n'

const props = defineProps<{ facts: LifecycleFacts; investigationNumber: number; maxRounds?: number }>()
const { t } = useI18n()
const steps = computed(() => lifecycle(props.facts))
const TONE = {
  done: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  current: 'bg-accent-50 text-accent-700 ring-accent-300 font-bold',
  todo: 'bg-slate-50 text-slate-400 ring-slate-200',
  blocked: 'bg-rose-50 text-rose-700 ring-rose-300',
} as const
const MARK = { done: '✓', current: '●', todo: '○', blocked: '!' } as const
const branch = computed(() => {
  const s = props.facts.incidentStatus
  if (s === 'resolved') return 'resolved'
  if (s === 'escalated') return 'escalated'
  if (props.investigationNumber > 1) return 'loop'
  return null
})
</script>

<template>
  <div class="mt-4">
    <ol class="flex flex-wrap items-center gap-1" :aria-label="t('lcb.aria')">
      <template v-for="(s, n) in steps" :key="s.key">
        <li class="rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ring-inset" :class="TONE[s.state]" :aria-current="s.state === 'current' ? 'step' : undefined">
          {{ MARK[s.state] }} {{ s.label }}
        </li>
        <li v-if="n < steps.length - 1" aria-hidden="true" class="text-[10px] text-slate-300">→</li>
      </template>
    </ol>
    <div class="mt-2 grid gap-1 text-[11px] text-slate-500 sm:grid-cols-3">
      <p :class="branch === 'resolved' ? 'font-semibold text-emerald-700' : ''">{{ t('lcb.resolved') }}</p>
      <p :class="branch === 'loop' ? 'font-semibold text-amber-700' : ''">
        {{ t('lcb.loop') }}
        <span v-if="investigationNumber > 1">{{ maxRounds ? t('lcb.cycleOf', { n: investigationNumber, max: maxRounds }) : t('lcb.cycle', { n: investigationNumber }) }}</span>
      </p>
      <p :class="branch === 'escalated' ? 'font-semibold text-rose-700' : ''">{{ t('lcb.escalated') }}</p>
    </div>
  </div>
</template>
