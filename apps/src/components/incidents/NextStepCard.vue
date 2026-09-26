<script setup lang="ts">
// "ขั้นต่อไป" card at the top of the incident page: whose turn it is, what is next, and ONE button for it.
// The decision of what is next lives in utils/nextStep.ts (tested); this component only renders it.
import { computed } from 'vue'
import { ArrowRight, CheckCircle2, Clock, Loader2, TriangleAlert, UserRound } from 'lucide-vue-next'
import { useI18n, type MsgKey } from '@/i18n'
import { WORKFLOW_STEPS, type NextStep } from '@/utils/nextStep'

const props = defineProps<{ step: NextStep; role: string | null; busy?: boolean }>()
const emit = defineEmits<{ act: [] }>()
const { t } = useI18n()

const k = (part: 'title' | 'body' | 'cta') => t(`next.${props.step.key}.${part}` as MsgKey, props.step.params)
const STYLE = {
  action: { box: 'border-sky-300 bg-sky-50/70', badge: 'bg-navy-800 text-white' },
  waiting: { box: 'border-slate-200 bg-white', badge: 'bg-slate-100 text-slate-700' },
  done: { box: 'border-emerald-200 bg-emerald-50/60', badge: 'bg-emerald-100 text-emerald-800' },
  problem: { box: 'border-rose-200 bg-rose-50/60', badge: 'bg-rose-100 text-rose-800' },
} as const
const style = computed(() => STYLE[props.step.tone])
const turnLabel = computed(() => (props.step.mine ? t('next.yourTurn') : t(`next.who.${props.step.turn}` as MsgKey)))
const showButton = computed(() => props.step.mine || props.step.turn === 'NONE')
</script>

<template>
  <section class="mb-5 rounded-xl border p-4" :class="style.box" aria-labelledby="next-step-h" data-testid="next-step">
    <div class="flex flex-wrap items-center gap-2 text-xs">
      <h2 id="next-step-h" class="font-semibold uppercase tracking-wide text-slate-500">{{ t('next.heading') }}</h2>
      <span class="inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-semibold" :class="style.badge">
        <CheckCircle2 v-if="step.tone === 'done'" class="size-3.5" /><TriangleAlert v-else-if="step.tone === 'problem'" class="size-3.5" /><UserRound v-else-if="step.mine" class="size-3.5" /><Clock v-else class="size-3.5" />
        {{ turnLabel }}
      </span>
      <span v-if="step.position" class="ml-auto text-slate-500">{{ t('next.progress', { n: step.position, total: WORKFLOW_STEPS }) }}</span>
    </div>
    <div v-if="step.position" class="mt-2 flex gap-1" aria-hidden="true">
      <span v-for="i in WORKFLOW_STEPS" :key="i" class="h-1 flex-1 rounded-full" :class="i < step.position ? 'bg-emerald-400' : i === step.position ? 'bg-navy-800' : 'bg-slate-200'" />
    </div>
    <p v-if="step.newCycle" class="mt-3 rounded-lg bg-amber-50 px-3 py-1.5 text-xs font-medium text-amber-900">{{ t('next.newCycle', { n: step.newCycle }) }}</p>

    <div class="mt-3 flex flex-wrap items-center justify-between gap-3">
      <div class="min-w-0 flex-1">
        <p class="text-base font-bold text-slate-900">{{ k('title') }}</p>
        <p class="mt-0.5 text-sm text-slate-600">{{ k('body') }}</p>
        <p v-if="!showButton" class="mt-1.5 text-xs text-slate-500">{{ role === 'admin' ? t('next.adminView') : t('next.waiting') }}</p>
      </div>
      <button
        v-if="showButton"
        type="button"
        class="inline-flex shrink-0 items-center gap-1.5 rounded-lg px-4 py-2.5 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-60"
        :class="step.mine ? 'bg-navy-800 text-white hover:bg-navy-700' : 'border border-slate-300 bg-white text-slate-700 hover:bg-slate-50'"
        :disabled="busy"
        :aria-busy="busy"
        @click="emit('act')"
      >
        <Loader2 v-if="busy" class="size-4 animate-spin" />{{ k('cta') }} <ArrowRight v-if="!busy" class="size-4" />
      </button>
    </div>
  </section>
</template>
