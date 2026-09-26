<script setup lang="ts">
import { computed } from 'vue'
import type { WorkTicket } from '@/api/work'
import type { Verification } from '@/api/vigix'
import StatusPill from '@/components/common/StatusPill.vue'
import { WORK_STAGE_LABEL } from '@/utils/workspace'
import { statusLabel } from '@/utils/vigix'
import { approvalSummary, latestTicket, rehuntRounds } from '@/utils/incidentWorkflow'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'

/**
 * Read-only lifecycle of the incident for every role (the SOC monitors here — it has no Response Tickets menu):
 * response + approval status of the current ticket, the latest re-hunt, the full re-hunt history and escalation.
 * Nothing here acts: IR executes and re-hunts on the Response Ticket.
 */
const props = defineProps<{
  incidentStatus: string
  investigationNumber: number
  tickets: WorkTicket[]
  verifications: Verification[]
  maxRounds?: number
}>()

const { t } = useI18n()
const current = computed(() => latestTicket(props.tickets))
const rounds = computed(() => rehuntRounds(props.verifications))
const lastRound = computed(() => rounds.value[rounds.value.length - 1] ?? null)
const escalated = computed(() => props.incidentStatus === 'escalated')
</script>

<template>
  <section class="rounded-lg border border-slate-200 p-3" aria-labelledby="wf-h">
    <h3 id="wf-h" class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('wf.title') }} <span class="font-normal normal-case text-slate-400">{{ t('wf.readOnly') }}</span></h3>
    <dl class="mt-2 grid gap-x-4 gap-y-2 text-sm sm:grid-cols-2">
      <div><dt class="text-xs text-slate-400">{{ t('wf.incidentStatus') }}</dt><dd class="mt-0.5 flex items-center gap-2"><StatusPill :status="incidentStatus" /><span class="text-xs text-slate-500">{{ t('wf.cycle', { n: investigationNumber }) }}</span></dd></div>
      <div>
        <dt class="text-xs text-slate-400">{{ t('wf.responseStatus') }}</dt>
        <dd class="mt-0.5">
          <template v-if="current">
            <span class="font-medium text-slate-800">{{ WORK_STAGE_LABEL[current.stage] ?? current.stage }}</span>
            <span class="text-xs text-slate-500"> · {{ current.assignedRole }}<template v-if="current.assignedToEmail"> ({{ current.assignedToEmail }})</template></span>
          </template>
          <span v-else class="text-slate-500">{{ t('wf.noTicket') }}</span>
        </dd>
      </div>
      <div><dt class="text-xs text-slate-400">{{ t('wf.irDecision') }}</dt><dd class="mt-0.5 text-slate-800">{{ approvalSummary(current) }}</dd></div>
      <div>
        <dt class="text-xs text-slate-400">{{ t('wf.latestAction') }}</dt>
        <dd class="mt-0.5 text-slate-800">
          <template v-if="current">{{ current.stepTitle ?? current.actionName ?? t('wf.response') }}<span v-if="current.target" class="font-mono text-xs text-slate-500"> → {{ current.target }}</span></template>
          <span v-else class="text-slate-500">—</span>
        </dd>
      </div>
      <div>
        <dt class="text-xs text-slate-400">{{ t('wf.latestRehunt') }}</dt>
        <dd class="mt-0.5">
          <template v-if="lastRound">
            <span class="font-semibold" :class="lastRound.result === 'RESOLVED' ? 'text-emerald-700' : 'text-rose-700'">{{ lastRound.result === 'RESOLVED' ? t('wf.resolved') : t('wf.stillAbnormal') }}</span>
            <span class="text-xs text-slate-500"> · {{ t('wf.round', { n: lastRound.round }) }}<template v-if="lastRound.at"> · {{ formatDateTime(lastRound.at) }}</template></span>
          </template>
          <span v-else class="text-slate-500">{{ t('wf.notRehunted') }}</span>
        </dd>
      </div>
      <div>
        <dt class="text-xs text-slate-400">{{ t('wf.escalation') }}</dt>
        <dd class="mt-0.5" :class="escalated ? 'font-semibold text-rose-700' : 'text-slate-500'">
          {{ escalated ? t('wf.escalated', { n: maxRounds ?? 3 }) : t('wf.notEscalated') }}
        </dd>
      </div>
    </dl>

    <div v-if="rounds.length" class="mt-3 border-t border-slate-100 pt-2">
      <p class="text-xs font-semibold text-slate-500">{{ t('wf.history') }}</p>
      <ol class="mt-1 space-y-1 text-xs">
        <li v-for="r in rounds" :key="r.id" class="flex flex-wrap items-center gap-x-2">
          <span class="font-semibold text-slate-700">{{ t('wf.roundN', { n: r.round }) }}</span>
          <span :class="r.result === 'RESOLVED' ? 'text-emerald-700' : 'text-rose-700'">{{ statusLabel(r.result) }}</span>
          <span class="text-slate-500">{{ t('wf.matching', { n: r.matchingEvents ?? '—' }) }}<template v-if="r.spreadDetected">{{ t('wf.spread') }}</template></span>
          <span v-if="r.source" class="text-slate-400">{{ r.source }}</span>
          <span v-if="r.at" class="text-slate-400">{{ formatDateTime(r.at) }}</span>
          <span v-if="r.by" class="text-slate-400">{{ t('wf.by', { who: r.by }) }}</span>
        </li>
      </ol>
      <p class="mt-1 text-[11px] text-slate-400">{{ t('wf.historyNote') }}</p>
    </div>
  </section>
</template>
