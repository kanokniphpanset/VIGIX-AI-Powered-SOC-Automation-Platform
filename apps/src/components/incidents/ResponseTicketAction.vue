<script setup lang="ts">
import type { ResponsePlan, RecommendationStep } from '@/api/vigix'
import { ticketStatusLabel } from '@/utils/ticket'
import { useI18n } from '@/i18n'
/** Per-step ticket status on the Recommendation tab. Tickets are created by the SOC "Send to IR" action. */
defineProps<{ step: RecommendationStep; ticket?: ResponsePlan }>()
const { t } = useI18n()
</script>
<template>
  <div class="mt-3 space-y-1 text-xs">
    <template v-if="ticket">
      <p>{{ t('rta.ticket') }} <strong>{{ ticketStatusLabel(ticket.status) }}</strong> · {{ t('rta.by', { role: ticket.assignedRole }) }}</p>
      <router-link :to="`/tickets/${ticket.id}`" class="font-semibold text-accent-700 underline">{{ t('rta.view') }}</router-link>
    </template>
    <p v-else-if="!step.actionId" class="text-slate-500">{{ t('rta.investigationOnly') }}</p>
    <p v-else class="text-slate-500">{{ t('rta.notSent') }}</p>
  </div>
</template>
