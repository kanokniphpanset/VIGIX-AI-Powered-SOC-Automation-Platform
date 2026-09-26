<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { BookOpen, CheckCircle2, Loader2, RotateCw, Send } from 'lucide-vue-next'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import SendToIrModal from '@/components/ir/SendToIrModal.vue'
import { irEmailApi, type ResponseGuide } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { toSeverity } from '@/utils/vigix'
import { sendErrorMessage, type SendState } from '@/utils/irEmail'
import { dateLocale, useI18n } from '@/i18n'

/**
 * Response guide for an incident (built by the backend from the incident, its current-cycle IOCs, MITRE, severity and the
 * current recommendation) + "Send Response Guide to IR". `compact` shows only the send action and last result.
 * With `responseId` (from a response ticket) the guide/email covers that ticket's step and references the ticket.
 */
const props = withDefaults(defineProps<{ incidentId: string; responseId?: string | null; compact?: boolean }>(), { compact: false, responseId: null })
const session = useSessionStore()
const { t } = useI18n()

const guide = ref<ResponseGuide | null>(null)
const loading = ref(true)
const error = ref('')
const modalOpen = ref(false)
const lastSent = ref<SendState | null>(null)

async function load() {
  if (props.compact) {
    loading.value = false
    return
  }
  loading.value = true
  error.value = ''
  try {
    guide.value = (await irEmailApi.responseGuide(props.incidentId, props.responseId)).guide
  } catch (e) {
    error.value = sendErrorMessage(e)
  } finally {
    loading.value = false
  }
}
onMounted(load)
watch(() => [props.incidentId, props.responseId], load)

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString(dateLocale(), { dateStyle: 'medium', timeStyle: 'medium' }) : '—')
</script>

<template>
  <section :class="compact ? '' : 'rounded-xl border border-slate-200 bg-white p-5'" :aria-label="t('rg.aria')">
    <div v-if="!compact" class="mb-4 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h3 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><BookOpen class="size-4 text-slate-400" /> {{ t('rg.title') }}</h3>
        <p class="mt-0.5 text-xs text-slate-500">{{ t('rg.subtitle') }}</p>
      </div>
      <button type="button" class="inline-flex items-center gap-1 text-xs text-slate-500 hover:text-slate-800" @click="load"><RotateCw class="size-3.5" /> {{ t('c.refresh') }}</button>
    </div>

    <template v-if="!compact">
      <p v-if="loading" class="flex items-center gap-2 text-sm text-slate-500" role="status"><Loader2 class="size-4 animate-spin" /> {{ t('rg.loading') }}</p>
      <p v-else-if="error" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ error }}</p>
      <div v-else-if="guide" class="space-y-4 text-sm">
        <dl class="grid grid-cols-2 gap-3 rounded-lg bg-slate-50 p-3 sm:grid-cols-4">
          <div><dt class="text-xs text-slate-400">{{ t('tk.severity') }}</dt><dd class="mt-0.5"><SeverityBadge :severity="toSeverity(guide.severity)" size="sm" /></dd></div>
          <div><dt class="text-xs text-slate-400">MITRE</dt><dd class="mt-0.5 flex flex-wrap gap-1"><span v-for="m in guide.mitre" :key="m.techniqueId" class="rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[11px] font-semibold text-white" :title="m.tactic">{{ m.techniqueId }}</span><span v-if="!guide.mitre.length">—</span></dd></div>
          <div><dt class="text-xs text-slate-400">{{ t('tk.investigation') }}</dt><dd class="mt-0.5 font-semibold">#{{ guide.investigationNumber }}</dd></div>
        </dl>

        <div>
          <h4 class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('rg.relevantIocs', { n: guide.iocs.length }) }}</h4>
          <p v-if="!guide.iocs.length" class="mt-1 text-slate-500">{{ t('rg.noIocs') }}</p>
          <ul v-else class="mt-1.5 flex flex-wrap gap-1.5">
            <li v-for="i in guide.iocs" :key="i.type + i.value" class="rounded-md bg-slate-100 px-2 py-1 text-xs"><span class="font-semibold text-slate-600">{{ i.type }}</span> <span class="font-mono text-slate-900">{{ i.value }}</span> <span class="text-slate-400">· {{ i.source }}</span></li>
          </ul>
        </div>

        <div>
          <h4 class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('rg.recommended') }}<template v-if="guide.recommendation"> · #{{ guide.recommendation.number }}</template></h4>
          <p v-if="!guide.recommendation" class="mt-1 text-slate-500">{{ t('rg.noRec') }}</p>
          <template v-else>
            <p class="mt-1 text-slate-700">{{ guide.recommendation.summary }}</p>
            <ol class="mt-3 space-y-3">
              <li v-for="s in guide.steps" :key="s.stepOrder" class="rounded-lg border border-slate-200 p-3">
                <p class="font-semibold text-slate-900">{{ s.stepOrder }}. {{ s.action }}</p>
                <p class="mt-1 text-xs text-slate-600">{{ t('tk.target') }} <span class="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-slate-900">{{ s.target ?? '—' }}</span> · {{ s.reason }}</p>
                <ol class="mt-2 space-y-1 text-xs text-slate-700">
                  <li v-for="i in s.instructions" :key="i.order" class="flex gap-2"><span class="w-4 shrink-0 font-semibold text-slate-400">{{ i.order }}.</span><span>{{ i.instruction }}<span v-if="i.expectedResult" class="text-slate-400">{{ t('rg.expected', { text: i.expectedResult }) }}</span></span></li>
                </ol>
                <p v-if="s.verificationCriteria" class="mt-2 text-xs text-emerald-800">{{ t('inc.verify', { text: s.verificationCriteria }) }}</p>
                <p class="mt-2 text-[11px] text-slate-400">{{ t('rg.runbook') }} <span class="font-mono">{{ s.runbook ? `${s.runbook.code} — ${s.runbook.name}` : '—' }}</span></p>
              </li>
            </ol>
          </template>
        </div>
        <p class="text-xs text-slate-500">{{ t('rg.source') }}<template v-if="guide.playbook"> · {{ t('rg.playbook') }} <span class="font-mono">{{ guide.playbook.code }}</span> v{{ guide.playbook.version }}</template></p>
      </div>
    </template>

    <div class="flex flex-wrap items-center gap-3" :class="compact ? '' : 'mt-4 border-t border-slate-100 pt-4'">
      <button
        v-if="session.canSendToIr"
        type="button"
        class="inline-flex items-center gap-1.5 rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-accent-700"
        @click="modalOpen = true"
      ><Send class="size-4" /> {{ t('rg.send') }}</button>
      <p v-else class="text-xs text-slate-500">{{ t('rg.socOnly') }}</p>
      <p v-if="lastSent" class="flex items-center gap-1.5 text-xs text-emerald-700" role="status"><CheckCircle2 class="size-4" /> {{ t('rg.sent') }}<template v-if="lastSent.recipient"> ({{ lastSent.recipient }})</template> · {{ fmt(lastSent.sentAt) }} · {{ lastSent.deliveryStatus }}</p>
    </div>

    <SendToIrModal
      :open="modalOpen"
      :heading="t('rg.modalTitle')"
      :load-preview="() => irEmailApi.responseGuide(incidentId, responseId)"
      :send="(subject, key) => irEmailApi.sendResponseGuide(incidentId, { subject, responseId, idempotencyKey: key })"
      @sent="(s) => (lastSent = s)"
      @close="modalOpen = false"
    />
  </section>
</template>
