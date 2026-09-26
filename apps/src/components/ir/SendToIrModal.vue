<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { CheckCircle2, Loader2, Mail, Send, XCircle } from 'lucide-vue-next'
import Modal from '@/components/common/Modal.vue'
import type { SendToIrPreview } from '@/api/vigix'
import { initialSendState, recipientProblem, runSend, sendErrorMessage, type IrEmailOutcome, type SendState } from '@/utils/irEmail'
import { dateLocale, useI18n, type MsgKey } from '@/i18n'

/**
 * Send-to-IR dialog (article or response guide). The preview is rendered by the backend — exactly what will be
 * sent — and names the IR Team recipient it resolved (masked). The user may only edit the subject. One idempotency
 * key per dialog: a repeated click or retry can never send the same email twice.
 */
const props = defineProps<{
  open: boolean
  heading: string
  loadPreview: () => Promise<SendToIrPreview>
  send: (subject: string | null, idempotencyKey: string) => Promise<IrEmailOutcome>
}>()
const emit = defineEmits<{ close: []; sent: [state: SendState] }>()
const { t } = useI18n()

const preview = ref<SendToIrPreview | null>(null)
const idempotencyKey = ref('')
const previewError = ref('')
const subject = ref('')
const state = ref<SendState>(initialSendState())

watch(
  () => props.open,
  async (open) => {
    if (!open) return
    state.value = initialSendState()
    idempotencyKey.value = crypto.randomUUID()
    preview.value = null
    previewError.value = ''
    try {
      preview.value = await props.loadPreview()
      subject.value = preview.value.email.subject
    } catch (e) {
      previewError.value = sendErrorMessage(e)
    }
  },
  { immediate: true },
)

async function submit() {
  if (!preview.value || blocked.value || state.value.status === 'sending' || state.value.status === 'sent') return
  // Unchanged subject → let the backend generate it from the content.
  const chosen = subject.value.trim() && subject.value.trim() !== preview.value.email.subject ? subject.value.trim() : null
  const final = await runSend(() => props.send(chosen, idempotencyKey.value), (s) => (state.value = s))
  if (final.status === 'sent') emit('sent', final)
}

const blocked = computed(() => recipientProblem(preview.value?.recipient ?? null))
const source = (s: string) => (['settings', 'server', 'none'].includes(s) ? t(`em.src.${s}` as MsgKey) : s)

function exact(iso: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.toLocaleDateString(dateLocale(), { day: '2-digit', month: 'short', year: 'numeric' })}, ${d.toLocaleTimeString(dateLocale(), { hour12: false })}`
}
</script>

<template>
  <Modal :open="open" :title="heading" size="lg" @close="state.status !== 'sending' && emit('close')">
    <!-- sent -->
    <div v-if="state.status === 'sent'" class="rounded-lg border border-emerald-200 bg-emerald-50 p-4" role="status">
      <p class="flex items-center gap-2 text-base font-semibold text-emerald-800"><CheckCircle2 class="size-5" /> {{ t('sti.sentTitle') }}</p>
      <dl class="mt-3 grid gap-2 text-sm sm:grid-cols-3">
        <div><dt class="text-xs text-emerald-700/70">{{ t('sti.sentAt') }}</dt><dd class="font-medium text-emerald-900">{{ exact(state.sentAt) }}</dd></div>
        <div><dt class="text-xs text-emerald-700/70">{{ t('sti.status') }}</dt><dd class="font-mono font-semibold text-emerald-900">{{ state.deliveryStatus }}</dd></div>
        <div><dt class="text-xs text-emerald-700/70">{{ t('sti.recipient') }}</dt><dd class="font-mono text-emerald-900">{{ state.recipient ?? t('sti.irTeam') }}</dd></div>
      </dl>
    </div>

    <template v-else>
      <dl class="grid gap-3 text-sm sm:grid-cols-[7rem_1fr] sm:items-center">
        <dt class="text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('sti.recipient') }}</dt>
        <dd class="flex flex-wrap items-center gap-2 font-semibold text-slate-800">
          <Mail class="size-4 text-slate-400" /> {{ t('sti.irTeam') }}
          <span v-if="preview?.recipient.recipient" class="font-mono text-xs font-normal text-slate-600">{{ preview.recipient.recipient }}</span>
          <span v-if="preview" class="text-xs font-normal text-slate-400">({{ source(preview.recipient.source) }})</span>
        </dd>
        <dt class="text-xs font-semibold uppercase tracking-wide text-slate-400"><label for="ir-subject">{{ t('sti.subject') }}</label></dt>
        <dd><input id="ir-subject" v-model="subject" maxlength="200" :disabled="!preview || state.status === 'sending'" class="w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-accent-500 focus:outline-none disabled:bg-slate-50" /></dd>
      </dl>

      <p class="mt-4 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('sti.preview') }}</p>
      <p v-if="!preview && !previewError" class="mt-2 flex items-center gap-2 text-sm text-slate-500" role="status"><Loader2 class="size-4 animate-spin" /> {{ t('em.loadingPreview') }}</p>
      <p v-else-if="previewError" class="mt-2 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ previewError }}</p>
      <pre v-else class="mt-2 max-h-80 overflow-auto whitespace-pre-wrap rounded-lg border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-relaxed text-slate-700">{{ preview!.email.body }}</pre>

      <p v-if="blocked" class="mt-3 flex items-start gap-2 rounded-lg bg-amber-50 px-3 py-2 text-sm text-amber-800" role="alert"><XCircle class="mt-0.5 size-4 shrink-0" /> {{ blocked }}</p>

      <p v-if="state.status === 'error'" class="mt-3 flex items-start gap-2 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert"><XCircle class="mt-0.5 size-4 shrink-0" /> {{ state.message }}</p>
      <p v-else-if="!blocked" class="mt-3 text-xs text-slate-500">{{ t('sti.realNote') }}</p>
    </template>

    <template #footer>
      <template v-if="state.status === 'sent'">
        <button type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-sm font-semibold text-white hover:bg-navy-700" @click="emit('close')">{{ t('c.close') }}</button>
      </template>
      <template v-else>
        <button type="button" class="rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-40" :disabled="state.status === 'sending'" @click="emit('close')">{{ t('c.cancel') }}</button>
        <button type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-accent-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-accent-700 disabled:cursor-not-allowed disabled:opacity-40" :disabled="!preview || !!blocked || state.status === 'sending'" @click="submit">
          <Loader2 v-if="state.status === 'sending'" class="size-4 animate-spin" /><Send v-else class="size-4" /> {{ state.status === 'sending' ? t('em.sending') : t('sti.send') }}
        </button>
      </template>
    </template>
  </Modal>
</template>
