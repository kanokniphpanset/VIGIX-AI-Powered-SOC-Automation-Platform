<script setup lang="ts">
// Role-context incident email. The CONTENT follows the sender's role (SOC investigation / IR response with the IR
// decision); the RECIPIENT is a role whose address comes from Settings → Notification (never typed here). One
// idempotency key per dialog: a double click or retry after success never sends twice.
import { computed, ref, watch } from 'vue'
import { Mail, Send } from 'lucide-vue-next'
import { incidentEmailApi, type ContextEmailOutcome, type ContextEmailPreview, type EmailRecipientRole } from '@/api/work'
import { useSessionStore } from '@/stores/session'
import { formatDateTime } from '@/utils/formatters'
import { workflowError } from '@/utils/workflow'
import { useI18n, type MsgKey } from '@/i18n'

const props = defineProps<{ incidentId: string }>()
const session = useSessionStore()
const { t } = useI18n()
const ROLES: EmailRecipientRole[] = ['SOC', 'IR_TEAM', 'ADMIN']
const context = (c: string) => (['INVESTIGATION', 'RESPONSE', 'ADMINISTRATIVE'].includes(c) ? t(`em.ctx.${c}` as MsgKey) : c)
const source = (s: string) => (['settings', 'server', 'none'].includes(s) ? t(`em.src.${s}` as MsgKey) : s)

const canSend = computed(() => ['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? ''))
const recipientRole = ref<EmailRecipientRole>(session.role === 'SOC' ? 'IR_TEAM' : session.role === 'IR_TEAM' ? 'SOC' : 'IR_TEAM')
const note = ref('')
const preview = ref<ContextEmailPreview | null>(null)
const loadingPreview = ref(false)
const previewError = ref('')
const sending = ref(false)
const outcome = ref<ContextEmailOutcome | null>(null)
const sendError = ref('')
let key = crypto.randomUUID()

async function loadPreview() {
  loadingPreview.value = true
  previewError.value = ''
  try {
    preview.value = await incidentEmailApi.preview(props.incidentId, recipientRole.value, note.value.trim() || undefined)
  } catch (e) {
    preview.value = null
    previewError.value = workflowError(e)
  } finally {
    loadingPreview.value = false
  }
}
watch(recipientRole, () => {
  outcome.value = null
  key = crypto.randomUUID()
  void loadPreview()
}, { immediate: true })

const blocked = computed(() => !preview.value?.recipient.recipient ? t('em.noAddress') : !preview.value.recipient.emailChannelConfigured ? t('err.CHANNEL_NOT_CONFIGURED') : null)

async function send() {
  if (sending.value || !canSend.value || blocked.value) return
  sending.value = true
  sendError.value = ''
  try {
    outcome.value = await incidentEmailApi.send(props.incidentId, { recipientRole: recipientRole.value, note: note.value.trim() || null, idempotencyKey: key })
  } catch (e) {
    const body = (e as { body?: ContextEmailOutcome }).body
    sendError.value = workflowError({ code: body?.error ?? (e as { code?: string }).code })
    if (body?.status === 'FAILED') key = crypto.randomUUID() // a failed delivery may be retried as a new attempt
  } finally {
    sending.value = false
  }
}
function newEmail() {
  outcome.value = null
  note.value = ''
  key = crypto.randomUUID()
  void loadPreview()
}
</script>

<template>
  <div class="space-y-3">
    <p class="flex items-center gap-1.5 text-xs text-slate-500"><Mail class="size-4" /> {{ t('em.intro') }}</p>
    <div v-if="outcome" class="rounded-lg border p-3 text-sm" :class="outcome.status === 'SENT' ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-rose-200 bg-rose-50 text-rose-700'" role="status">
      <p v-if="outcome.status === 'SENT'">{{ t('em.sentTo', { role: t(`em.role.${outcome.recipientRole}` as MsgKey) }) }} <span class="font-mono">{{ outcome.recipient }}</span> · {{ outcome.sentAt ? formatDateTime(outcome.sentAt) : '' }}<template v-if="outcome.duplicate">{{ t('em.duplicate') }}</template></p>
      <p v-else>{{ t('em.notSent', { reason: workflowError({ code: outcome.error ?? 'HTTP_502' }) }) }}</p>
      <button type="button" class="mt-2 text-xs underline" @click="newEmail">{{ t('em.another') }}</button>
    </div>
    <template v-else>
      <div class="flex flex-wrap items-end gap-3">
        <label class="flex flex-col gap-1 text-xs text-slate-500">{{ t('em.recipientRole') }}
          <select v-model="recipientRole" class="rounded-lg border border-slate-300 px-2 py-1.5 text-sm text-slate-800" :disabled="sending"><option v-for="v in ROLES" :key="v" :value="v">{{ t(`em.role.${v}`) }}</option></select>
        </label>
        <p v-if="preview" class="pb-2 text-xs text-slate-600">
          {{ t('em.to') }} <span class="font-mono">{{ preview.recipient.recipient ?? t('em.notConfigured') }}</span> <span class="text-slate-400">({{ source(preview.recipient.source) }})</span>
          · {{ context(preview.context) }}
        </p>
      </div>
      <textarea v-model="note" rows="2" maxlength="2000" :placeholder="t('em.notePlaceholder')" :aria-label="t('em.noteAria')" class="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm" :disabled="sending" @blur="loadPreview" />
      <p v-if="previewError" class="rounded bg-rose-50 px-2 py-1 text-xs text-rose-700" role="alert">{{ previewError }}</p>
      <p v-if="preview" class="text-[11px] text-slate-400">{{ t('em.previewNote') }}</p>
      <div v-if="preview" class="rounded-lg border border-slate-200 bg-slate-50 p-3">
        <p class="text-xs font-semibold text-slate-700">{{ preview.email.subject }}</p>
        <pre class="mt-2 max-h-64 overflow-auto whitespace-pre-wrap text-[12px] text-slate-700">{{ preview.email.body }}</pre>
      </div>
      <p v-else-if="loadingPreview" class="text-xs text-slate-500">{{ t('em.loadingPreview') }}</p>
      <p v-if="blocked" class="text-xs text-amber-700">{{ blocked }}</p>
      <p v-if="sendError" class="rounded bg-rose-50 px-2 py-1 text-xs text-rose-700" role="alert">{{ sendError }}</p>
      <button v-if="canSend" type="button" class="inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-sm font-semibold text-white hover:bg-navy-700 disabled:opacity-40" :disabled="sending || !preview || !!blocked" :aria-busy="sending" @click="send">
        <Send class="size-4" /> {{ sending ? t('em.sending') : t('em.send') }}
      </button>
    </template>
  </div>
</template>
