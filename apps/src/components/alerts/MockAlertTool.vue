<script setup lang="ts">
// Alert Inbox → "Test with a mock alert": the SOC picks one fixture from resources/ (TC-01…TC-10, ATK-01…ATK-10) and
// sends it through the same Wazuh normalization + ingestion as the real webhook (backend SendMockAlertUseCase). Every
// send is a new alert whose id starts with "mock-<case>-". Test data only; the backend turns sending off in production.
import { computed, ref } from 'vue'
import { FlaskConical, Loader2, Send } from 'lucide-vue-next'
import { alertsApi, type MockAlertCase } from '@/api/vigix'
import { useUiStore } from '@/stores/ui'
import { workflowError } from '@/utils/workflow'
import { SEVERITY_LABEL } from '@/utils/formatters'
import { toSeverity } from '@/utils/vigix'
import { useI18n } from '@/i18n'

const props = defineProps<{ cases: MockAlertCase[]; sendEnabled: boolean }>()
const emit = defineEmits<{ sent: [key: string] }>()
const { t } = useI18n()
const ui = useUiStore()

const key = ref('')
const busy = ref(false)
const groups = computed(() => [
  { label: t('al.mockGroupTc'), items: props.cases.filter((c) => c.set === 'TC') },
  { label: t('al.mockGroupAtk'), items: props.cases.filter((c) => c.set === 'MOCK_ATK') },
].filter((g) => g.items.length))
const chosen = computed(() => props.cases.find((c) => c.key === key.value) ?? null)
/** "ATK-03" for the E2E set (its own id), "TC-03" for the evaluation set. */
const label = (c: MockAlertCase) => `${c.key.replace(/^MOCK-/, '')} · ${c.title}`

async function send() {
  if (!key.value || busy.value) return
  busy.value = true
  try {
    const r = await alertsApi.sendMock(key.value)
    ui.success(t('al.mockSent', { key: r.key.replace(/^MOCK-/, ''), severity: SEVERITY_LABEL[toSeverity(r.severity)] }), r.incidentId ? t('al.mockSentIncident') : t('al.mockSentTriage'))
    emit('sent', r.key)
  } catch (e) {
    ui.error(t('al.mockSendFailed'), workflowError(e))
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="mb-4 rounded-xl border border-dashed border-violet-300 bg-violet-50/50 p-4" data-testid="mock-alert-tool" :aria-label="t('al.mockTool')">
    <h2 class="flex items-center gap-2 text-sm font-semibold text-violet-900"><FlaskConical class="size-4" /> {{ t('al.mockTool') }}</h2>
    <p class="mt-0.5 text-xs text-violet-800/80">{{ t('al.mockToolHint') }}</p>
    <p v-if="!sendEnabled" class="mt-2 text-xs text-slate-500">{{ t('al.mockDisabled') }}</p>
    <form v-else class="mt-3 flex flex-col gap-2 sm:flex-row sm:items-start" @submit.prevent="send">
      <div class="min-w-0 flex-1">
        <select v-model="key" :disabled="busy" :aria-label="t('al.mockPick')" class="w-full rounded border border-slate-300 bg-white p-2 text-sm text-slate-800">
          <option value="" disabled>{{ t('al.mockPick') }}</option>
          <optgroup v-for="g in groups" :key="g.label" :label="g.label">
            <option v-for="c in g.items" :key="c.key" :value="c.key">{{ label(c) }}</option>
          </optgroup>
        </select>
        <p v-if="chosen" class="mt-1 truncate text-xs text-slate-500" :title="chosen.file">
          Rule {{ chosen.ruleId ?? '—' }} · level {{ chosen.ruleLevel ?? '—' }} · {{ chosen.host ?? '—' }} · <span class="font-mono">{{ chosen.file }}</span>
        </p>
      </div>
      <button type="submit" class="inline-flex shrink-0 items-center justify-center gap-1.5 rounded-lg bg-violet-700 px-4 py-2 text-sm font-semibold text-white hover:bg-violet-800 disabled:opacity-50" :disabled="!key || busy">
        <Loader2 v-if="busy" class="size-4 animate-spin" /><Send v-else class="size-4" />{{ busy ? t('al.mockSending') : t('al.mockSend') }}
      </button>
    </form>
  </section>
</template>
