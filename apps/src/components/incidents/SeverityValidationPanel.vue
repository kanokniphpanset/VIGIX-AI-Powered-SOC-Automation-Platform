<script setup lang="ts">
// SOC Severity Validation. VIGIX has ONE severity source: the Wazuh rule level (deterministic mapping). The SOC confirms
// it from the Wazuh evidence, or chooses another value — kept separate from the Wazuh value, with a mandatory reason.
// AI never generates, suggests or changes a severity. POST /api/v1/incidents/:id/severity-validation (audited
// SEVERITY_VALIDATED; a change re-runs the Policy assignment). Refused (SEVERITY_LOCKED) while a ticket awaits the IR
// decision or is in progress.
import { computed, onMounted, ref, watch } from 'vue'
import { ShieldCheck } from 'lucide-vue-next'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { incidentsApi, type IncidentSeverity } from '@/api/vigix'
import { toSeverity } from '@/utils/vigix'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { workflowError } from '@/utils/workflow'
import type { Severity } from '@/types'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

const props = defineProps<{ incidentId: string; incidentStatus: string; canValidate: boolean }>()
const emit = defineEmits<{ done: [message: string, result: { changed: boolean; severity: string }] }>()

const { t } = useI18n()
const LEVELS: Severity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
const info = ref<IncidentSeverity | null>(null)
const loadError = ref('')
const choice = ref<Severity>('MEDIUM')
const note = ref('')
const busy = ref(false)
const error = ref('')
const closed = computed(() => props.incidentStatus === 'resolved' || props.incidentStatus === 'dismissed')
const current = computed<Severity>(() => toSeverity(info.value?.severity))
const wazuh = computed<Severity | null>(() => (info.value?.wazuhSeverity ? toSeverity(info.value.wazuhSeverity) : null))
const changing = computed(() => choice.value !== current.value)
/** A reason is required for any change, and whenever the chosen value differs from the Wazuh severity. */
const reasonNeeded = computed(() => changing.value || (!!wazuh.value && choice.value !== wazuh.value))

async function load() {
  loadError.value = ''
  try {
    info.value = await incidentsApi.severity(props.incidentId)
    choice.value = toSeverity(info.value.severity)
  } catch (e) {
    loadError.value = workflowError(e)
  }
}
onMounted(load)
watch(() => props.incidentId, load)

const message = (code: string) => (hasMsg(`sv.err.${code}`) ? t(`sv.err.${code}` as MsgKey) : null)

async function submit() {
  if (busy.value || !props.canValidate || closed.value) return
  if (reasonNeeded.value && !note.value.trim()) {
    error.value = t('sv.err.REASON_REQUIRED')
    return
  }
  busy.value = true
  error.value = ''
  try {
    const r = await incidentsApi.validateSeverity(props.incidentId, choice.value, note.value.trim() || null)
    note.value = ''
    await load()
    emit('done', r.changed ? t('sv.doneChanged', { from: r.previous, to: r.severity }) : t('sv.doneConfirmed', { sev: r.severity }), { changed: r.changed, severity: r.severity })
  } catch (e) {
    const code = (e as { code?: string }).code ?? ''
    error.value = message(code) ?? workflowError(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="rounded-lg border border-slate-200 p-3">
    <h3 class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400"><ShieldCheck class="size-4" /> {{ t('sv.title') }}</h3>
    <p v-if="loadError" class="mt-2 text-xs text-rose-700" role="alert">{{ loadError }}</p>
    <template v-if="info">
      <dl class="mt-2 grid gap-3 text-sm sm:grid-cols-2">
        <div>
          <dt class="text-xs text-slate-500">{{ t('sv.incident') }}</dt>
          <dd class="mt-1"><SeverityBadge :severity="current" size="sm" /></dd>
        </div>
        <div>
          <dt class="text-xs text-slate-500">{{ t('sv.fromWazuh') }}</dt>
          <dd class="mt-1 text-slate-700">
            <template v-if="wazuh">{{ t('sv.wazuhRule', { sev: SEVERITY_LABEL[wazuh], rule: info.wazuhRuleId ?? t('c.notAvailable'), level: info.wazuhRuleLevel ?? t('c.notAvailable') }) }}</template>
            <template v-else>{{ t('c.notAvailable') }}</template>
          </dd>
        </div>
      </dl>
      <p v-if="info.overridden" class="mt-2 rounded bg-amber-50 px-2 py-1 text-xs text-amber-800">
        {{ t('sv.override') }}<template v-if="info.override"> · {{ info.override.reason ?? t('sv.noReason') }} ({{ formatDateTime(info.override.at) }})</template>
      </p>
      <template v-if="canValidate && !closed">
        <div class="mt-3 flex flex-wrap items-center gap-2">
          <label class="text-xs text-slate-600">{{ t('sv.select') }}
            <select v-model="choice" class="ml-1 rounded-lg border border-slate-300 px-2 py-1 text-sm" :disabled="busy" :aria-label="t('sv.select')">
              <option v-for="l in LEVELS" :key="l" :value="l">{{ SEVERITY_LABEL[l] }}</option>
            </select>
          </label>
          <input v-model="note" :placeholder="reasonNeeded ? t('sv.reasonRequired') : t('sv.noteOptional')" :aria-label="t('sv.reasonAria')" class="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-1 text-sm sm:min-w-56" :disabled="busy" />
          <button type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:opacity-50" :disabled="busy" :aria-busy="busy" @click="submit">
            {{ busy ? t('c.saving') : changing ? t('sv.changeTo', { sev: SEVERITY_LABEL[choice] }) : t('sv.confirm', { sev: SEVERITY_LABEL[current] }) }}
          </button>
        </div>
        <p v-if="error" class="mt-2 rounded bg-rose-50 px-2 py-1 text-xs text-rose-700" role="alert">{{ error }}</p>
      </template>
      <p v-else-if="!canValidate" class="mt-2 text-xs text-slate-400">{{ t('sv.socConfirms') }}</p>
    </template>
  </div>
</template>
