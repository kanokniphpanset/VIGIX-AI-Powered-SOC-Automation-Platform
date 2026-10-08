<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import Modal from '@/components/common/Modal.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { alertsApi, type AlertView } from '@/api/vigix'
import { available, DECISION_LABEL, reasonRequired, reviewDecisions, type ReviewDecision } from '@/utils/triage'
import { formatDateTime } from '@/utils/formatters'
import { useI18n } from '@/i18n'
import { statusLabel, toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'

/**
 * SOC review of one open alert (no claim). MEDIUM: create the incident, or close it with a reason. HIGH / CRITICAL
 * without an incident (legacy): create it. The incident keeps the Wazuh severity; nothing is emailed from here.
 */
const props = defineProps<{ alertId: string | null }>()
const emit = defineEmits<{ close: []; done: [incidentId: string | null] }>()
const { t } = useI18n()
const view = ref<AlertView | null>(null)
const decision = ref<ReviewDecision>('CREATE_INCIDENT')
const reason = ref('')
const error = ref('')
const busy = ref(false)
let generation = 0
watch(
  () => props.alertId,
  async (id) => {
    const request = ++generation
    view.value = null
    reason.value = ''
    error.value = ''
    decision.value = 'CREATE_INCIDENT'
    if (!id) return
    try {
      const result = await alertsApi.view(id)
      if (request === generation) view.value = result
    } catch (e) {
      if (request === generation) error.value = workflowError(e)
    }
  },
  { immediate: true },
)
const decisions = computed(() => (view.value ? reviewDecisions(view.value.alert) : []))
const valid = computed(() => decisions.value.includes(decision.value) && (!reasonRequired(decision.value) || !!reason.value.trim()))
async function submit() {
  if (!props.alertId || !valid.value || busy.value) return
  busy.value = true
  error.value = ''
  try {
    const result = await alertsApi.triage(props.alertId, { decision: decision.value, reason: reason.value.trim() || null })
    emit('done', result.incidentId)
  } catch (e) {
    error.value = workflowError(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <Modal :open="!!alertId" :title="t('rv.title')" size="lg" @close="!busy && emit('close')">
    <p v-if="error" role="alert" class="mb-3 text-sm text-rose-700">{{ error }}</p>
    <p v-if="!view && !error">{{ t('rv.loading') }}</p>
    <template v-if="view">
      <h3 class="mb-4 font-semibold text-slate-900">{{ available(view.alert.summary.ruleDescription) }}</h3>
      <dl class="grid grid-cols-2 gap-3 text-sm">
        <div><dt class="text-slate-500">{{ t('rv.severity', { level: available(view.alert.summary.ruleLevel) }) }}</dt><dd><SeverityBadge :severity="toSeverity(view.alert.severity)" size="sm" /></dd></div>
        <div><dt class="text-slate-500">{{ t('rv.rule') }}</dt><dd>{{ available(view.alert.summary.ruleId) }}</dd></div>
        <div><dt class="text-slate-500">{{ t('rv.time') }}</dt><dd>{{ formatDateTime(view.alert.receivedAt) }}</dd></div>
        <div><dt class="text-slate-500">{{ t('rv.source') }}</dt><dd>{{ available(view.alert.siemSource) }} / {{ available(view.alert.summary.host) }}</dd></div>
        <div><dt class="text-slate-500">{{ t('rv.sla') }}</dt><dd>{{ view.alert.slaStatus ? statusLabel(view.alert.slaStatus) : t('c.notAvailable') }} · {{ view.alert.slaDueAt ? formatDateTime(view.alert.slaDueAt) : t('c.notAvailable') }}</dd></div>
        <div><dt class="text-slate-500">{{ t('rv.id') }}</dt><dd class="break-all font-mono text-xs">{{ view.alert.externalAlertId }}</dd></div>
      </dl>
      <div class="my-4 rounded border border-slate-200 p-3 text-sm">
        <p class="font-medium">{{ t('rv.evidence') }}</p>
        <p v-for="ioc in view.iocs" :key="ioc.path + ioc.value" class="mt-2 font-mono">{{ ioc.iocType }}: {{ ioc.value }}</p>
        <pre class="mt-3 max-h-64 overflow-auto whitespace-pre-wrap text-xs">{{ JSON.stringify(view.rawPayload, null, 2) }}</pre>
      </div>
      <p v-if="!decisions.length" class="rounded bg-slate-50 p-3 text-sm text-slate-600">{{ t('rv.nothing') }}</p>
      <form v-else class="space-y-4" @submit.prevent="submit">
        <fieldset class="space-y-2">
          <legend class="text-sm font-medium">{{ t('rv.decision') }}</legend>
          <label v-for="d in decisions" :key="d" class="flex items-center gap-2 text-sm">
            <input v-model="decision" type="radio" name="decision" :value="d" :disabled="busy" /> {{ DECISION_LABEL[d] }}
          </label>
        </fieldset>
        <p v-if="decision === 'CREATE_INCIDENT'" class="text-sm text-slate-600">{{ t('rv.createHint') }}</p>
        <label class="block text-sm font-medium">{{ t('rv.reason') }} {{ reasonRequired(decision) ? t('c.required') : t('c.optional') }}
          <textarea v-model="reason" :required="reasonRequired(decision)" :disabled="busy" rows="3" maxlength="2000" class="mt-1 w-full rounded border border-slate-300 p-2" />
        </label>
        <button type="submit" :disabled="!valid || busy" class="rounded-lg bg-navy-800 px-4 py-2 text-sm font-semibold text-white disabled:opacity-40">{{ busy ? t('c.saving') : DECISION_LABEL[decision] }}</button>
      </form>
    </template>
  </Modal>
</template>
