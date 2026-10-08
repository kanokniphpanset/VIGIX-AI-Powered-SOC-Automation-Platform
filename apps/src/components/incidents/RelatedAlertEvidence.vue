<script setup lang="ts">
// Related-alert evidence (Investigation). 1 Alert = 1 Incident stays: other Wazuh alerts are only SHOWN here (same host
// within ±24 h, or sharing an indicator of this incident). The SOC — not the AI — decides whether one of their
// indicators belongs to this incident and records it with its source alert and a reason; the re-hunt then hunts for it.
import { computed, onMounted, ref, watch } from 'vue'
import { Link2, Loader2, Plus } from 'lucide-vue-next'
import Modal from '@/components/common/Modal.vue'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import { incidentsApi, type RelatedAlertEvidence } from '@/api/vigix'
import { useUiStore } from '@/stores/ui'
import { formatDateTime } from '@/utils/formatters'
import { incidentLabel, toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

const props = defineProps<{ incidentId: string; investigationId: string | null; canAdd: boolean; reload: () => Promise<unknown> }>()
const ui = useUiStore()
const { t } = useI18n()

const items = ref<RelatedAlertEvidence[] | null>(null)
const error = ref('')
async function load() {
  error.value = ''
  try {
    items.value = (await incidentsApi.relatedAlertEvidence(props.incidentId)).items
  } catch (e) {
    error.value = workflowError(e)
    items.value = []
  }
}
onMounted(load)
watch(() => props.incidentId, load)

const pick = ref<{ alert: RelatedAlertEvidence; ioc: RelatedAlertEvidence['iocs'][number] } | null>(null)
const reason = ref('')
const busy = ref(false)
const addError = ref('')
const reasonOk = computed(() => reason.value.trim().length >= 5)
function open(alert: RelatedAlertEvidence, ioc: RelatedAlertEvidence['iocs'][number]) {
  pick.value = { alert, ioc }
  reason.value = ''
  addError.value = ''
}
async function add() {
  if (!pick.value || !props.investigationId || !reasonOk.value || busy.value) return
  busy.value = true
  addError.value = ''
  const { alert, ioc } = pick.value
  try {
    await incidentsApi.addIoc(props.investigationId, {
      iocType: ioc.iocType,
      iocValue: ioc.value,
      source: `SOC analyst (related Wazuh alert ${alert.externalAlertId})`.slice(0, 100),
      sourceAlertId: alert.alertId,
      reason: reason.value.trim(),
    })
    ui.success(t('rae.added'), t('rae.addedBody', { value: ioc.value, alert: alert.externalAlertId }))
    pick.value = null
    await Promise.all([props.reload(), load()])
  } catch (e) {
    addError.value = workflowError(e)
  } finally {
    busy.value = false
  }
}
const relation = (r: string) => t(`rae.rel.${r}` as MsgKey)
const iocTypeLabel = (type: string) => (hasMsg(`rae.t.${type}`) ? t(`rae.t.${type}` as MsgKey) : type)
</script>

<template>
  <div class="rounded-xl border border-slate-200 bg-slate-50/60 p-4">
    <h3 class="flex items-center gap-1.5 text-sm font-semibold text-slate-800"><Link2 class="size-4" /> {{ t('rae.title') }}</h3>
    <p class="mt-1 text-xs text-slate-500">{{ t('rae.intro') }}</p>
    <p v-if="error" class="mt-2 text-xs text-rose-700" role="alert">{{ error }}</p>
    <p v-else-if="items === null" class="mt-2 text-xs text-slate-500">{{ t('c.loading') }}</p>
    <p v-else-if="!items.length" class="mt-2 text-xs text-slate-500">{{ t('rae.none') }}</p>
    <ul v-else class="mt-3 space-y-3">
      <li v-for="a in items" :key="a.alertId" class="rounded-xl border border-slate-200 bg-white p-4">
        <div class="flex flex-wrap items-start gap-x-3 gap-y-1">
          <SeverityBadge :severity="toSeverity(a.severity)" size="sm" />
          <div class="min-w-0 flex-1">
            <router-link :to="`/alerts/${a.alertId}`" class="text-sm font-semibold text-slate-900 hover:underline">{{ a.ruleDescription ?? a.externalAlertId }}</router-link>
            <p class="mt-0.5 text-[11px] text-slate-500">{{ a.host ?? '—' }} · {{ t('rae.rule', { id: a.ruleId ?? '—' }) }} · {{ formatDateTime(a.receivedAt) }}</p>
          </div>
          <router-link v-if="a.incidentId && a.incidentId !== incidentId" :to="`/incidents/${a.incidentId}`" class="shrink-0 text-[11px] text-slate-500 hover:underline">{{ t('rae.inIncident', { inc: incidentLabel(a.incidentId) }) }}</router-link>
        </div>
        <p class="mt-2 flex flex-wrap gap-1.5">
          <span v-for="r in a.relation" :key="r" class="rounded bg-sky-50 px-1.5 py-0.5 text-[11px] font-semibold text-sky-800">{{ relation(r) }}</span>
        </p>
        <!-- indicators as rows: type | full value (wrapped, never cut) | on this incident / add -->
        <ul v-if="a.iocs.length" class="mt-3 divide-y divide-slate-100 rounded-lg border border-slate-100">
          <li v-for="i in a.iocs" :key="i.iocType + i.value" class="grid grid-cols-1 gap-1 px-3 py-2 text-xs sm:grid-cols-[minmax(0,8.5rem)_minmax(0,1fr)_auto] sm:items-start sm:gap-3">
            <span class="text-slate-500">{{ iocTypeLabel(i.iocType) }}</span>
            <span class="break-all font-mono text-slate-900">{{ i.value }}</span>
            <span v-if="i.onIncident" class="whitespace-nowrap rounded bg-emerald-50 px-1.5 py-0.5 text-[11px] font-semibold text-emerald-800">{{ t('rae.onIncidentShort') }}</span>
            <button v-else-if="canAdd && investigationId" type="button" class="inline-flex items-center gap-1 whitespace-nowrap rounded bg-navy-800 px-2 py-0.5 text-[11px] font-semibold text-white hover:bg-navy-700" :aria-label="t('rae.addAria', { value: i.value })" @click="open(a, i)"><Plus class="size-3" /> {{ t('rae.addShort') }}</button>
            <span v-else />
          </li>
        </ul>
        <p v-else class="mt-2 text-[11px] text-slate-400">{{ t('rae.noIndicator') }}</p>
      </li>
    </ul>

    <Modal :open="!!pick" :title="t('rae.modalTitle')" @close="!busy && (pick = null)">
      <form v-if="pick" class="space-y-3 text-sm" @submit.prevent="add">
        <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
          <dt class="text-slate-500">{{ t('rae.indicator') }}</dt><dd class="break-all font-mono">{{ pick.ioc.iocType }} · {{ pick.ioc.value }}</dd>
          <dt class="text-slate-500">{{ t('rae.sourceAlert') }}</dt><dd>{{ pick.alert.externalAlertId }} — {{ pick.alert.ruleDescription ?? '—' }}</dd>
          <dt class="text-slate-500">{{ t('rae.observedIn') }}</dt><dd class="font-mono">{{ pick.ioc.path }}</dd>
        </dl>
        <label class="block text-sm font-medium">{{ t('rae.why') }}
          <textarea v-model="reason" rows="3" maxlength="1000" required :disabled="busy" :placeholder="t('rae.whyPlaceholder')" class="mt-1 w-full rounded border border-slate-300 p-2 text-sm" />
        </label>
        <p class="text-xs text-slate-500">{{ t('rae.provenance') }}</p>
        <p v-if="addError" class="text-xs text-rose-700" role="alert">{{ addError }}</p>
        <div class="flex justify-end gap-2">
          <button type="button" class="btn-secondary" :disabled="busy" @click="pick = null">{{ t('c.cancel') }}</button>
          <button class="btn-primary inline-flex items-center gap-2" :disabled="busy || !reasonOk"><Loader2 v-if="busy" class="size-4 animate-spin" />{{ t('rae.add') }}</button>
        </div>
      </form>
    </Modal>
  </div>
</template>
