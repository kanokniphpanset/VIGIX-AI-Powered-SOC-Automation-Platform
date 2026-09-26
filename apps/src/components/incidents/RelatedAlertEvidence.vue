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
</script>

<template>
  <div class="rounded-lg border border-slate-200 p-3">
    <h3 class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400"><Link2 class="size-4" /> {{ t('rae.title') }}</h3>
    <p class="mt-1 text-xs text-slate-500">{{ t('rae.intro') }}</p>
    <p v-if="error" class="mt-2 text-xs text-rose-700" role="alert">{{ error }}</p>
    <p v-else-if="items === null" class="mt-2 text-xs text-slate-500">{{ t('c.loading') }}</p>
    <p v-else-if="!items.length" class="mt-2 text-xs text-slate-500">{{ t('rae.none') }}</p>
    <ul v-else class="mt-3 space-y-2">
      <li v-for="a in items" :key="a.alertId" class="rounded-lg bg-slate-50 p-3">
        <div class="flex flex-wrap items-center gap-2 text-xs">
          <SeverityBadge :severity="toSeverity(a.severity)" size="sm" />
          <router-link :to="`/alerts/${a.alertId}`" class="font-medium text-slate-800 hover:underline">{{ a.ruleDescription ?? a.externalAlertId }}</router-link>
          <span class="text-slate-500">{{ a.host ?? '—' }} · {{ t('rae.rule', { id: a.ruleId ?? '—' }) }} · {{ formatDateTime(a.receivedAt) }}</span>
          <span v-for="r in a.relation" :key="r" class="rounded bg-sky-100 px-1.5 py-0.5 text-[11px] font-semibold text-sky-800">{{ relation(r) }}</span>
          <router-link v-if="a.incidentId && a.incidentId !== incidentId" :to="`/incidents/${a.incidentId}`" class="ml-auto text-[11px] text-slate-500 hover:underline">{{ t('rae.inIncident', { inc: incidentLabel(a.incidentId) }) }}</router-link>
        </div>
        <div v-if="a.iocs.length" class="mt-2 flex flex-wrap gap-1.5">
          <span v-for="i in a.iocs" :key="i.iocType + i.value" class="inline-flex max-w-full items-center gap-1 rounded border px-1.5 py-0.5 text-[11px]" :class="i.onIncident ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-slate-200 bg-white text-slate-700'">
            <span class="text-slate-400">{{ i.iocType }}</span>
            <span class="truncate font-mono">{{ i.value }}</span>
            <span v-if="i.onIncident" class="font-semibold">{{ t('rae.onIncident') }}</span>
            <button v-else-if="canAdd && investigationId" type="button" class="ml-0.5 inline-flex items-center rounded bg-navy-800 px-1 text-white hover:bg-navy-700" :aria-label="t('rae.addAria', { value: i.value })" @click="open(a, i)"><Plus class="size-3" /></button>
          </span>
        </div>
        <p v-else class="mt-1 text-[11px] text-slate-400">{{ t('rae.noIndicator') }}</p>
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
