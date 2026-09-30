<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { ListChecks } from 'lucide-vue-next'
import { incidentsApi, type ResponseSetup } from '@/api/vigix'
import { workflowError } from '@/utils/workflow'
import { SEVERITY_LABEL } from '@/utils/formatters'
import { toSeverity } from '@/utils/vigix'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

/**
 * Response guidance before a Recommendation. The incident's group (type · severity) may have a guidance policy
 * (RESPONSE_GUIDANCE) for every case of that group; the SOC can adjust it for this case only. What is in force:
 * case > group > the playbook's actions. The Recommendation may only use the checked actions (backend-enforced) and
 * receives the instruction.
 */
const props = defineProps<{ incidentId: string; incidentStatus: string; canEdit: boolean }>()
const emit = defineEmits<{ saved: [message: string] }>()
const { t } = useI18n()

const setup = ref<ResponseSetup | null>(null)
const loadError = ref('')
const selected = ref<string[]>([])
const instructions = ref('')
const busy = ref(false)
const error = ref('')
const closed = computed(() => props.incidentStatus === 'resolved' || props.incidentStatus === 'dismissed')
const editable = computed(() => props.canEdit && !closed.value && !!setup.value?.playbook?.actions.length)

const typeLabel = (type: string | null) => (!type ? t('iaf.type.noneShort') : hasMsg(`iaf.type.${type}`) ? t(`iaf.type.${type}` as MsgKey) : type)
const group = computed(() => (setup.value?.incidentType ? `${typeLabel(setup.value.incidentType)} · ${SEVERITY_LABEL[toSeverity(setup.value.severity)]}` : null))
const dirty = computed(() => {
  const e = setup.value?.effective
  if (!e) return false
  return [...selected.value].sort().join() !== [...e.allowedActions].sort().join() || instructions.value.trim() !== (e.instructions ?? '')
})

function reset(s: ResponseSetup | null) {
  setup.value = s
  selected.value = [...(s?.effective.allowedActions ?? [])]
  instructions.value = s?.effective.instructions ?? ''
}
async function load() {
  loadError.value = ''
  try {
    reset(await incidentsApi.responseSetup(props.incidentId))
  } catch (e) {
    loadError.value = workflowError(e)
  }
}
watch(() => props.incidentId, load, { immediate: true })
defineExpose({ load })

const message = (code: string) => (hasMsg(`rgd.err.${code}`) ? t(`rgd.err.${code}` as MsgKey) : null)
async function run(action: () => Promise<ResponseSetup>, done: MsgKey) {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    reset(await action())
    emit('saved', t(done, { group: group.value ?? '' }))
  } catch (e) {
    error.value = message((e as { code?: string }).code ?? '') ?? workflowError(e)
  } finally {
    busy.value = false
  }
}
const saveCase = () => run(() => incidentsApi.setCaseGuidance(props.incidentId, selected.value, instructions.value.trim() || null), 'rgd.doneCase')
const saveGroup = () => {
  if (!window.confirm(t('rgd.groupConfirm', { group: group.value ?? '' }))) return
  return run(() => incidentsApi.saveGroupGuidance(props.incidentId, selected.value, instructions.value.trim() || null), 'rgd.doneGroup')
}
const clearCase = () => run(() => incidentsApi.clearCaseGuidance(props.incidentId), 'rgd.doneCleared')

const SOURCE_TONE = { CASE: 'bg-violet-50 text-violet-800 ring-violet-200', GROUP: 'bg-sky-50 text-sky-800 ring-sky-200', PLAYBOOK: 'bg-slate-100 text-slate-600 ring-slate-200' } as const
</script>

<template>
  <div class="rounded-lg border border-slate-200 p-3">
    <h3 class="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400"><ListChecks class="size-4" /> {{ t('rgd.title') }}</h3>
    <p v-if="loadError" class="mt-2 text-xs text-rose-700" role="alert">{{ loadError }}</p>
    <template v-else-if="setup">
      <p v-if="!setup.playbook" class="mt-2 text-sm text-slate-500">{{ t('rgd.noPlaybook') }}</p>
      <template v-else>
        <div class="mt-2 flex flex-wrap items-center gap-2 text-sm">
          <span class="text-slate-600">{{ t('rgd.group') }} <strong class="text-slate-900">{{ group }}</strong></span>
          <span class="text-xs text-slate-400">· Playbook {{ setup.playbook.code }}</span>
          <span class="rounded px-2 py-0.5 text-xs font-medium ring-1" :class="SOURCE_TONE[setup.effective.source]">{{ t(`rgd.source.${setup.effective.source}` as MsgKey) }}</span>
        </div>
        <p class="mt-1 text-xs text-slate-500">
          <template v-if="setup.group?.policies.length">{{ t('rgd.groupHas', { codes: setup.group.policies.join(', ') }) }}</template>
          <template v-else>{{ t('rgd.groupNone') }}</template>
        </p>

        <fieldset class="mt-3">
          <legend class="text-xs font-medium text-slate-600">{{ t('rgd.actions') }}</legend>
          <div class="mt-1 grid gap-1.5 sm:grid-cols-2">
            <label v-for="a in setup.playbook.actions" :key="a.code" class="flex items-start gap-2 rounded border border-slate-100 px-2 py-1.5 text-sm" :class="selected.includes(a.code) ? 'bg-sky-50/50' : ''">
              <input v-model="selected" type="checkbox" :value="a.code" :disabled="!editable || busy" class="mt-0.5" />
              <span><span class="text-slate-800">{{ a.name }}</span> <span class="font-mono text-[11px] text-slate-400">{{ a.code }}</span><span class="ml-1 text-[11px] text-slate-400">· {{ t('rgd.impact', { level: a.impactLevel }) }}</span></span>
            </label>
          </div>
        </fieldset>
        <label class="mt-3 block text-xs font-medium text-slate-600">{{ t('rgd.instructions') }} <span class="font-normal text-slate-400">{{ t('c.optional') }}</span>
          <textarea v-model="instructions" rows="2" maxlength="2000" :disabled="!editable || busy" :placeholder="t('rgd.placeholder')" class="mt-1 w-full rounded-lg border border-slate-300 p-2 text-sm font-normal" />
        </label>

        <div v-if="editable" class="mt-2 flex flex-wrap items-center gap-2">
          <button type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:opacity-50" :disabled="busy || !selected.length" @click="saveCase">{{ t('rgd.saveCase') }}</button>
          <button type="button" class="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50" :disabled="busy || !selected.length" @click="saveGroup">{{ t('rgd.saveGroup', { group: group ?? '' }) }}</button>
          <button v-if="setup.caseGuidance" type="button" class="text-xs text-slate-500 underline hover:text-slate-800 disabled:opacity-50" :disabled="busy" @click="clearCase">{{ t('rgd.clearCase') }}</button>
          <span v-if="dirty" class="text-xs text-amber-700">{{ t('rgd.unsaved') }}</span>
        </div>
        <p v-if="editable && !selected.length" class="mt-1 text-xs text-rose-700">{{ t('rgd.pickOne') }}</p>
        <p v-if="error" class="mt-2 rounded bg-rose-50 px-2 py-1 text-xs text-rose-700" role="alert">{{ error }}</p>
        <p v-if="!canEdit" class="mt-2 text-xs text-slate-400">{{ t('rgd.socOnly') }}</p>
      </template>
    </template>
  </div>
</template>
