<script setup lang="ts">
// Incident group & Response Policy (Overview tab). Incidents are grouped by TYPE + SEVERITY so the organization can write
// ONE response policy per group (RESPONSE_GUIDANCE). This panel: (1) the group - its incidents and whether its policy is
// set; (2) the group's Response Policy - allowed / forbidden actions and what to do first (the per-case setting is only an
// exception). Moving incidents between groups is done with "+ Add Group" (OpenIncidents).
// Saves use the existing audited endpoints (response-guidance group / case).
import { computed, ref, watch } from 'vue'
import { Check, Layers, Loader2, X } from 'lucide-vue-next'
import StatusPill from '@/components/common/StatusPill.vue'
import { incidentsApi, type IncidentSeverity, type ResponseGroup, type ResponseSetup } from '@/api/vigix'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { incidentLabel, toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import type { Severity } from '@/types'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

const props = defineProps<{ incidentId: string; incidentStatus: string; canEdit: boolean }>()
const emit = defineEmits<{ changed: [message: string, result?: { changed: boolean; severity: string }] }>()
const { t } = useI18n()

const sev = ref<IncidentSeverity | null>(null)
const setup = ref<ResponseSetup | null>(null)
const group = ref<ResponseGroup | null>(null)
const loadError = ref('')
const closed = computed(() => props.incidentStatus === 'resolved' || props.incidentStatus === 'dismissed')

const typeLabel = (type: string | null | undefined) => (!type ? t('iaf.type.noneShort') : hasMsg(`iaf.type.${type}`) ? t(`iaf.type.${type}` as MsgKey) : type)
const groupName = (type: string | null | undefined, s: Severity) => `${typeLabel(type)} · ${SEVERITY_LABEL[s]}`

async function load() {
  loadError.value = ''
  try {
    const [s, rs, g] = await Promise.all([
      incidentsApi.severity(props.incidentId),
      incidentsApi.responseSetup(props.incidentId).catch(() => null),
      incidentsApi.responseGroup(props.incidentId).catch(() => null),
    ])
    sev.value = s
    setup.value = rs
    group.value = g
      resetPolicy()
  } catch (e) {
    loadError.value = workflowError(e)
  }
}
watch(() => props.incidentId, load, { immediate: true })

// ---- 1. group ------------------------------------------------------------------------------------------------------------
const severity = computed<Severity>(() => toSeverity(sev.value?.severity))
const currentGroup = computed(() => (setup.value?.incidentType ? groupName(setup.value.incidentType, severity.value) : null))
const members = computed(() => [...(group.value?.members ?? [])].sort((a, b) => Number(['resolved', 'dismissed'].includes(a.status)) - Number(['resolved', 'dismissed'].includes(b.status)) || b.openedAt.localeCompare(a.openedAt)))
const openCount = computed(() => members.value.filter((m) => !['resolved', 'dismissed'].includes(m.status)).length)

// ---- 2. response policy of the group ---------------------------------------------------------------------------------------
const actions = computed(() => setup.value?.playbook?.actions ?? [])
/** What the group policy allows (no policy yet = every playbook action, as the Recommendation does today). */
const groupAllowed = computed(() => setup.value?.group?.allowedActions ?? actions.value.map((a) => a.code))
const groupSteps = computed(() => (setup.value?.group?.notes ?? []).flatMap((n) => n.split('\n')).map((s) => s.trim()).filter(Boolean))
const hasPolicy = computed(() => !!group.value?.policy)
const editing = ref(false)
const selected = ref<string[]>([])
const steps = ref('')
const busy = ref(false)
const error = ref('')
const editable = computed(() => props.canEdit && !closed.value && actions.value.length > 0)
function resetPolicy() {
  selected.value = [...groupAllowed.value]
  steps.value = groupSteps.value.join('\n')
}
const message = (code: string, prefix: string) => (hasMsg(`${prefix}.err.${code}`) ? t(`${prefix}.err.${code}` as MsgKey) : null)

async function saveGroup() {
  if (busy.value || !selected.value.length) return
  busy.value = true
  error.value = ''
  try {
    await incidentsApi.saveGroupGuidance(props.incidentId, selected.value, steps.value.trim() || null)
    editing.value = false
    await load()
    emit('changed', t('grp.policySaved', { group: currentGroup.value ?? '' }))
  } catch (e) {
    error.value = message((e as { code?: string }).code ?? '', 'rgd') ?? workflowError(e)
  } finally {
    busy.value = false
  }
}
async function saveCaseException() {
  if (busy.value || !selected.value.length) return
  busy.value = true
  error.value = ''
  try {
    await incidentsApi.setCaseGuidance(props.incidentId, selected.value, steps.value.trim() || null)
    editing.value = false
    await load()
    emit('changed', t('rgd.doneCase'))
  } catch (e) {
    error.value = message((e as { code?: string }).code ?? '', 'rgd') ?? workflowError(e)
  } finally {
    busy.value = false
  }
}
async function clearCaseException() {
  if (busy.value) return
  busy.value = true
  try {
    await incidentsApi.clearCaseGuidance(props.incidentId)
    await load()
    emit('changed', t('rgd.doneCleared'))
  } catch (e) {
    error.value = workflowError(e)
  } finally {
    busy.value = false
  }
}

</script>

<template>
  <section class="rounded-xl border border-slate-200 bg-white p-4" aria-labelledby="grp-title">
    <p v-if="loadError" class="text-xs text-rose-700" role="alert">{{ loadError }}</p>
    <template v-else-if="sev && setup">
      <!-- 1. the group -->
      <div class="flex flex-wrap items-start gap-3">
        <Layers class="mt-0.5 size-5 text-slate-400" />
        <div class="min-w-0 flex-1">
          <p class="text-xs text-slate-500">{{ t('grp.label') }}</p>
          <h2 id="grp-title" class="text-lg font-semibold text-slate-900">{{ currentGroup ?? t('grp.none') }}</h2>
          <p v-if="setup.typeSource === 'MITRE'" class="text-[11px] text-slate-500">{{ t('grp.typeFromMitreAdd') }}</p>
        </div>
        <button
          v-if="editable && !editing && currentGroup"
          type="button"
          class="rounded-lg bg-navy-800 px-3 py-2 text-xs font-semibold text-white hover:bg-navy-700"
          @click="resetPolicy(); editing = true"
        >{{ t('grp.define') }}</button>
      </div>

      <dl v-if="currentGroup" class="mt-3 grid grid-cols-2 gap-3 rounded-lg bg-slate-50 p-3 text-sm sm:grid-cols-4">
        <div>
          <dt class="text-xs text-slate-500">{{ t('grp.count') }}</dt>
          <dd class="mt-0.5 font-semibold text-slate-900">{{ t('grp.cases', { n: members.length }) }} <span class="text-xs font-normal text-slate-500">{{ t('grp.open', { n: openCount }) }}</span></dd>
        </div>
        <div>
          <dt class="text-xs text-slate-500">Policy</dt>
          <dd class="mt-0.5 font-semibold" :class="hasPolicy ? 'text-emerald-700' : 'text-amber-700'">{{ hasPolicy ? t('grp.configured') : t('grp.notConfigured') }}</dd>
        </div>
        <div>
          <dt class="text-xs text-slate-500">{{ t('grp.owner') }}</dt>
          <dd class="mt-0.5 text-slate-800">{{ t('grp.ownerSoc') }}</dd>
        </div>
        <div>
          <dt class="text-xs text-slate-500">{{ t('grp.updated') }}</dt>
          <dd class="mt-0.5 text-slate-800">{{ group?.policy ? t('grp.updatedAt', { at: formatDateTime(group.policy.updatedAt), v: group.policy.version }) : '—' }}</dd>
        </div>
      </dl>

      <div v-if="currentGroup" class="mt-3">
        <p class="text-xs font-semibold text-slate-600">{{ t('grp.members') }}</p>
        <ul class="mt-1 divide-y divide-slate-100">
          <li v-for="m in members" :key="m.id">
            <RouterLink :to="{ name: 'incident-detail', params: { id: m.id } }" class="flex flex-wrap items-center gap-x-3 gap-y-0.5 py-1.5 text-xs hover:bg-slate-50" :class="m.id === incidentId ? 'bg-sky-50/60' : ''">
              <span class="font-mono text-slate-500">{{ incidentLabel(m.id) }}</span>
              <span class="min-w-0 flex-1 truncate text-slate-800">{{ m.title }}</span>
              <span v-if="m.id === incidentId" class="rounded bg-sky-100 px-1.5 py-0.5 text-[11px] font-semibold text-sky-800">{{ t('oi.current') }}</span>
              <StatusPill :status="m.status" />
            </RouterLink>
          </li>
        </ul>
      </div>

      <!-- 2. the group's Response Policy -->
      <div v-if="currentGroup" class="mt-5 border-t border-slate-100 pt-4">
        <h3 class="text-sm font-semibold text-slate-800">{{ t('grp.policyTitle', { group: currentGroup }) }}</h3>
        <p v-if="!setup.playbook" class="mt-1 text-sm text-slate-500">{{ t('rgd.noPlaybook') }}</p>

        <!-- read view -->
        <div v-else-if="!editing" class="mt-2 grid gap-4 sm:grid-cols-3">
          <div>
            <p class="text-xs font-semibold text-emerald-700">{{ t('grp.allowed') }}</p>
            <ul class="mt-1 space-y-0.5 text-sm text-slate-800">
              <li v-for="a in actions.filter((x) => groupAllowed.includes(x.code))" :key="a.code" class="flex items-start gap-1.5"><Check class="mt-0.5 size-3.5 shrink-0 text-emerald-600" />{{ a.name }}</li>
            </ul>
          </div>
          <div>
            <p class="text-xs font-semibold text-rose-700">{{ t('grp.forbidden') }}</p>
            <ul class="mt-1 space-y-0.5 text-sm text-slate-800">
              <li v-for="a in actions.filter((x) => !groupAllowed.includes(x.code))" :key="a.code" class="flex items-start gap-1.5"><X class="mt-0.5 size-3.5 shrink-0 text-rose-600" />{{ a.name }}</li>
              <li v-if="actions.every((x) => groupAllowed.includes(x.code))" class="text-xs text-slate-400">{{ t('grp.noneForbidden') }}</li>
            </ul>
          </div>
          <div>
            <p class="text-xs font-semibold text-slate-700">{{ t('grp.first') }}</p>
            <ol v-if="groupSteps.length" class="mt-1 list-decimal space-y-0.5 pl-5 text-sm text-slate-800"><li v-for="s in groupSteps" :key="s">{{ s }}</li></ol>
            <p v-else class="mt-1 text-xs text-slate-400">{{ t('grp.noSteps') }}</p>
          </div>
          <p v-if="!hasPolicy" class="text-xs text-amber-700 sm:col-span-3">{{ t('grp.defaultNote') }}</p>
        </div>

        <!-- edit view -->
        <div v-else class="mt-2">
          <p class="text-xs text-slate-500">{{ t('grp.editHint') }}</p>
          <ul class="mt-2 divide-y divide-slate-100 rounded-lg border border-slate-200">
            <li v-for="a in actions" :key="a.code" class="flex flex-wrap items-center gap-2 px-3 py-2 text-sm">
              <span class="min-w-0 flex-1 text-slate-800">{{ a.name }}</span>
              <span class="inline-flex overflow-hidden rounded-lg border border-slate-200 text-xs" role="radiogroup" :aria-label="a.name">
                <button type="button" role="radio" :aria-checked="selected.includes(a.code)" class="px-2.5 py-1" :class="selected.includes(a.code) ? 'bg-emerald-600 font-semibold text-white' : 'bg-white text-slate-600'" :disabled="busy" @click="selected = [...new Set([...selected, a.code])]">{{ t('grp.allow') }}</button>
                <button type="button" role="radio" :aria-checked="!selected.includes(a.code)" class="px-2.5 py-1" :class="!selected.includes(a.code) ? 'bg-rose-600 font-semibold text-white' : 'bg-white text-slate-600'" :disabled="busy" @click="selected = selected.filter((c) => c !== a.code)">{{ t('grp.forbid') }}</button>
              </span>
            </li>
          </ul>
          <label class="mt-3 block text-xs font-semibold text-slate-700">{{ t('grp.first') }} <span class="font-normal text-slate-500">{{ t('grp.firstHint') }}</span>
            <textarea v-model="steps" rows="3" maxlength="2000" :disabled="busy" :placeholder="t('grp.firstPlaceholder')" class="mt-1 w-full rounded-lg border border-slate-300 p-2 text-sm font-normal" />
          </label>
          <p v-if="!selected.length" class="mt-1 text-xs text-rose-700">{{ t('rgd.pickOne') }}</p>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <button type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:opacity-50" :disabled="busy || !selected.length" @click="saveGroup">
              <Loader2 v-if="busy" class="mr-1 inline size-3.5 animate-spin" />{{ t('grp.saveGroup', { group: currentGroup }) }}
            </button>
            <button type="button" class="rounded-lg border border-slate-300 px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50" :disabled="busy" @click="editing = false; resetPolicy()">{{ t('c.cancel') }}</button>
            <button type="button" class="ml-auto text-xs text-slate-500 underline hover:text-slate-800 disabled:opacity-50" :disabled="busy || !selected.length" @click="saveCaseException">{{ t('grp.saveCase') }}</button>
          </div>
        </div>

        <p v-if="setup.caseGuidance" class="mt-3 rounded bg-violet-50 px-3 py-2 text-xs text-violet-900">
          {{ t('grp.caseException') }}
          <button v-if="editable" type="button" class="ml-1 underline disabled:opacity-50" :disabled="busy" @click="clearCaseException">{{ t('grp.clearCase') }}</button>
        </p>
        <p v-if="error" class="mt-2 rounded bg-rose-50 px-2 py-1 text-xs text-rose-700" role="alert">{{ error }}</p>
        <p v-if="!canEdit" class="mt-2 text-xs text-slate-400">{{ t('grp.socOnly') }}</p>
      </div>

    </template>
    <p v-else class="text-xs text-slate-500">{{ t('c.loading') }}</p>
  </section>
</template>
