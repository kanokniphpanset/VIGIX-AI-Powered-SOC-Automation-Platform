<script setup lang="ts">
// Overview: every incident that is not closed yet (closed = resolved / dismissed, as in the backend), most severe first,
// then newest. A row opens the incident; the current incident is marked, not hidden.
// "+ Add Group" (SOC): pick a group (type + severity) and tick incidents to move into it. Each move uses the same audited
// endpoints as the grouping control of the incident page (severity-validation, incident-type) - nothing else is changed.
import { computed, onMounted, ref, watch } from 'vue'
import { Loader2, Plus } from 'lucide-vue-next'
import SeverityBadge from '@/components/common/SeverityBadge.vue'
import StatusPill from '@/components/common/StatusPill.vue'
import { incidentsApi, type Incident, type ResponseSetup } from '@/api/vigix'
import { formatDateTime, SEVERITY_LABEL } from '@/utils/formatters'
import { incidentLabel, toSeverity } from '@/utils/vigix'
import { workflowError } from '@/utils/workflow'
import type { Severity } from '@/types'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

const props = defineProps<{ currentId: string; canGroup?: boolean }>()
const emit = defineEmits<{ grouped: [message: string] }>()
const { t } = useI18n()

const CLOSED = ['resolved', 'dismissed']
const RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
const LEVELS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PAGE = 200

const items = ref<Incident[] | null>(null)
const failed = ref(false)

async function load() {
  failed.value = false
  try {
    const all: Incident[] = []
    for (;;) {
      const r = await incidentsApi.list(PAGE, all.length)
      all.push(...r.items)
      if (!r.items.length || all.length >= r.total) break
    }
    items.value = all.filter((i) => !CLOSED.includes(i.status))
  } catch {
    failed.value = true
    items.value = []
  }
}
onMounted(load)
watch(() => props.currentId, load)

const sorted = computed(() => [...(items.value ?? [])].sort((a, b) =>
  (RANK[toSeverity(a.priority)] ?? 9) - (RANK[toSeverity(b.priority)] ?? 9) || b.openedAt.localeCompare(a.openedAt)))

// ---- + Add Group -----------------------------------------------------------------------------------------------------------
const grouping = ref(false)
const types = ref<ResponseSetup['types']>([])
const typeChoice = ref('')
const sevChoice = ref<Severity>('CRITICAL')
const reason = ref('')
const picked = ref<string[]>([])
const busy = ref(false)
const result = ref<{ ok: string[]; failed: { id: string; error: string }[] } | null>(null)
const typeLabel = (type: string) => (hasMsg(`iaf.type.${type}`) ? t(`iaf.type.${type}` as MsgKey) : type)
const groupName = computed(() => (typeChoice.value ? `${typeLabel(typeChoice.value)} · ${SEVERITY_LABEL[sevChoice.value]}` : ''))

async function startGrouping() {
  grouping.value = true
  result.value = null
  picked.value = []
  reason.value = ''
  let currentType: string | null = null
  try {
    const setup = await incidentsApi.responseSetup(props.currentId)
    types.value = setup.types
    currentType = setup.incidentType
  } catch { /* keep the list we have */ }
  // start from the group of the incident being viewed
  typeChoice.value = typeChoice.value || currentType || types.value[0]?.incidentType || ''
}
function toggle(id: string) {
  picked.value = picked.value.includes(id) ? picked.value.filter((x) => x !== id) : [...picked.value, id]
}
const errorText = (e: unknown) => {
  const code = (e as { code?: string }).code ?? ''
  return hasMsg(`sv.err.${code}`) ? t(`sv.err.${code}` as MsgKey) : workflowError(e)
}
async function moveIntoGroup() {
  if (busy.value || !picked.value.length || !typeChoice.value) return
  busy.value = true
  const ok: string[] = []
  const bad: { id: string; error: string }[] = []
  for (const id of picked.value) {
    const inc = items.value?.find((i) => i.id === id)
    try {
      if (inc && toSeverity(inc.priority) !== sevChoice.value) await incidentsApi.validateSeverity(id, sevChoice.value, reason.value.trim() || null)
      await incidentsApi.setIncidentType(id, typeChoice.value)
      ok.push(id)
    } catch (e) {
      bad.push({ id, error: errorText(e) })
    }
  }
  result.value = { ok, failed: bad }
  busy.value = false
  await load()
  if (ok.length) {
    picked.value = bad.map((b) => b.id)
    emit('grouped', t('oi.grp.done', { n: ok.length, group: groupName.value }))
  }
}
</script>

<template>
  <section class="rounded-xl border border-slate-200 p-4" :aria-label="t('oi.title')">
    <div class="flex flex-wrap items-center justify-between gap-2">
      <h3 class="text-sm font-semibold text-slate-800">{{ t('oi.title') }}</h3>
      <div class="flex items-center gap-3">
        <span v-if="items" class="text-xs text-slate-500">{{ t('oi.count', { n: items.length }) }}</span>
        <button
          v-if="canGroup && !grouping"
          type="button"
          class="inline-flex items-center gap-1 rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700"
          @click="startGrouping"
        ><Plus class="size-3.5" /> Add Group</button>
      </div>
    </div>

    <!-- Add Group: choose the group, tick the incidents to move into it -->
    <div v-if="grouping" class="mt-3 rounded-lg border border-sky-200 bg-sky-50/50 p-3 text-sm">
      <p class="text-xs text-slate-600">{{ t('oi.grp.hint') }}</p>
      <div class="mt-2 flex flex-wrap items-center gap-2">
        <label class="text-xs text-slate-600">{{ t('rs.type') }}
          <select v-model="typeChoice" class="ml-1 rounded-lg border border-slate-300 px-2 py-1 text-sm" :disabled="busy">
            <option v-for="ty in types" :key="ty.incidentType" :value="ty.incidentType">{{ typeLabel(ty.incidentType) }}</option>
          </select>
        </label>
        <label class="text-xs text-slate-600">{{ t('sv.select') }}
          <select v-model="sevChoice" class="ml-1 rounded-lg border border-slate-300 px-2 py-1 text-sm" :disabled="busy">
            <option v-for="l in LEVELS" :key="l" :value="l">{{ SEVERITY_LABEL[l] }}</option>
          </select>
        </label>
        <input v-model="reason" :placeholder="t('grp.reason')" class="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-1 text-sm sm:min-w-56" :disabled="busy" />
      </div>
      <div class="mt-2 flex flex-wrap items-center gap-2">
        <button type="button" class="rounded-lg bg-navy-800 px-3 py-1.5 text-xs font-semibold text-white hover:bg-navy-700 disabled:opacity-50" :disabled="busy || !picked.length || !typeChoice" @click="moveIntoGroup">
          <Loader2 v-if="busy" class="mr-1 inline size-3.5 animate-spin" />{{ t('oi.grp.move', { n: picked.length, group: groupName }) }}
        </button>
        <button type="button" class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs text-slate-700 hover:bg-slate-50" :disabled="busy" @click="grouping = false; picked = []">{{ t('c.cancel') }}</button>
        <span class="text-xs text-slate-500">{{ t('oi.grp.picked', { n: picked.length }) }}</span>
      </div>
      <div v-if="result" class="mt-2 space-y-1 text-xs">
        <p v-if="result.ok.length" class="rounded bg-emerald-50 px-2 py-1 text-emerald-800">{{ t('oi.grp.done', { n: result.ok.length, group: groupName }) }} — {{ t('oi.grp.next') }}</p>
        <p v-for="f in result.failed" :key="f.id" class="rounded bg-rose-50 px-2 py-1 text-rose-700">{{ incidentLabel(f.id) }}: {{ f.error }}</p>
      </div>
    </div>

    <p v-if="items === null" class="mt-3 flex items-center gap-1.5 text-xs text-slate-500"><Loader2 class="size-3.5 animate-spin" /> {{ t('c.loading') }}</p>
    <p v-else-if="failed" class="mt-3 text-xs text-rose-600">{{ t('oi.failed') }}</p>
    <p v-else-if="!items.length" class="mt-3 text-xs text-slate-500">{{ t('oi.none') }}</p>

    <ul v-else class="mt-2 divide-y divide-slate-100">
      <li v-for="i in sorted" :key="i.id" class="flex items-center gap-2" :class="i.id === currentId ? 'bg-sky-50/60' : ''">
        <input
          v-if="grouping"
          type="checkbox"
          class="ml-1 shrink-0"
          :checked="picked.includes(i.id)"
          :disabled="busy"
          :aria-label="t('oi.grp.pick', { id: incidentLabel(i.id) })"
          @change="toggle(i.id)"
        />
        <RouterLink
          :to="{ name: 'incident-detail', params: { id: i.id } }"
          class="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1 py-2 hover:bg-slate-50"
          :aria-current="i.id === currentId ? 'page' : undefined"
        >
          <SeverityBadge :severity="toSeverity(i.priority)" size="sm" />
          <span class="min-w-0 flex-1">
            <span class="block text-sm text-slate-900">{{ i.title }}</span>
            <span class="text-[11px] text-slate-500"><span class="font-mono">{{ incidentLabel(i.id) }}</span> · {{ t('oi.opened', { at: formatDateTime(i.openedAt) }) }}</span>
          </span>
          <span v-if="i.id === currentId" class="rounded bg-sky-100 px-1.5 py-0.5 text-[11px] font-semibold text-sky-800">{{ t('oi.current') }}</span>
          <StatusPill :status="i.status" />
        </RouterLink>
      </li>
    </ul>
  </section>
</template>
