<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { BookOpen, Crosshair, FileCheck2, Loader2, ScrollText, Search, ShieldQuestion } from 'lucide-vue-next'
import PageHeader from '@/components/layout/PageHeader.vue'
import EmptyState from '@/components/common/EmptyState.vue'
import KnowledgeControls from '@/components/knowledge/KnowledgeControls.vue'
import KnowledgeValue from '@/components/knowledge/KnowledgeValue.vue'
import BackendForm from '@/components/common/BackendForm.vue'
import type { FormField } from '@/utils/forms'
import PlaybookFormModal from '@/components/knowledge/PlaybookFormModal.vue'
import KnowledgeDeleteButton from '@/components/knowledge/KnowledgeDeleteButton.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import { useUiStore } from '@/stores/ui'
import { knowledgeApi, type MitreTechnique, type Playbook, type Policy, type Runbook } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

/**
 * Knowledge (read-only). Lists the libraries VIGIX already uses to build recommendations and evaluate Policy, straight
 * from the backend's existing list endpoints. No CRUD yet and nothing invented: a library without an endpoint (threat
 * intelligence) shows an empty state.
 */
type Key = 'playbooks' | 'policies' | 'runbooks' | 'actions' | 'threat-intel' | 'mitre'
interface Row { id: string; code: string; name: string; meta: string; description: string | null; status?: string }

const { t } = useI18n()
/** Library tabs; label and blurb are getters so they follow the UI language. */
const LIBRARIES: { key: Key; label: string; icon: typeof BookOpen; blurb: string }[] = ([
  ['actions', FileCheck2], ['playbooks', BookOpen], ['policies', FileCheck2], ['runbooks', ScrollText], ['threat-intel', ShieldQuestion], ['mitre', Crosshair],
] as [Key, typeof BookOpen][]).map(([key, icon]) => ({
  key,
  icon,
  get label() { return t(`kb.lib.${key}` as MsgKey) },
  get blurb() { return t(`kb.lib.${key}.blurb` as MsgKey) },
}))
const statusText = (s: string) => (hasMsg(`kb.${s.toLowerCase()}`) ? t(`kb.${s.toLowerCase()}` as MsgKey) : s.toLowerCase())

const route = useRoute()
const session = useSessionStore()
const router = useRouter()
const active = ref<Key>(LIBRARIES.some((l) => l.key === route.query.section) ? (route.query.section as Key) : 'playbooks')
watch(active, (k) => router.replace({ query: { ...route.query, section: k } }))

const loading = ref(true)
// null = not loaded / no endpoint (shown as "—", never as a fake 0). Threat intelligence has no library endpoint yet.
const rows = ref<Record<Key, Row[] | null>>({ actions: null, playbooks: null, policies: null, runbooks: null, 'threat-intel': null, mitre: null })
const NO_ENDPOINT: Key[] = ['threat-intel']
const failed = ref<Set<Key>>(new Set())
const search = ref('')

async function load() {
  loading.value = true
  const next = new Set<Key>()
  const take = async <T,>(key: Key, p: Promise<T>, map: (v: T) => Row[]) => {
    try {
      rows.value[key] = map(await p)
    } catch {
      rows.value[key] = null
      next.add(key)
    }
  }
  await Promise.all([
    take('actions', knowledgeApi.actions(), r => r.items.map(a => ({ id:a.id,code:a.code,name:a.name,description:a.description,meta:a.category,status:a.enabled?'active':'disabled' }))),
    take('playbooks', knowledgeApi.playbooks(), (r) =>
      r.items.map((p: Playbook) => ({ id: p.id, code: p.code, name: p.name, get meta() { return [t('kb.steps', { v: p.version, n: p.steps?.length ?? 0 }), typeof p.triggerConditions?.incidentType === 'string' ? p.triggerConditions.incidentType : null].filter(Boolean).join(' · ') }, description: p.description, status: p.status }))),
    take('policies', knowledgeApi.policies(), (r) =>
      [...r.items].sort((a, b) => a.precedence - b.precedence).map((p: Policy) => ({
        id: p.id, code: p.code, name: p.name, get meta() { return t('kb.policyMeta', { type: p.type, p: p.precedence, n: p.rules?.length ?? 0, v: p.version }) },
        description: p.description, status: p.enabled ? 'active' : 'disabled',
      }))),
    take('runbooks', knowledgeApi.runbooks(), (r) =>
      r.items.map((b: Runbook) => ({ id: b.id, code: b.code, name: b.name, meta: `v${b.version}`, description: b.objective ?? b.description, status: b.status }))),
    take('mitre', knowledgeApi.techniques(), (r) =>
      r.techniques.map((t: MitreTechnique) => ({ id: t.techniqueId, code: t.techniqueId, name: t.name, meta: t.tactics.join(' · '), description: null }))),
  ])
  failed.value = next
  loading.value = false
}
onMounted(load)


const count = (k: Key) => rows.value[k]?.length ?? null
const current = computed(() => LIBRARIES.find((l) => l.key === active.value)!)
const visible = computed(() => {
  const q = search.value.trim().toLowerCase()
  const list = rows.value[active.value] ?? []
  return q ? list.filter((r) => `${r.code} ${r.name} ${r.meta} ${r.description ?? ''}`.toLowerCase().includes(q)) : list
})
async function reloadLibrary() { await load(); if (failed.value.has(active.value)) throw new Error('Library refresh failed') }
// Playbook management (Knowledge → Playbooks): SOC, IR_TEAM and admin, as the backend enforces. Human-controlled, audited.
const ui = useUiStore()
const canManagePlaybooks = computed(() => ['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? ''))
const playbookForm = ref<{ open: boolean; id: string | null }>({ open: false, id: null })
const playbookCodes = computed(() => (rows.value.playbooks ?? []).map((r) => r.code))
async function playbookSaved(code: string, created: boolean) {
  playbookForm.value = { open: false, id: null }
  ui.success(t(created ? 'pbf.created' : 'pbf.updated', { code }))
  await load() // refresh the list in place (no page reload)
}
// Clicking a row opens its details (libraries with a detail endpoint); buttons inside the row stop the click.
type DetailLibrary = 'playbooks' | 'runbooks' | 'policies' | 'actions'
const DETAIL_LIBRARIES: Key[] = ['playbooks', 'runbooks', 'policies', 'actions']
const hasDetail = computed(() => DETAIL_LIBRARIES.includes(active.value))
const detailRow = ref<{ library: DetailLibrary; id: string } | null>(null)
const openDetail = (r: Row) => { if (hasDetail.value) detailRow.value = { library: active.value as DetailLibrary, id: r.id } }
// Delete (×) for policies and playbooks: SOC / IR_TEAM / admin (backend-enforced; reason required, audited).
const canDeletePolicies = computed(() => ['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? ''))
async function knowledgeDeleted(message: 'pol.deleted' | 'pbd.deleted', code: string) {
  ui.success(t(message, { code }))
  await load()
}
const setPlaybookStatus = (r: Row) => knowledgeApi.update('playbooks', r.id, { status: r.status === 'ACTIVE' ? 'DEPRECATED' : 'ACTIVE' })
const evaluation = ref<Record<string, unknown> | null>(null)
const evaluationFields = computed<FormField[]>(() => [
  {key:'severity',label:t('kb.f.severity'),type:'select',options:['LOW','MEDIUM','HIGH','CRITICAL']},
  {key:'assetCriticality',label:t('kb.f.assetCriticality'),type:'select',options:['LOW','MEDIUM','HIGH','CRITICAL']},
  {key:'actionImpactLevel',label:t('kb.f.actionImpact'),type:'select',options:['LOW','MEDIUM','HIGH','CRITICAL']},
  {key:'verificationResult',label:t('kb.f.verificationResult'),type:'select',options:['RESOLVED','NOT_RESOLVED']},
])
async function evaluate(body: Record<string,unknown>) { evaluation.value = await knowledgeApi.evaluate(body) }
</script>

<template>
  <div>
    <PageHeader :title="t('kb.title')" :description="t('kb.description')" />
    <div class="mb-4 flex flex-wrap gap-2">
      <KnowledgeControls v-if="active === 'playbooks' || active === 'runbooks' || active === 'policies' || active === 'actions'" :key="active" :library="active" :reload="reloadLibrary" />
      <BackendForm v-if="active === 'policies'" :label="t('kb.evaluate')" :fields="evaluationFields" :action="evaluate" :reload="async () => {}" :description="t('kb.evaluateHint')" />
    </div>
    <section v-if="active === 'policies' && evaluation" class="card mb-4 p-4 text-sm"><h2 class="font-semibold">{{ t('kb.evalResult') }}</h2><KnowledgeValue :value="evaluation" /></section>

    <h2 class="mb-3 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('kb.base') }}</h2>
    <div class="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5" role="tablist" :aria-label="t('kb.tabsAria')">
      <button
        v-for="l in LIBRARIES"
        :key="l.key"
        type="button"
        role="tab"
        :aria-selected="active === l.key"
        class="card min-w-0 p-4 text-left transition hover:ring-1 hover:ring-accent-200"
        :class="active === l.key ? 'ring-2 ring-accent-500' : ''"
        @click="active = l.key; search = ''"
      >
        <span class="flex items-center justify-between gap-2">
          <component :is="l.icon" class="size-5" :class="active === l.key ? 'text-accent-600' : 'text-slate-400'" />
          <span class="text-xl font-bold text-slate-900">
            <Loader2 v-if="loading && count(l.key) === null && !failed.has(l.key) && !NO_ENDPOINT.includes(l.key)" class="size-4 animate-spin text-slate-300" />
            <template v-else>{{ count(l.key) ?? '—' }}</template>
          </span>
        </span>
        <span class="mt-2 block truncate text-sm font-semibold text-slate-800">{{ l.label }}</span>
        <span class="mt-0.5 line-clamp-2 block text-xs text-slate-500">{{ l.blurb }}</span>
      </button>
    </div>

    <section class="card mt-5 p-5" :aria-label="current.label">
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 class="text-base font-semibold text-slate-900">{{ current.label }}</h2>
          <p class="text-xs text-slate-500">{{ active === 'playbooks' ? t(canManagePlaybooks ? 'pb.managed' : 'pb.readOnlyRole') : t('kb.readOnly') }}</p>
        </div>
        <button v-if="active === 'playbooks' && canManagePlaybooks" type="button" class="btn-primary ml-auto sm:order-last" @click="playbookForm = { open: true, id: null }">{{ t('pb.add') }}</button>
        <label v-if="(rows[active]?.length ?? 0) > 0" class="relative w-full sm:w-64">
          <Search class="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-slate-400" />
          <input v-model="search" type="search" :placeholder="t('kb.searchIn', { lib: current.label })" :aria-label="t('kb.searchAria', { lib: current.label })" class="w-full rounded-lg border border-slate-300 py-1.5 pl-8 pr-3 text-sm focus:border-accent-500 focus:outline-none" />
        </label>
      </div>

      <p v-if="loading && rows[active] === null && !NO_ENDPOINT.includes(active)" class="flex items-center gap-2 py-8 text-sm text-slate-500" role="status"><Loader2 class="size-4 animate-spin" /> {{ t('c.loading') }}</p>
      <div v-else-if="failed.has(active)" class="rounded-lg bg-rose-50 px-4 py-3 text-sm text-rose-700" role="alert">
        {{ t('kb.loadFailed', { lib: current.label }) }}
        <button type="button" class="ml-2 font-semibold underline" @click="load">{{ t('c.retry') }}</button>
      </div>
      <EmptyState
        v-else-if="!visible.length"
        :title="search ? t('kb.noMatch') : t('kb.empty')"
        :description="NO_ENDPOINT.includes(active) && !search ? t('kb.noTi') : undefined"
      />
      <ul v-else class="divide-y divide-slate-100">
        <li
          v-for="r in visible"
          :key="r.id"
          class="-mx-2 flex flex-wrap items-start gap-x-4 gap-y-1 rounded-lg px-2 py-3"
          :class="hasDetail ? 'cursor-pointer hover:bg-slate-50 focus:bg-slate-50 focus:outline-none' : ''"
          :role="hasDetail ? 'button' : undefined"
          :tabindex="hasDetail ? 0 : undefined"
          :aria-label="hasDetail ? t('kb.rowOpen', { name: r.name }) : undefined"
          @click="openDetail(r)"
          @keydown.enter.self="openDetail(r)"
        >
          <span class="w-28 shrink-0 font-mono text-xs font-semibold text-slate-600">{{ r.code }}</span>
          <div class="min-w-0 flex-1">
            <p class="text-sm font-semibold text-slate-900">{{ r.name }}</p>
            <p v-if="r.description" class="mt-0.5 text-xs text-slate-500">{{ r.description }}</p>
            <p class="mt-0.5 text-[11px] text-slate-400">{{ r.meta }}</p>
          </div>
          <span
            v-if="r.status"
            class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset"
            :class="r.status.toLowerCase() === 'active' ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-slate-200'"
          >{{ statusText(r.status) }}</span>
          <template v-if="active === 'playbooks' && canManagePlaybooks">
            <button type="button" class="btn-secondary" :aria-label="t('pb.editAria', { name: r.name })" @click.stop="playbookForm = { open: true, id: r.id }">{{ t('pb.edit') }}</button>
            <span class="contents" @click.stop><WorkflowAction
              :key="`${r.id}-${r.status}`"
              :label="r.status === 'ACTIVE' ? t('pb.deactivate') : t('pb.activate')"
              :success-label="r.status === 'ACTIVE' ? t('pb.deactivated') : t('pb.activated')"
              :action="() => setPlaybookStatus(r)"
              :reload="reloadLibrary"
            >
              <p class="text-sm text-slate-600">{{ r.status === 'ACTIVE' ? t('pb.deactivateHint') : t('pb.activateHint') }}</p>
            </WorkflowAction></span>
          </template>
          <KnowledgeDeleteButton v-if="active === 'policies' && canDeletePolicies" library="policies" :id="r.id" :code="r.code" :name="r.name" :enabled="r.status === 'active'" @deleted="(code) => knowledgeDeleted('pol.deleted', code)" />
          <KnowledgeDeleteButton v-if="active === 'playbooks' && canManagePlaybooks" library="playbooks" :id="r.id" :code="r.code" :name="r.name" :enabled="r.status === 'ACTIVE'" @deleted="(code) => knowledgeDeleted('pbd.deleted', code)" />
        </li>
      </ul>
    </section>

    <KnowledgeControls v-if="detailRow" :key="`${detailRow.library}-${detailRow.id}`" :library="detailRow.library" :id="detailRow.id" :reload="reloadLibrary" auto-open @closed="detailRow = null" />
    <PlaybookFormModal
      :open="playbookForm.open"
      :playbook-id="playbookForm.id"
      :existing-codes="playbookCodes"
      @close="playbookForm = { open: false, id: null }"
      @saved="playbookSaved"
    />
  </div>
</template>
