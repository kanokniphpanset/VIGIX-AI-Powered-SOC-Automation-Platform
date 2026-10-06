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
import { knowledgeApi, playbookVersionsApi, type MitreTechnique, type Playbook, type Policy, type Runbook } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { playbookLifecycle, type PlaybookLifecycle } from '@/utils/playbookLifecycle'
import { useSessionStore } from '@/stores/session'
import { useI18n, type MsgKey } from '@/i18n'
import { hasMsg } from '@/i18n/messages'

/**
 * Knowledge (read-only). Lists the libraries VIGIX already uses to build recommendations and evaluate Policy, straight
 * from the backend's existing list endpoints. No CRUD yet and nothing invented: a library without an endpoint (threat
 * intelligence) shows an empty state.
 */
type Key = 'playbooks' | 'policies' | 'runbooks' | 'actions' | 'threat-intel' | 'mitre'
interface Row { id: string; code: string; name: string; meta: string; description: string | null; status?: string; version?: string }

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
      r.items.map((p: Playbook) => ({ id: p.id, code: p.code, name: p.name, get meta() { return [t('kb.steps', { v: p.version, n: p.steps?.length ?? 0 }), typeof p.triggerConditions?.incidentType === 'string' ? p.triggerConditions.incidentType : null].filter(Boolean).join(' · ') }, description: p.description, status: p.status, version: p.version }))),
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
  await loadLifecycles()
  loading.value = false
}
onMounted(load)

// Playbook versions (Draft → Publish, no approval step): status and buttons per row from its version history.
const lifecycles = ref<Record<string, PlaybookLifecycle>>({})
async function loadLifecycles() {
  const list = rows.value.playbooks ?? []
  const entries = await Promise.all(list.map(async (r) => {
    try { return [r.id, playbookLifecycle((await playbookVersionsApi.list(r.id)).items, session.role, r.version)] as const } catch { return null }
  }))
  lifecycles.value = Object.fromEntries(entries.filter((e): e is NonNullable<typeof e> => !!e))
}
const lifecycleOf = (r: Row) => lifecycles.value[r.id]
const can = (r: Row, action: PlaybookLifecycle['actions'][number]) => !!lifecycleOf(r)?.actions.includes(action)
/** A plain 403 on a playbook action reads "you are not allowed to manage this playbook". */
const playbookAction = (fn: () => Promise<unknown>) => async () => {
  try { return await fn() } catch (e) {
    if (e instanceof ApiError && e.status === 403 && e.code === 'FORBIDDEN') throw Object.assign(new Error('forbidden'), { code: 'PLAYBOOK_FORBIDDEN' })
    throw e
  }
}


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
const playbookForm = ref<{ open: boolean; id: string | null; revisionId: string | null }>({ open: false, id: null, revisionId: null })
const playbookCodes = computed(() => (rows.value.playbooks ?? []).map((r) => r.code))
async function playbookSaved(code: string, created: boolean) {
  playbookForm.value = { open: false, id: null, revisionId: null }
  ui.success(t(created ? 'pbf.created' : 'pbl.draftSaved', { code }))
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
// Runbooks / Policies / Actions are configuration: the admin role creates them (backend requireAdmin()), via the same
// "+ Add" button in the library header as Playbooks.
const isAdminManaged = computed(() => (['runbooks', 'policies', 'actions'] as Key[]).includes(active.value))
const canManageCatalog = computed(() => session.role === 'admin')
const subtitle = computed(() => {
  if (active.value === 'playbooks') return t(canManagePlaybooks.value ? 'pbl.managed' : 'pb.readOnlyRole')
  if (isAdminManaged.value) return canManageCatalog.value ? t('kbc.managed') : t('kbc.readOnlyRole', { lib: current.value.label })
  return t('kb.readOnly')
})
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
    <div v-if="active === 'policies'" class="mb-4 flex flex-wrap gap-2">
      <BackendForm :label="t('kb.evaluate')" :fields="evaluationFields" :action="evaluate" :reload="async () => {}" :description="t('kb.evaluateHint')" />
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
          <p class="text-xs text-slate-500">{{ subtitle }}</p>
        </div>
        <button v-if="active === 'playbooks' && canManagePlaybooks" type="button" class="btn-primary ml-auto sm:order-last" @click="playbookForm = { open: true, id: null, revisionId: null }">{{ t('pb.add') }}</button>
        <div v-else-if="isAdminManaged && canManageCatalog" class="ml-auto sm:order-last"><KnowledgeControls :key="active" :library="active as 'runbooks' | 'policies' | 'actions'" :reload="reloadLibrary" /></div>
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
            <p v-if="active === 'playbooks' && lifecycleOf(r)?.state === 'PUBLISHED' && lifecycleOf(r)?.draft" class="mt-1 text-[11px] font-medium text-amber-700">{{ t('pbl.draftOf', { v: lifecycleOf(r)!.draft!.version }) }}</p>
          </div>
          <span v-if="active === 'playbooks' && lifecycleOf(r)" class="flex flex-col items-end gap-0.5 text-right" data-testid="playbook-state">
            <span
              class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset"
              :class="lifecycleOf(r)!.state === 'PUBLISHED' ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-amber-50 text-amber-800 ring-amber-200'"
            >{{ lifecycleOf(r)!.state === 'PUBLISHED' ? t('pbl.published') : t('pbl.draft') }} · {{ t('pbl.version', { v: lifecycleOf(r)!.version }) }}</span>
            <span class="text-[11px] text-slate-500">{{ lifecycleOf(r)!.state === 'DRAFT' ? t('pbl.draftHint') : r.status === 'DEPRECATED' ? t('pbl.publishedOff') : t('pbl.publishedHint') }}</span>
          </span>
          <span
            v-else-if="r.status"
            class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset"
            :class="r.status.toLowerCase() === 'active' ? 'bg-emerald-50 text-emerald-700 ring-emerald-200' : 'bg-slate-100 text-slate-500 ring-slate-200'"
          >{{ statusText(r.status) }}</span>
          <span v-if="active === 'playbooks' && lifecycleOf(r)" class="contents" @click.stop>
            <button v-if="lifecycleOf(r)!.state === 'PUBLISHED'" type="button" class="btn-secondary" @click="openDetail(r)">{{ t('pbl.view') }}</button>
            <button v-if="can(r, 'edit')" type="button" class="btn-secondary" :aria-label="t('pbl.editAria', { name: r.name })" @click="playbookForm = { open: true, id: r.id, revisionId: lifecycleOf(r)!.draft!.id }">{{ t('pbl.edit') }}</button>
            <WorkflowAction
              v-if="can(r, 'publish')"
              :key="`publish-${lifecycleOf(r)!.draft!.id}`"
              :label="t('pbl.publish')"
              :success-label="t('pbl.publishOk', { code: r.code, v: lifecycleOf(r)!.draft!.version })"
              :action="playbookAction(() => playbookVersionsApi.publish(r.id, lifecycleOf(r)!.draft!.id))"
              :reload="reloadLibrary"
            ><p class="text-sm text-slate-600">{{ t('pbl.publishHint', { v: lifecycleOf(r)!.draft!.version }) }}</p></WorkflowAction>
            <WorkflowAction
              v-if="can(r, 'createVersion')"
              :key="`version-${r.id}-${lifecycleOf(r)!.version}`"
              :label="t('pbl.createVersion')"
              :success-label="t('pbl.createVersionOk', { code: r.code })"
              :action="playbookAction(() => playbookVersionsApi.createVersion(r.id))"
              :reload="reloadLibrary"
            ><p class="text-sm text-slate-600">{{ t('pbl.createVersionHint') }}</p></WorkflowAction>
            <WorkflowAction
              v-if="can(r, 'rollback')"
              :key="`rollback-${r.id}-${lifecycleOf(r)!.version}`"
              :label="t('pbl.rollback')"
              :success-label="t('pbl.rollbackOk', { code: r.code, v: lifecycleOf(r)!.rollbackTo!.version })"
              :action="playbookAction(() => playbookVersionsApi.rollback(r.id, lifecycleOf(r)!.rollbackTo!.id))"
              :reload="reloadLibrary"
            ><p class="text-sm text-slate-600">{{ t('pbl.rollbackHint', { v: lifecycleOf(r)!.rollbackTo!.version, cur: lifecycleOf(r)!.version }) }}</p></WorkflowAction>
          </span>
          <KnowledgeDeleteButton v-if="active === 'policies' && canDeletePolicies" library="policies" :id="r.id" :code="r.code" :name="r.name" :enabled="r.status === 'active'" @deleted="(code) => knowledgeDeleted('pol.deleted', code)" />
          <KnowledgeDeleteButton v-if="active === 'playbooks' && can(r, 'delete')" library="playbooks" :id="r.id" :code="r.code" :name="r.name" :enabled="false" @deleted="(code) => knowledgeDeleted('pbd.deleted', code)" />
        </li>
      </ul>
    </section>

    <KnowledgeControls v-if="detailRow" :key="`${detailRow.library}-${detailRow.id}`" :library="detailRow.library" :id="detailRow.id" :reload="reloadLibrary" auto-open @closed="detailRow = null" />
    <PlaybookFormModal
      :open="playbookForm.open"
      :playbook-id="playbookForm.id"
      :revision-id="playbookForm.revisionId"
      :existing-codes="playbookCodes"
      @close="playbookForm = { open: false, id: null, revisionId: null }"
      @saved="playbookSaved"
    />
  </div>
</template>
