<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import Modal from '@/components/common/Modal.vue'
import { knowledgeApi, type Runbook } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { useI18n } from '@/i18n'
import { mutate, mutationState, workflowError } from '@/utils/workflow'
import { actionGovernanceBody, canSetActionGovernance, initialActionGovernance } from '@/utils/actionForm'

const props = defineProps<{ id?: string; initial?: Record<string, unknown>; reload: () => Promise<unknown> }>()
const { t } = useI18n()
const session = useSessionStore()
const ui = useUiStore()
const canManage = computed(() => ['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? ''))
// impactLevel / defaultApprovalRequired feed the approval policy: admin only (backend: ACTION_GOVERNANCE_FIELD_FORBIDDEN).
const governanceLocked = computed(() => !canSetActionGovernance(session.role ?? null))
const open = ref(false)
const loading = ref(false)
const loadError = ref('')
const runbooks = ref<Runbook[]>([])
const state = reactive(mutationState())
const form = reactive({ code: '', name: '', description: '', category: 'INVESTIGATION', impactLevel: 'LOW', defaultApprovalRequired: false, runbookId: '' })
const selected = computed(() => runbooks.value.find(r => r.id === form.runbookId))
const unavailable = computed(() => !!form.runbookId && !selected.value)
const title = computed(() => props.id ? t('af.editTitle', { code: form.code }) : t('kbc.addTitle.actions'))
async function loadRunbooks() {
  loading.value = true; loadError.value = ''
  try { runbooks.value = (await knowledgeApi.runbooks()).items.sort((a, b) => a.code.localeCompare(b.code)) }
  catch (e) { loadError.value = workflowError(e) }
  finally { loading.value = false }
}
async function begin() {
  if (!canManage.value || state.busy) return
  open.value = true
  if (state.saved && !state.success) return
  Object.assign(state, mutationState())
  const r = props.initial ?? {}
  Object.assign(form, { code: String(r.code ?? ''), name: String(r.name ?? ''), description: String(r.description ?? ''), category: String(r.category ?? 'INVESTIGATION'), ...initialActionGovernance(session.role ?? null, !props.id, r), runbookId: String(r.runbookId ?? '') })
  await loadRunbooks()
}
function describe(e: unknown) {
  const code = (e as { code?: string })?.code
  if (code === 'RUNBOOK_NOT_FOUND') return t('af.missingRunbook')
  if (code === 'ACTION_RUNBOOK_TENANT_MISMATCH') return t('af.tenantMismatch')
  if (code === 'DUPLICATE_CODE') return t('af.duplicateCode')
  if (code === 'ACTION_GOVERNANCE_FIELD_FORBIDDEN') return t('af.governanceForbidden')
  return workflowError(e)
}
async function save() {
  if (!canManage.value || loading.value || loadError.value || state.busy) return
  if (!form.name.trim()) { state.error = t('form.required', { label: t('kbc.f.name') }); return }
  const body: Record<string, unknown> = { name: form.name.trim(), description: form.description.trim() || null, ...actionGovernanceBody(session.role ?? null, !props.id, form) }
  // Preserve an unavailable existing link on unrelated edits; selecting None explicitly removes it.
  if (!props.id || form.runbookId !== String(props.initial?.runbookId ?? '')) body.runbookId = form.runbookId || null
  if (!props.id) { body.code = form.code.trim(); body.category = form.category }
  if (await mutate(state, () => props.id ? knowledgeApi.update('actions', props.id, body) : knowledgeApi.create('actions', body), props.reload, describe)) {
    open.value = false
    ui.success(t('af.saved'))
  }
}
</script>

<template>
  <button v-if="canManage" type="button" :class="id ? 'btn-secondary' : 'btn-primary'" @click="begin">{{ id ? t('kbc.edit') : t('kbc.add.actions') }}</button>
  <Modal :open="open" :title="title" size="lg" @close="!state.busy && (open = false)">
    <form class="space-y-4 text-sm" @submit.prevent="save">
      <fieldset :disabled="state.busy || state.saved" class="grid gap-4 sm:grid-cols-2">
        <label class="block">{{ t('kbc.f.code') }} *<input v-model="form.code" class="action-input font-mono" required pattern="[A-Z0-9-]+" :disabled="!!id" /></label>
        <label class="block">{{ t('kbc.f.name') }} *<input v-model="form.name" class="action-input" required /></label>
        <label class="block sm:col-span-2">{{ t('kbc.f.description') }}<textarea v-model="form.description" class="action-input" rows="3" /></label>
        <label class="block">{{ t('kbc.f.category') }}<select v-model="form.category" class="action-input" :disabled="!!id"><option v-for="v in ['CONTAINMENT', 'INVESTIGATION', 'VERIFICATION']" :key="v">{{ v }}</option></select></label>
        <label class="block">{{ t('kbc.f.impact') }}<select v-model="form.impactLevel" class="action-input" :disabled="governanceLocked"><option v-for="v in ['LOW', 'MEDIUM', 'HIGH']" :key="v">{{ v }}</option></select></label>
        <label class="flex items-center gap-2 sm:col-span-2"><input v-model="form.defaultApprovalRequired" type="checkbox" :disabled="governanceLocked" />{{ t('kbc.f.defaultApproval') }}</label>
        <p v-if="governanceLocked" class="sm:col-span-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">{{ t(id ? 'af.governanceEditLocked' : 'af.governanceCreateLocked') }}</p>
        <div class="sm:col-span-2 space-y-2">
          <label class="block">{{ t('af.runbook') }}
            <select v-model="form.runbookId" class="action-input" :disabled="loading || !!loadError">
              <option value="">{{ t('af.noRunbook') }}</option>
              <option v-if="unavailable" :value="form.runbookId" disabled>{{ t('af.unavailable') }}</option>
              <option v-for="r in runbooks" :key="r.id" :value="r.id">{{ r.code }} — {{ r.name }} · v{{ r.version }} · {{ r.status }}</option>
            </select>
          </label>
          <p v-if="loading" role="status" class="text-slate-500">{{ t('c.loading') }}</p>
          <p v-else-if="loadError" role="alert" class="text-rose-700">{{ loadError }} <button type="button" class="underline" @click="loadRunbooks">{{ t('c.retry') }}</button></p>
          <p v-else-if="!runbooks.length" class="text-slate-500">{{ t('af.emptyRunbooks') }}</p>
          <div v-if="selected" class="rounded-lg bg-slate-50 p-3 text-slate-600"><strong>{{ selected.name }}</strong><p v-if="selected.objective || selected.description" class="mt-1 whitespace-pre-wrap">{{ selected.objective || selected.description }}</p></div>
          <p v-if="unavailable && !loading && !loadError" class="text-amber-700">{{ t('af.keepUnavailable') }}</p>
        </div>
      </fieldset>
      <p v-if="state.error" role="alert" class="rounded-lg bg-rose-50 p-3 text-rose-700">{{ state.error }}</p>
      <div class="flex justify-end gap-2"><button type="button" class="btn-secondary" :disabled="state.busy" @click="open = false">{{ t('c.cancel') }}</button><button class="btn-primary" :disabled="state.busy || loading || !!loadError">{{ state.busy ? t('c.saving') : state.saved ? t('ui.retryRefresh') : t('c.save') }}</button></div>
    </form>
  </Modal>
</template>

<style scoped>
.action-input { display: block; width: 100%; margin-top: .25rem; border: 1px solid #cbd5e1; border-radius: .5rem; padding: .5rem .75rem; }
.action-input:focus { outline: 2px solid #94a3b8; outline-offset: 1px; }
.action-input:disabled { background: #f8fafc; color: #64748b; }
</style>
