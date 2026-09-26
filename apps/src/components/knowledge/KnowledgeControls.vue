<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import BackendForm from '@/components/common/BackendForm.vue'
import WorkflowAction from '@/components/common/WorkflowAction.vue'
import Modal from '@/components/common/Modal.vue'
import KnowledgeValue from './KnowledgeValue.vue'
import { knowledgeApi } from '@/api/vigix'
import { useSessionStore } from '@/stores/session'
import { workflowError } from '@/utils/workflow'
import type { FormField } from '@/utils/forms'
import { useI18n } from '@/i18n'
type Library = 'playbooks' | 'runbooks' | 'policies' | 'actions'
// autoOpen: the details dialog opens on mount (the Knowledge row itself is the trigger — no "View details" button).
const props = defineProps<{ library: Library; id?: string; reload: () => Promise<unknown>; autoOpen?: boolean }>()
const emit = defineEmits<{ closed: [] }>()
const session = useSessionStore()
const { t } = useI18n()
// Catalog / Policy edits are configuration: the admin system role only (backend requireAdmin()).
const canEdit = computed(() => session.role === 'admin')
const record = ref<Record<string, unknown> | null>(null)
const open = ref(false)
const busy = ref(false)
const error = ref('')
async function detail() {
  if (!props.id || busy.value) return
  busy.value = true; open.value = true; error.value = ''
  try { record.value = await knowledgeApi.record(props.library, props.id) } catch (e) { error.value = workflowError(e) } finally { busy.value = false }
}
function close() { open.value = false; emit('closed') }
onMounted(() => { if (props.autoOpen && props.id) void detail() })
async function reload() { await props.reload(); if (props.id) { record.value = await knowledgeApi.record(props.library, props.id) } }
const fields = computed<FormField[]>(() => {
  const create = !props.id
  const common: FormField[] = [ ...(create ? [{ key: 'code', label: t('kbc.f.code'), required: true }] : []),
    { key: 'name', label: t('kbc.f.name'), required: true }, { key: 'description', label: t('kbc.f.description'), type: 'textarea' } ]
  if (props.library === 'policies') return [...common,
    { key: 'precedence', label: t('kbc.f.precedence'), type: 'number' },
    ...(create ? [
      { key: 'type', label: t('kbc.f.type'), type: 'select', required: true, options: ['PRIORITY','ASSIGNMENT','APPROVAL','VERIFICATION','ESCALATION'] },
      { key: 'conditionField', label: t('kbc.f.conditionField'), type: 'select', required: true, options: ['severity','verificationResult','spreadDetected','threatContained'] },
      { key: 'operator', label: t('kbc.f.operator'), type: 'select', required: true, options: ['eq','neq','gte','lte','gt','lt'] },
      { key: 'conditionValue', label: t('kbc.f.conditionValue'), required: true },
      { key: 'responsibleRole', label: t('kbc.f.responsibleRole'), type: 'select', options: ['SOC','IR_TEAM'] },
      { key: 'approvalRequired', label: t('kbc.f.approvalRequired'), type: 'checkbox' },
      { key: 'approvalRole', label: t('kbc.f.approvalRole'), type: 'select', options: ['IR_TEAM'] },
      { key: 'priority', label: t('kbc.f.priority'), type: 'select', options: ['P0','P1','P2','P3'] },
      { key: 'requireNewInvestigation', label: t('kbc.f.requireNewInvestigation'), type: 'checkbox' },
      { key: 'requireEscalation', label: t('kbc.f.requireEscalation'), type: 'checkbox' },
    ] as FormField[] : [])]
  if (props.library === 'actions') return [...common,
    ...(create ? [{ key: 'category', label: t('kbc.f.category'), type: 'select', required: true, options: ['CONTAINMENT','INVESTIGATION','VERIFICATION'] }] as FormField[] : []),
    { key: 'impactLevel', label: t('kbc.f.impact'), type: 'select', required: true, options: ['LOW','MEDIUM','HIGH'] },
    { key: 'defaultApprovalRequired', label: t('kbc.f.defaultApproval'), type: 'checkbox' },
    { key: 'runbookId', label: t('kbc.f.runbookId') }]
  const version: FormField[] = [{ key: 'version', label: t('kbc.f.version') }, ...(!create ? [{key:'status',label:t('kbc.f.status'),type:'select',options:['ACTIVE','DEPRECATED']}] as FormField[] : [])]
  if (props.library === 'playbooks') return [...common, ...version, ...(create ? [{key:'stepTitles',label:t('kbc.f.stepTitles'),type:'lines',required:true}] as FormField[] : [])]
  return [...common, ...version,
    ...['trigger','objective','expectedResult','escalation'].map(key => ({ key, label: key })),
    ...['preconditions','procedure','decisionPoints','verificationCriteria'].map(key => ({key,label:t('kbc.f.lines', { name: key }),type:'lines' as const,required:key==='procedure'}))]
})
const initial = computed(() => Object.fromEntries(Object.entries(record.value ?? {}).map(([k,v]) => [k, Array.isArray(v) && v.every(x => typeof x === 'string') ? v.join('\n') : v])))
async function save(body: Record<string, unknown>) {
  if (!props.id && props.library === 'playbooks') { body.steps = (body.stepTitles as string[]).map((title,i) => ({stepOrder:i+1,title})); delete body.stepTitles }
  if (!props.id && props.library === 'policies') {
    const {conditionField,operator,conditionValue,responsibleRole,approvalRequired,approvalRole,priority,requireNewInvestigation,requireEscalation,...base}=body
    const value = ['spreadDetected','threatContained'].includes(String(conditionField)) ? String(conditionValue)==='true' : conditionValue
    body = { ...base, rules: [{ condition: { field:conditionField,operator,value }, result: {responsibleRole,approvalRequired,approvalRole,priority,requireNewInvestigation,requireEscalation} }] }
  }
  return props.id ? knowledgeApi.update(props.library, props.id, body) : knowledgeApi.create(props.library, body)
}
</script>
<template>
  <!-- Playbooks have their own create / edit form (PlaybookFormModal on the Knowledge page). -->
  <BackendForm v-if="!id && canEdit && library !== 'playbooks'" :key="library" :label="t(`kbc.create.${library}`)" :fields="fields" :action="save" :reload="reload" />
  <button v-else-if="id && !autoOpen" class="btn-secondary" :disabled="busy" @click="detail">{{ busy ? t('c.loading') : t('kbc.viewDetails') }}</button>
  <Modal :open="open" :title="t('kbc.detailsTitle')" size="lg" @close="close">
    <p v-if="error" role="alert" class="text-rose-700">{{ error }} <button type="button" class="underline" @click="detail">{{ t('c.retry') }}</button></p>
    <template v-if="record">
      <h3 class="font-semibold">{{ record.name }}</h3>
      <div class="my-3 text-sm"><KnowledgeValue :value="Object.fromEntries(Object.entries(record).filter(([k]) => !['tenantId','id'].includes(k)))" /></div>
      <div v-if="canEdit && library !== 'playbooks'" class="flex flex-wrap gap-2">
        <BackendForm :key="`${id}-${record.updatedAt}`" :label="t('kbc.edit')" :fields="fields" :initial="initial" :action="save" :reload="reload" :description="library === 'policies' ? t('kbc.policyEditHint') : undefined" />
        <WorkflowAction v-if="library === 'policies' || library === 'actions'" :key="String(record.enabled)" :label="record.enabled ? t('kbc.disable') : t('kbc.enable')" :action="() => knowledgeApi.toggle(library as 'policies' | 'actions', id!, !record!.enabled)" :reload="reload" />
      </div>
    </template>
  </Modal>
</template>
