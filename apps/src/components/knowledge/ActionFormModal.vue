<script setup lang="ts">
// Add an Action (Knowledge → Actions; SOC, IR_TEAM and admin — the backend enforces the role). Same fields as a stored
// action: code, name, description, category, impact level, default approval and its runbook. Audited (CREATE_ACTION).
// A playbook can only use it once its code is listed in that playbook's allowed actions.
import { reactive, ref, watch } from 'vue'
import { Loader2 } from 'lucide-vue-next'
import Modal from '@/components/common/Modal.vue'
import { knowledgeApi } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { useI18n, type MsgKey } from '@/i18n'
import { workflowError } from '@/utils/workflow'
import { ACTION_CATEGORIES, IMPACT_LEVELS, actionPayload, emptyActionDraft, hasActionErrors, validateActionDraft, type ActionDraft, type ActionDraftErrors } from '@/utils/actionForm'

const props = defineProps<{ open: boolean; existingCodes: string[]; runbooks: { id: string; code: string; name: string }[] }>()
const emit = defineEmits<{ close: []; saved: [code: string] }>()
const { t } = useI18n()

const draft = reactive<ActionDraft>(emptyActionDraft())
const errors = ref<ActionDraftErrors>({})
const touched = ref(false)
const saving = ref(false)
const serverError = ref('')

watch(() => props.open, (open) => {
  if (!open) return
  Object.assign(draft, emptyActionDraft())
  errors.value = {}
  touched.value = false
  serverError.value = ''
}, { immediate: true })
watch(draft, () => { if (touched.value) errors.value = validateActionDraft(draft, props.existingCodes) }, { deep: true })

function serverMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === 'DUPLICATE_CODE') return t('actf.err.codeDuplicate')
    if (e.code === 'FORBIDDEN' || e.status === 403) return t('actf.err.forbidden')
    if (e.code === 'VALIDATION_ERROR') return t('pbf.err.server')
  }
  return workflowError(e)
}

async function save() {
  if (saving.value) return
  touched.value = true
  errors.value = validateActionDraft(draft, props.existingCodes)
  if (hasActionErrors(errors.value)) return
  saving.value = true
  serverError.value = ''
  try {
    const saved = await knowledgeApi.create('actions', actionPayload(draft))
    emit('saved', String(saved.code ?? draft.code.trim().toUpperCase()))
  } catch (e) {
    serverError.value = serverMessage(e)
  } finally {
    saving.value = false
  }
}
const fieldError = (k: keyof ActionDraftErrors) => (errors.value[k] ? t(errors.value[k] as MsgKey) : '')
const inputClass = (bad: boolean) => ['mt-1 w-full rounded-lg border px-3 py-1.5 text-sm focus:outline-none', bad ? 'border-rose-400 focus:border-rose-500' : 'border-slate-300 focus:border-accent-500']
</script>

<template>
  <Modal :open="open" :title="t('actf.createTitle')" size="lg" @close="!saving && emit('close')">
    <form class="space-y-4 text-sm" novalidate @submit.prevent="save">
      <fieldset class="space-y-4" :disabled="saving">
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block font-medium text-slate-700">{{ t('pbf.code') }} *
            <input v-model="draft.code" :class="inputClass(!!errors.code)" class="font-mono uppercase" autocomplete="off" :aria-invalid="!!errors.code" />
            <span class="mt-0.5 block text-[11px] font-normal text-slate-400">{{ t('actf.codeHint') }}</span>
            <span v-if="errors.code" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('code') }}</span>
          </label>
          <label class="block font-medium text-slate-700">{{ t('actf.name') }} *
            <input v-model="draft.name" :class="inputClass(!!errors.name)" maxlength="200" :aria-invalid="!!errors.name" />
            <span v-if="errors.name" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('name') }}</span>
          </label>
        </div>
        <label class="block font-medium text-slate-700">{{ t('pbf.description') }}
          <textarea v-model="draft.description" rows="2" maxlength="2000" :class="inputClass(false)" />
        </label>
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block font-medium text-slate-700">{{ t('kbc.f.category') }} *
            <select v-model="draft.category" :class="inputClass(!!errors.category)" :aria-invalid="!!errors.category">
              <option value="" disabled>{{ t('polf.choose') }}</option>
              <option v-for="c in ACTION_CATEGORIES" :key="c" :value="c">{{ c }}</option>
            </select>
            <span class="mt-0.5 block text-[11px] font-normal text-slate-400">{{ t('actf.categoryHint') }}</span>
            <span v-if="errors.category" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('category') }}</span>
          </label>
          <label class="block font-medium text-slate-700">{{ t('actf.impact') }} *
            <select v-model="draft.impactLevel" :class="inputClass(!!errors.impactLevel)" :aria-invalid="!!errors.impactLevel">
              <option value="" disabled>{{ t('polf.choose') }}</option>
              <option v-for="l in IMPACT_LEVELS" :key="l" :value="l">{{ l }}</option>
            </select>
            <span v-if="errors.impactLevel" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('impactLevel') }}</span>
          </label>
        </div>
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block font-medium text-slate-700">{{ t('actf.runbook') }}
            <select v-model="draft.runbookId" :class="inputClass(false)">
              <option value="">{{ t('actf.noRunbook') }}</option>
              <option v-for="rb in runbooks" :key="rb.id" :value="rb.id">{{ rb.code }} — {{ rb.name }}</option>
            </select>
          </label>
          <label class="flex items-start gap-2 pt-7 font-medium text-slate-700">
            <input v-model="draft.defaultApprovalRequired" type="checkbox" class="mt-0.5 size-4 rounded border-slate-300" />
            <span>{{ t('kbc.f.defaultApproval') }}<span class="block text-[11px] font-normal text-slate-400">{{ t('actf.approvalHint') }}</span></span>
          </label>
        </div>
      </fieldset>

      <p class="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600">{{ t('actf.futureOnly') }}</p>
      <p v-if="serverError" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ serverError }}</p>
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" :disabled="saving" @click="emit('close')">{{ t('c.cancel') }}</button>
        <button type="submit" class="btn-primary inline-flex items-center gap-2" :disabled="saving"><Loader2 v-if="saving" class="size-4 animate-spin" />{{ saving ? t('pbf.saving') : t('pbf.save') }}</button>
      </div>
    </form>
  </Modal>
</template>
