<script setup lang="ts">
// Add a Policy (Knowledge → Policies; SOC, IR_TEAM and admin — the backend enforces the role). Same fields as a stored
// policy: code, name, description, type, precedence and rules (condition → result). Human-controlled and audited;
// a new policy is evaluated from the next Policy decision on.
import { reactive, ref, watch } from 'vue'
import { Loader2, Trash2 } from 'lucide-vue-next'
import Modal from '@/components/common/Modal.vue'
import { knowledgeApi } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { useI18n, type MsgKey } from '@/i18n'
import { workflowError } from '@/utils/workflow'
import {
  CONDITION_FIELDS, CONDITION_OPERATORS, CONDITION_VALUES, POLICY_TYPES, RESULT_FIELDS,
  emptyCondition, emptyPolicyDraft, emptyRule, hasPolicyErrors, policyPayload, validatePolicyDraft,
  type ConditionDraft, type PolicyDraft, type PolicyDraftErrors,
} from '@/utils/policyForm'

const props = defineProps<{ open: boolean; existingCodes: string[] }>()
const emit = defineEmits<{ close: []; saved: [code: string] }>()
const { t } = useI18n()

const draft = reactive<PolicyDraft>(emptyPolicyDraft())
const errors = ref<PolicyDraftErrors>({})
const touched = ref(false)
const saving = ref(false)
const serverError = ref('')

watch(() => props.open, (open) => {
  if (!open) return
  Object.assign(draft, emptyPolicyDraft())
  errors.value = {}
  touched.value = false
  serverError.value = ''
}, { immediate: true })
watch(draft, () => { if (touched.value) errors.value = validatePolicyDraft(draft, props.existingCodes) }, { deep: true })

const addRule = () => draft.rules.push(emptyRule())
const removeRule = (i: number) => { draft.rules.splice(i, 1); if (!draft.rules.length) addRule() }
const removeCondition = (ri: number, ci: number) => { const c = draft.rules[ri].conditions; c.splice(ci, 1); if (!c.length) c.push(emptyCondition()) }
// A new field has other values: clear a value that no longer fits.
const fieldChanged = (c: ConditionDraft) => { if (!CONDITION_VALUES[c.field]?.includes(c.value)) c.value = '' }

function serverMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.code === 'DUPLICATE_CODE') return t('polf.err.codeDuplicate')
    if (e.code === 'FORBIDDEN' || e.status === 403) return t('polf.err.forbidden')
    if (e.code === 'VALIDATION_ERROR') return t('pbf.err.server')
  }
  return workflowError(e)
}

async function save() {
  if (saving.value) return
  touched.value = true
  errors.value = validatePolicyDraft(draft, props.existingCodes)
  if (hasPolicyErrors(errors.value)) return
  saving.value = true
  serverError.value = ''
  try {
    const saved = await knowledgeApi.create('policies', policyPayload(draft))
    emit('saved', String(saved.code ?? draft.code.trim().toUpperCase()))
  } catch (e) {
    serverError.value = serverMessage(e)
  } finally {
    saving.value = false
  }
}
const fieldError = (k: 'code' | 'name' | 'type' | 'precedence') => (errors.value[k] ? t(errors.value[k] as MsgKey) : '')
const inputClass = (bad: boolean) => ['mt-1 w-full rounded-lg border px-3 py-1.5 text-sm focus:outline-none', bad ? 'border-rose-400 focus:border-rose-500' : 'border-slate-300 focus:border-accent-500']
const smallInput = 'w-full rounded-md border border-slate-300 px-2 py-1 text-xs focus:border-accent-500 focus:outline-none'
</script>

<template>
  <Modal :open="open" :title="t('polf.createTitle')" size="lg" @close="!saving && emit('close')">
    <form class="space-y-4 text-sm" novalidate @submit.prevent="save">
      <fieldset class="space-y-4" :disabled="saving">
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block font-medium text-slate-700">{{ t('pbf.code') }} *
            <input v-model="draft.code" :class="inputClass(!!errors.code)" class="font-mono uppercase" autocomplete="off" :aria-invalid="!!errors.code" />
            <span class="mt-0.5 block text-[11px] font-normal text-slate-400">{{ t('polf.codeHint') }}</span>
            <span v-if="errors.code" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('code') }}</span>
          </label>
          <label class="block font-medium text-slate-700">{{ t('polf.name') }} *
            <input v-model="draft.name" :class="inputClass(!!errors.name)" maxlength="200" :aria-invalid="!!errors.name" />
            <span v-if="errors.name" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('name') }}</span>
          </label>
        </div>
        <label class="block font-medium text-slate-700">{{ t('pbf.description') }}
          <textarea v-model="draft.description" rows="2" maxlength="2000" :class="inputClass(false)" />
        </label>
        <div class="grid gap-4 sm:grid-cols-2">
          <label class="block font-medium text-slate-700">{{ t('polf.type') }} *
            <select v-model="draft.type" :class="inputClass(!!errors.type)" :aria-invalid="!!errors.type">
              <option value="" disabled>{{ t('polf.choose') }}</option>
              <option v-for="ty in POLICY_TYPES" :key="ty" :value="ty">{{ ty }}</option>
            </select>
            <span class="mt-0.5 block text-[11px] font-normal text-slate-400">{{ draft.type ? t(`polf.typeHint.${draft.type}` as MsgKey) : '' }}</span>
            <span v-if="errors.type" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('type') }}</span>
          </label>
          <label class="block font-medium text-slate-700">{{ t('polf.precedence') }} *
            <input v-model="draft.precedence" inputmode="numeric" :class="inputClass(!!errors.precedence)" :aria-invalid="!!errors.precedence" />
            <span class="mt-0.5 block text-[11px] font-normal text-slate-400">{{ t('polf.precedenceHint') }}</span>
            <span v-if="errors.precedence" class="mt-0.5 block text-xs font-normal text-rose-700" role="alert">{{ fieldError('precedence') }}</span>
          </label>
        </div>

        <div>
          <p class="font-medium text-slate-700">{{ t('polf.rules') }} *</p>
          <ol class="mt-2 space-y-3">
            <li v-for="(r, ri) in draft.rules" :key="ri" class="rounded-lg border p-3" :class="errors.rules?.[ri] ? 'border-rose-300' : 'border-slate-200'">
              <div class="mb-2 flex items-center justify-between">
                <span class="text-xs font-semibold text-slate-500">{{ t('polf.rule', { n: ri + 1 }) }}</span>
                <button type="button" class="rounded p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600" :aria-label="t('polf.removeRule', { n: ri + 1 })" @click="removeRule(ri)"><Trash2 class="size-3.5" /></button>
              </div>

              <p class="text-xs font-semibold text-slate-600">{{ t('polf.condition') }}</p>
              <p class="text-[11px] text-slate-400">{{ t('polf.conditionHint') }}</p>
              <div v-for="(c, ci) in r.conditions" :key="ci" class="mt-1.5 grid grid-cols-[1fr_auto_1fr_auto] items-center gap-1.5">
                <select v-model="c.field" :class="smallInput" :aria-label="t('polf.conditionField')" @change="fieldChanged(c)">
                  <option v-for="f in CONDITION_FIELDS" :key="f" :value="f">{{ f }}</option>
                </select>
                <select v-model="c.operator" :class="smallInput" class="w-20" :aria-label="t('kbc.f.operator')">
                  <option v-for="o in CONDITION_OPERATORS" :key="o" :value="o">{{ o }}</option>
                </select>
                <select v-model="c.value" :class="smallInput" :aria-label="t('polf.conditionValue')">
                  <option value="" disabled>{{ t('polf.choose') }}</option>
                  <option v-for="v in CONDITION_VALUES[c.field]" :key="v" :value="v">{{ v }}</option>
                </select>
                <button type="button" class="rounded p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600" :aria-label="t('polf.removeCondition')" @click="removeCondition(ri, ci)"><Trash2 class="size-3.5" /></button>
              </div>
              <button type="button" class="mt-1.5 text-xs font-semibold text-accent-700 hover:underline" @click="r.conditions.push(emptyCondition())">{{ t('polf.addCondition') }}</button>

              <p class="mt-3 text-xs font-semibold text-slate-600">{{ t('polf.result') }}</p>
              <p class="text-[11px] text-slate-400">{{ t('polf.resultHint') }}</p>
              <div class="mt-1.5 grid gap-x-3 gap-y-1.5 sm:grid-cols-2">
                <label v-for="f in RESULT_FIELDS" :key="f.key" class="block text-xs text-slate-600">{{ t(`polf.r.${f.key}` as MsgKey) }}
                  <select v-if="f.kind === 'boolean'" v-model="r.result[f.key]" :class="smallInput" class="mt-0.5">
                    <option value="">{{ t('polf.notSet') }}</option>
                    <option value="true">{{ t('kbv.yes') }}</option>
                    <option value="false">{{ t('kbv.no') }}</option>
                  </select>
                  <select v-else-if="f.kind === 'select'" v-model="r.result[f.key]" :class="smallInput" class="mt-0.5">
                    <option value="">{{ t('polf.notSet') }}</option>
                    <option v-for="o in f.options" :key="o" :value="o">{{ o }}</option>
                  </select>
                  <input v-else v-model="r.result[f.key]" :inputmode="f.kind === 'number' ? 'numeric' : undefined" :placeholder="f.kind === 'list' ? t('polf.listPlaceholder') : t('polf.notSet')" :class="smallInput" class="mt-0.5" />
                </label>
              </div>
              <p v-if="errors.rules?.[ri]" class="mt-2 text-xs text-rose-700" role="alert">{{ t(errors.rules[ri]) }}</p>
            </li>
          </ol>
          <button type="button" class="mt-2 text-xs font-semibold text-accent-700 hover:underline" @click="addRule">{{ t('polf.addRule') }}</button>
        </div>
      </fieldset>

      <p class="rounded-lg bg-slate-50 px-3 py-2 text-xs text-slate-600">{{ t('polf.futureOnly') }}</p>
      <p v-if="serverError" class="rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ serverError }}</p>
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" :disabled="saving" @click="emit('close')">{{ t('c.cancel') }}</button>
        <button type="submit" class="btn-primary inline-flex items-center gap-2" :disabled="saving"><Loader2 v-if="saving" class="size-4 animate-spin" />{{ saving ? t('pbf.saving') : t('pbf.save') }}</button>
      </div>
    </form>
  </Modal>
</template>
