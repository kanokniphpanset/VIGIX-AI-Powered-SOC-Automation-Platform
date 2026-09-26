<script setup lang="ts">
import { reactive, ref } from 'vue'
import { Loader2 } from 'lucide-vue-next'
import Modal from './Modal.vue'
import { mutationState, mutate } from '@/utils/workflow'
import { formPayload, type FormField } from '@/utils/forms'
import { useUiStore } from '@/stores/ui'
import { useI18n } from '@/i18n'
const { t } = useI18n()
const props = defineProps<{ label: string; fields: FormField[]; initial?: Record<string, unknown>; action: (body: Record<string, unknown>) => Promise<unknown>; reload: () => Promise<unknown>; disabled?: boolean; description?: string }>()
const open = ref(false)
const state = reactive(mutationState())
const values = reactive<Record<string, unknown>>({})
const validation = ref('')
const ui = useUiStore()
function begin() { if (props.disabled || state.busy) return; if (state.saved && !state.success) { open.value = true; return }; Object.assign(state, mutationState()); for (const key of Object.keys(values)) delete values[key]; Object.assign(values, props.initial ?? {}); validation.value = ''; open.value = true }
async function save() {
  if (state.busy || props.disabled) return
  let body: Record<string, unknown>
  try { body = formPayload(props.fields, values); validation.value = '' } catch (e) { validation.value = (e as Error).message; return }
  if (await mutate(state, () => props.action(body), props.reload)) { open.value = false; ui.success(t('ui.saved', { label: props.label })) }
  else ui.error(props.label, state.error)
}
</script>
<template>
  <button type="button" class="btn-secondary" :disabled="disabled || state.busy" @click="begin">{{ label }}</button>
  <Modal :open="open" :title="label" @close="!state.busy && (open = false)">
    <form class="space-y-3" @submit.prevent="save">
      <p v-if="description" class="text-sm text-slate-500">{{ description }}</p>
      <fieldset class="space-y-3" :disabled="state.busy || state.saved">
        <label v-for="field in fields" :key="field.key" class="block text-sm">
          {{ field.label }}{{ field.required ? ' *' : '' }}
          <select v-if="field.type === 'select'" v-model="values[field.key]" :required="field.required" class="mt-1 w-full rounded border border-slate-300 p-2"><option value="">{{ t('ui.choose') }}</option><option v-for="value in field.options" :key="value" :value="value">{{ value }}</option></select>
          <textarea v-else-if="field.type === 'textarea' || field.type === 'lines'" v-model="values[field.key] as string" :required="field.required" rows="3" class="mt-1 w-full rounded border border-slate-300 p-2" />
          <input v-else-if="field.type === 'checkbox'" v-model="values[field.key]" type="checkbox" class="ml-2" />
          <input v-else v-model="values[field.key]" :type="field.type ?? 'text'" :required="field.required" :min="field.min" :max="field.max" :step="field.type === 'number' ? 'any' : undefined" class="mt-1 w-full rounded border border-slate-300 p-2" />
        </label>
      </fieldset>
      <p v-if="validation || state.error" role="alert" class="text-sm text-rose-700">{{ validation || state.error }}</p>
      <div class="flex justify-end gap-2"><button type="button" class="btn-secondary" :disabled="state.busy" @click="open = false">{{ t('c.cancel') }}</button><button class="btn-primary inline-flex items-center gap-2" :disabled="state.busy"><Loader2 v-if="state.busy" class="size-4 animate-spin" />{{ state.busy ? t('c.saving') : state.saved ? t('ui.retryRefresh') : t('c.save') }}</button></div>
    </form>
  </Modal>
</template>
