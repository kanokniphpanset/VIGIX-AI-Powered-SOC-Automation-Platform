<script setup lang="ts">
import { reactive, ref } from 'vue'
import { Loader2 } from 'lucide-vue-next'
import Modal from './Modal.vue'
import { mutationState, mutate } from '@/utils/workflow'
import { formPayload, type FormField } from '@/utils/forms'
import { useUiStore } from '@/stores/ui'
import { useI18n } from '@/i18n'
const { t } = useI18n()
const props = defineProps<{ label: string; fields: FormField[]; initial?: Record<string, unknown>; action: (body: Record<string, unknown>) => Promise<unknown>; reload: () => Promise<unknown>; disabled?: boolean; description?: string
  // Optional presentation (defaults keep the compact form): trigger button class, dialog title/size, and the two-column
  // field layout used by the Knowledge create dialogs (same look as the Playbook form).
  buttonClass?: string; title?: string; size?: 'sm' | 'md' | 'lg'; grid?: boolean }>()
const open = ref(false)
const state = reactive(mutationState())
const values = reactive<Record<string, unknown>>({})
const validation = ref('')
const ui = useUiStore()
const wide = (f: FormField) => f.type === 'textarea' || f.type === 'lines'
const inputClass = () => (props.grid ? 'mt-1 w-full rounded-lg border border-slate-300 px-3 py-1.5 text-sm focus:border-accent-500 focus:outline-none' : 'mt-1 w-full rounded border border-slate-300 p-2')
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
  <button type="button" :class="buttonClass ?? 'btn-secondary'" :disabled="disabled || state.busy" @click="begin">{{ label }}</button>
  <Modal :open="open" :title="title ?? label" :size="size" @close="!state.busy && (open = false)">
    <form :class="grid ? 'space-y-4 text-sm' : 'space-y-3'" @submit.prevent="save">
      <p v-if="description" class="text-sm text-slate-500">{{ description }}</p>
      <fieldset :class="grid ? 'grid gap-4 sm:grid-cols-2' : 'space-y-3'" :disabled="state.busy || state.saved">
        <label v-for="field in fields" :key="field.key" :class="grid ? ['block font-medium text-slate-700', wide(field) ? 'sm:col-span-2' : '', field.type === 'checkbox' ? 'flex items-center gap-2 self-end' : ''] : 'block text-sm'">
          <input v-if="grid && field.type === 'checkbox'" v-model="values[field.key]" type="checkbox" class="size-4 rounded border-slate-300" />
          {{ field.label }}{{ field.required ? ' *' : '' }}
          <select v-if="field.type === 'select'" v-model="values[field.key]" :required="field.required" :class="inputClass()"><option value="">{{ t('ui.choose') }}</option><option v-for="value in field.options" :key="value" :value="value">{{ value }}</option></select>
          <textarea v-else-if="field.type === 'textarea' || field.type === 'lines'" v-model="values[field.key] as string" :required="field.required" rows="3" :class="inputClass()" />
          <template v-else-if="field.type === 'checkbox'"><input v-if="!grid" v-model="values[field.key]" type="checkbox" class="ml-2" /></template>
          <input v-else v-model="values[field.key]" :type="field.type ?? 'text'" :required="field.required" :min="field.min" :max="field.max" :step="field.type === 'number' ? 'any' : undefined" :class="[inputClass(), field.key === 'code' ? 'font-mono uppercase' : '']" />
        </label>
      </fieldset>
      <p v-if="validation || state.error" role="alert" :class="grid ? 'rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700' : 'text-sm text-rose-700'">{{ validation || state.error }}</p>
      <div class="flex justify-end gap-2"><button type="button" class="btn-secondary" :disabled="state.busy" @click="open = false">{{ t('c.cancel') }}</button><button class="btn-primary inline-flex items-center gap-2" :disabled="state.busy"><Loader2 v-if="state.busy" class="size-4 animate-spin" />{{ state.busy ? t('c.saving') : state.saved ? t('ui.retryRefresh') : t('c.save') }}</button></div>
    </form>
  </Modal>
</template>
