<script setup lang="ts">
import { reactive, ref } from 'vue'
import { Loader2 } from 'lucide-vue-next'
import Modal from './Modal.vue'
import { mutate, mutationState } from '@/utils/workflow'
import { useUiStore } from '@/stores/ui'
import type { Feedback } from '@/utils/feedback'
import { useI18n } from '@/i18n'
const { t } = useI18n()
const props = withDefaults(defineProps<{ label: string; action: (reason: string) => Promise<unknown>; reload: () => Promise<unknown>; reasonRequired?: boolean; disabled?: boolean; confirm?: boolean; successLabel?: string; /** Result + next step shown after success (utils/feedback.ts); overrides successLabel. */ feedback?: Feedback }>(), { confirm: true })
const state = reactive(mutationState())
const emit = defineEmits<{ busy: [value: boolean] }>()
const open = ref(false)
const reason = ref('')
const ui = useUiStore()
function begin() { if (state.busy || props.disabled) return; if (props.confirm) open.value = true; else void submit() }
async function submit() {
  if (state.busy || props.disabled || (props.reasonRequired && !reason.value.trim())) return
  emit('busy', true)
  const ok = await mutate(state, () => props.action(reason.value.trim()), props.reload)
  emit('busy', false)
  if (ok) { if (props.feedback) ui.notify(props.feedback); else ui.success(props.successLabel ?? t('ui.saved', { label: props.label })); open.value = false }
  else if (state.error) ui.error(props.label, state.error)
}
</script>
<template>
  <span class="inline-flex max-w-full flex-col gap-1">
    <button type="button" class="btn-secondary inline-flex items-center gap-2 disabled:opacity-50" :disabled="disabled || state.busy || state.success" :aria-busy="state.busy" @click="begin"><Loader2 v-if="state.busy" class="size-4 animate-spin" />{{ state.busy ? t('c.saving') : state.saved && !state.success ? t('ui.retryRefresh') : label }}</button>
    <span v-if="state.error && !open" role="alert" class="text-xs text-rose-700">{{ state.error }}</span>
    <Modal :open="open" :title="label" @close="!state.busy && (open = false)">
      <form class="space-y-3" @submit.prevent="submit">
        <slot />
        <label v-if="reasonRequired" class="block text-sm">{{ t('ui.reasonNeeded') }}<textarea v-model="reason" required :disabled="state.busy || state.saved" class="mt-1 w-full rounded border border-slate-300 p-2" rows="3" /></label>
        <p v-else class="text-sm text-slate-600">{{ t('ui.confirmAction', { action: label }) }}</p>
        <p v-if="state.error" role="alert" class="text-sm text-rose-700">{{ state.error }}</p>
        <div class="flex justify-end gap-2"><button type="button" class="btn-secondary" :disabled="state.busy" @click="open = false">{{ t('c.cancel') }}</button><button class="btn-primary inline-flex items-center gap-2" :disabled="state.busy || (reasonRequired && !reason.trim())"><Loader2 v-if="state.busy" class="size-4 animate-spin" />{{ state.busy ? t('c.saving') : state.saved ? t('ui.retryRefresh') : t('c.confirm') }}</button></div>
      </form>
    </Modal>
  </span>
</template>
