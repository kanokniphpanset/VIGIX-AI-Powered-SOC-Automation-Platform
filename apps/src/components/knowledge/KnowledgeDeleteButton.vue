<script setup lang="ts">
// Delete a Policy or a Playbook (Knowledge): an "×" on the row and one confirmation (no reason needed). The backend
// (SOC / IR_TEAM / admin) records DELETE_POLICY / DELETE_PLAYBOOK with the actor, the time and a full copy.
import { ref } from 'vue'
import { Loader2, X } from 'lucide-vue-next'
import Modal from '@/components/common/Modal.vue'
import { knowledgeApi } from '@/api/vigix'
import { useI18n, type MsgKey } from '@/i18n'
import { workflowError } from '@/utils/workflow'

const props = defineProps<{ library: 'policies' | 'playbooks'; id: string; code: string; name: string; enabled: boolean }>()
const emit = defineEmits<{ deleted: [code: string] }>()
const { t } = useI18n()
/** Same dialog for both libraries; only the wording differs (pol.* for policies, pbd.* for playbooks). */
const k = (key: string) => (props.library === 'playbooks' ? key.replace(/^pol\./, 'pbd.') : key) as MsgKey

const open = ref(false)
const busy = ref(false)
const error = ref('')
function begin() {
  error.value = ''
  open.value = true
}
async function confirm() {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await knowledgeApi.remove(props.library, props.id)
    open.value = false
    emit('deleted', props.code)
  } catch (e) {
    error.value = workflowError(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <button type="button" class="rounded-md p-1 text-slate-400 hover:bg-rose-50 hover:text-rose-600" :title="t(k('pol.delete'))" :aria-label="t(k('pol.deleteAria'), { name })" @click.stop="begin">
    <X class="size-4" />
  </button>
  <Modal :open="open" :title="t(k('pol.deleteTitle'), { code })" size="sm" @close="!busy && (open = false)">
    <form class="space-y-3 text-sm" @submit.prevent="confirm">
      <p class="text-slate-700">{{ t(k('pol.deleteBody'), { code, name }) }}</p>
      <p v-if="enabled" class="rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-800">{{ t(k('pol.deleteEnabled')) }}</p>
      <p class="text-xs text-slate-500">{{ t(k('pol.deleteHistory')) }}</p>
      <p v-if="error" class="rounded-lg bg-rose-50 px-3 py-2 text-rose-700" role="alert">{{ error }}</p>
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" :disabled="busy" @click="open = false">{{ t('c.cancel') }}</button>
        <button type="submit" class="inline-flex items-center gap-2 rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-semibold text-white hover:bg-rose-700 disabled:opacity-50" :disabled="busy">
          <Loader2 v-if="busy" class="size-4 animate-spin" />{{ busy ? t('c.saving') : t(k('pol.deleteConfirm')) }}
        </button>
      </div>
    </form>
  </Modal>
</template>
