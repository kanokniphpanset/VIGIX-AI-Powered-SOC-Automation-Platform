<script setup lang="ts">
import { useI18n } from '@/i18n'

withDefaults(defineProps<{ open: boolean; title?: string; size?: 'sm' | 'md' | 'lg' }>(), { size: 'md' })
const emit = defineEmits<{ close: [] }>()
const { t } = useI18n()
</script>

<template>
  <Teleport to="body">
    <transition name="modal-fade">
      <div v-if="open" class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/40 p-4" @mousedown.self="emit('close')">
        <div
          role="dialog" aria-modal="true" :aria-label="title" class="max-h-[90vh] overflow-y-auto w-full rounded-xl border border-slate-200 bg-white shadow-xl"
          :class="{ 'max-w-md': size === 'sm', 'max-w-xl': size === 'md', 'max-w-3xl': size === 'lg' }"
        >
          <div v-if="title || $slots.header" class="flex items-center justify-between border-b border-slate-100 px-5 py-4">
            <slot name="header">
              <h3 class="text-sm font-semibold text-slate-800">{{ title }}</h3>
            </slot>
            <button type="button" :aria-label="t('ui.closeDialog')" class="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600" @click="emit('close')">
              <svg class="size-4" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
            </button>
          </div>
          <div class="px-5 py-4">
            <slot />
          </div>
          <div v-if="$slots.footer" class="flex justify-end gap-2 border-t border-slate-100 px-5 py-3">
            <slot name="footer" />
          </div>
        </div>
      </div>
    </transition>
  </Teleport>
</template>

<style scoped>
.modal-fade-enter-active,
.modal-fade-leave-active {
  transition: opacity 0.15s ease;
}
.modal-fade-enter-from,
.modal-fade-leave-to {
  opacity: 0;
}
</style>
