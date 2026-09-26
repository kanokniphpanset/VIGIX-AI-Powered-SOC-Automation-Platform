<script setup lang="ts">
import { useUiStore } from '@/stores/ui'
import { useI18n } from '@/i18n'

const ui = useUiStore()
const { t } = useI18n()

const iconFor = {
  success: 'M5 13l4 4L19 7',
  error: 'M6 6l12 12M18 6 6 18',
  info: 'M12 8h.01M11 12h1v4h1',
  warning: 'M12 9v4m0 4h.01M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z',
}
const colorFor = {
  success: 'border-emerald-200 bg-emerald-50 text-emerald-800',
  error: 'border-critical-200 bg-critical-50 text-critical-800',
  info: 'border-blue-200 bg-blue-50 text-blue-800',
  warning: 'border-amber-200 bg-amber-50 text-amber-800',
}
</script>

<template>
  <Teleport to="body">
    <div class="pointer-events-none fixed bottom-4 right-4 z-[60] flex w-80 max-w-[calc(100vw-2rem)] flex-col gap-2" role="status" aria-live="polite">
      <transition-group name="toast">
        <div
          v-for="toast in ui.toasts"
          :key="toast.id"
          class="pointer-events-auto flex items-start gap-2.5 rounded-lg border p-3 shadow-lg"
          :class="colorFor[toast.type]"
        >
          <svg class="mt-0.5 size-4 shrink-0" viewBox="0 0 24 24" fill="none">
            <path :d="iconFor[toast.type]" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
          </svg>
          <div class="min-w-0 flex-1">
            <p class="text-xs font-semibold">{{ toast.title }}</p>
            <p v-if="toast.message" class="mt-0.5 text-[11px] opacity-80">{{ toast.message }}</p>
            <router-link v-if="toast.link" :to="toast.link.to" class="mt-1.5 inline-block text-xs font-semibold underline underline-offset-2 hover:no-underline" @click="ui.dismissToast(toast.id)">{{ toast.link.label }} →</router-link>
          </div>
          <button type="button" :aria-label="t('ui.dismiss')" class="text-current opacity-50 hover:opacity-100" @click="ui.dismissToast(toast.id)">
            <svg class="size-3.5" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" /></svg>
          </button>
        </div>
      </transition-group>
    </div>
  </Teleport>
</template>

<style scoped>
.toast-enter-active,
.toast-leave-active {
  transition: all 0.2s ease;
}
.toast-enter-from,
.toast-leave-to {
  opacity: 0;
  transform: translateX(12px);
}
</style>
