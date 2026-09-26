import { defineStore } from 'pinia'
import { ref } from 'vue'
import type { Feedback } from '@/utils/feedback'

export interface Toast {
  id: number
  type: 'success' | 'error' | 'info' | 'warning'
  title: string
  message?: string
  /** Optional link to where the next step happens. */
  link?: { label: string; to: string } | null
}

let toastSeq = 0

export const useUiStore = defineStore('ui', () => {
  const toasts = ref<Toast[]>([])
  const sidebarCollapsed = ref(false)
  const commandPaletteOpen = ref(false)
  /** First-use tour (components/layout/FirstRunTour.vue). */
  const tourOpen = ref(false)

  function pushToast(type: Toast['type'], title: string, message?: string, link?: Toast['link']) {
    toastSeq += 1
    const id = toastSeq
    toasts.value.push({ id, type, title, message, link })
    // A toast that tells the next step (and may carry a link) stays long enough to read and click.
    setTimeout(() => dismissToast(id), link || (message && message.length > 60) ? 10000 : 5000)
  }
  function dismissToast(id: number) {
    toasts.value = toasts.value.filter((t) => t.id !== id)
  }
  function success(title: string, message?: string) {
    pushToast('success', title, message)
  }
  function error(title: string, message?: string) {
    pushToast('error', title, message)
  }
  function info(title: string, message?: string) {
    pushToast('info', title, message)
  }
  /** Result of an action + the next step (utils/feedback.ts). */
  function notify(f: Feedback) {
    pushToast(f.type, f.title, f.message, f.link)
  }
  function startTour() {
    tourOpen.value = true
  }

  return { toasts, sidebarCollapsed, commandPaletteOpen, tourOpen, pushToast, dismissToast, success, error, info, notify, startTour }
})
