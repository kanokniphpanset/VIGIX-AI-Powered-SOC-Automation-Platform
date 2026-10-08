<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Bell } from 'lucide-vue-next'
import { notificationsApi, type InAppNotification } from '@/api/vigix'
import { useUiStore } from '@/stores/ui'
import { timeAgo } from '@/utils/vigix'
import { formatDateTime } from '@/utils/formatters'
import { notificationText, notificationType } from '@/utils/systemText'
import { useI18n } from '@/i18n'

/**
 * Header bell — persistent, role-aware in-app notifications from the backend (GET /api/v1/notifications): new
 * incidents, IR response required, approval required / decided, more evidence requested, response started /
 * completed, re-hunt results, escalation, resolution and every workflow email. Read state is stored per user on the
 * server, so it follows the user across browsers. New entries since the last poll also show as a toast.
 */
const POLL_MS = 30_000
const router = useRouter()
const ui = useUiStore()
const { t } = useI18n()
const open = ref(false)
const items = ref<InAppNotification[]>([])
const unread = ref(0)
const root = ref<HTMLElement | null>(null)
let newestSeen: string | null = null

async function poll() {
  try {
    const res = await notificationsApi.list(30)
    // Toast only what arrived after the first load of this page (never a flood of old entries).
    if (newestSeen) {
      const fresh = res.items.filter((n) => !n.read && n.createdAt > newestSeen!)
      for (const n of fresh.slice(0, 3).reverse()) {
        const text = notificationText(n)
        ui.info(text.title, text.body ?? undefined)
      }
    }
    newestSeen = res.items[0]?.createdAt ?? newestSeen ?? new Date(0).toISOString()
    items.value = res.items
    unread.value = res.unread
  } catch {
    /* backend unreachable — try again on the next tick */
  }
}

async function openNote(n: InAppNotification) {
  open.value = false
  if (!n.read) {
    n.read = true
    unread.value = Math.max(0, unread.value - 1)
    notificationsApi.markRead([n.id]).catch(() => undefined)
  }
  if (n.link) await router.push(n.link)
}

async function markAllRead() {
  items.value.forEach((n) => (n.read = true))
  unread.value = 0
  await notificationsApi.markRead().catch(() => undefined)
}

let timer: ReturnType<typeof setInterval> | undefined
function onClickOutside(e: MouseEvent) {
  if (root.value && !root.value.contains(e.target as Node)) open.value = false
}
onMounted(() => {
  void poll()
  timer = setInterval(poll, POLL_MS)
  document.addEventListener('mousedown', onClickOutside)
})
onUnmounted(() => {
  clearInterval(timer)
  document.removeEventListener('mousedown', onClickOutside)
})
</script>

<template>
  <div ref="root" class="relative">
    <button type="button" class="relative rounded-lg p-2 text-slate-500 hover:bg-slate-100 hover:text-slate-700" :aria-label="t('nt.aria', { n: unread })" :aria-expanded="open" @click="open = !open">
      <Bell class="size-4.5" />
      <span v-if="unread" class="absolute right-1 top-1 flex min-w-4 items-center justify-center rounded-full bg-accent-600 px-1 text-[10px] font-bold leading-4 text-white">{{ unread > 99 ? '99+' : unread }}</span>
    </button>
    <div v-if="open" class="absolute right-0 z-40 mt-2 w-96 rounded-xl border border-slate-200 bg-white shadow-lg">
      <div class="flex items-center justify-between border-b border-slate-100 px-3.5 py-2.5">
        <p class="text-xs font-semibold text-slate-700">{{ t('nt.title') }}</p>
        <button v-if="unread" type="button" class="text-[11px] font-semibold text-accent-600 hover:text-accent-700" @click="markAllRead">{{ t('nt.markAll') }}</button>
      </div>
      <p v-if="!items.length" class="px-3.5 py-6 text-center text-xs text-slate-500">{{ t('nt.empty') }}</p>
      <ul v-else class="max-h-96 divide-y divide-slate-100 overflow-y-auto">
        <li v-for="n in items" :key="n.id">
          <button type="button" class="w-full px-3.5 py-2.5 text-left hover:bg-slate-50" @click="openNote(n)">
            <p class="flex items-start gap-1.5 text-xs font-semibold" :class="n.read ? 'text-slate-600' : 'text-slate-900'">
              <span v-if="!n.read" class="mt-1 size-1.5 shrink-0 rounded-full bg-accent-500" />
              <span>{{ notificationText(n).title }}</span>
            </p>
            <p v-if="n.body" class="mt-0.5 text-xs text-slate-500">{{ notificationText(n).body }}</p>
            <p class="mt-0.5 text-[11px] text-slate-400" :title="formatDateTime(n.createdAt)">{{ timeAgo(n.createdAt) }} · {{ notificationType(n.eventType) }}</p>
          </button>
        </li>
      </ul>
    </div>
  </div>
</template>
