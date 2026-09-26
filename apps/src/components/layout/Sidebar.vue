<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  LayoutDashboard, BellRing, ShieldAlert, ShieldCheck, ScanSearch, TriangleAlert,
  FileBarChart2, LibraryBig, Settings, ChevronsLeft, ChevronsRight,
} from 'lucide-vue-next'
import { useSessionStore } from '@/stores/session'
import { navFor, type NavItem, type NavKey } from '@/utils/workspace'
import { useI18n, type MsgKey } from '@/i18n'

const route = useRoute()
const session = useSessionStore()
const { t } = useI18n()
const roleLabel = computed(() => (['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? '') ? t(`role.${session.role}` as MsgKey) : t('role.unknown')))
const navLabel = (k: NavKey) => t(`nav.${k}` as MsgKey)

// Tablet / mobile: compact icon rail by default (the user can still expand it).
const media = typeof window !== 'undefined' ? window.matchMedia('(max-width: 1023px)') : null
const collapsed = ref(media?.matches ?? false)
const onMedia = (e: MediaQueryListEvent) => (collapsed.value = e.matches)
onMounted(() => media?.addEventListener('change', onMedia))
onUnmounted(() => media?.removeEventListener('change', onMedia))

const ICON: Record<NavKey, unknown> = {
  dashboard: LayoutDashboard, alerts: BellRing, incidents: ShieldAlert,
  tickets: ShieldCheck, verification: ScanSearch, escalated: TriangleAlert,
  reports: FileBarChart2, knowledge: LibraryBig, settings: Settings,
}

// Workspace per role (visibility only — the backend enforces every action).
const navItems = computed(() => navFor(session.role))

function isActive(item: NavItem) {
  const [path, qs] = item.to.split('?')
  const view = qs ? new URLSearchParams(qs).get('view') : null
  if (path === '/incidents') {
    // Incident detail: highlight "Incidents", or the role's first incident list (IR: Response Tickets come from the Incidents list).
    if (route.path.startsWith('/incidents/')) return item.key === (navItems.value.find((i) => i.to.startsWith('/incidents'))?.key ?? 'incidents')
    return route.path === '/incidents' && (route.query.view ?? null) === view
  }
  return route.path === path || route.path.startsWith(`${path}/`)
}
</script>

<template>
  <aside
    class="flex h-full shrink-0 flex-col app-sidebar border-r border-slate-200 bg-white text-slate-700 transition-all duration-150"
    :class="collapsed ? 'w-[60px] sm:w-[68px]' : 'w-64'"
  >
    <div class="flex h-20 items-center gap-2.5 border-b border-slate-100 px-3 sm:px-4">
      <div class="flex size-8 shrink-0 items-center justify-center rounded-lg bg-accent-600">
        <ShieldCheck class="size-4.5 text-white" />
      </div>
      <div v-if="!collapsed" class="min-w-0 leading-tight">
        <p class="text-xl font-black tracking-[0.16em] text-slate-900">VIGIX</p>
        <p class="truncate text-[10px] text-slate-400">SECURITY OPERATIONS</p>
      </div>
    </div>

    <p v-if="!collapsed" class="px-7 pt-6 text-[10px] font-semibold tracking-[0.18em] text-slate-400">
      {{ t('nav.workspace', { role: roleLabel }).toUpperCase() }}
    </p>
    <nav class="flex-1 space-y-1 overflow-y-auto px-2 py-4 sm:px-3" :aria-label="t('nav.main')">
      <router-link
        v-for="item in navItems"
        :key="item.key"
        :to="item.to"
        :title="navLabel(item.key)"
        :data-tour="`nav-${item.key}`"
        :aria-current="isActive(item) ? 'page' : undefined"
        class="group flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition"
        :class="isActive(item) ? 'bg-accent-50 text-accent-700' : 'text-slate-500 hover:bg-slate-50 hover:text-slate-900'"
      >
        <component :is="ICON[item.key]" class="size-4.5 shrink-0" />
        <span v-if="!collapsed" class="truncate">{{ navLabel(item.key) }}</span>
      </router-link>
    </nav>

    <div class="border-t border-slate-100 px-2 py-3 sm:px-3">
      <div v-if="!collapsed && session.session" class="mb-2.5 space-y-0.5 px-1 text-[11px] text-slate-400">
        <p class="flex items-center gap-1.5"><span class="size-1.5 rounded-full bg-emerald-400" /><span class="font-medium text-slate-600">{{ t('nav.connected') }}</span></p>
        <p class="truncate">{{ session.session.email }} · {{ session.role }}</p>
      </div>
      <button
        type="button"
        class="flex w-full items-center justify-center gap-2 rounded-lg py-1.5 text-slate-400 hover:bg-slate-50 hover:text-accent-600"
        :aria-label="collapsed ? t('nav.expand') : t('nav.collapse')"
        @click="collapsed = !collapsed"
      >
        <component :is="collapsed ? ChevronsRight : ChevronsLeft" class="size-4" />
      </button>
    </div>
  </aside>
</template>
