<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ChevronDown, LogOut, UserRound } from 'lucide-vue-next'
import { useSessionStore } from '@/stores/session'
import { useI18n, type MsgKey } from '@/i18n'

const { t } = useI18n()

const session = useSessionStore()
const router = useRouter()
const open = ref(false)
const root = ref<HTMLElement | null>(null)

const email = computed(() => session.session?.email ?? '')
const initials = computed(
  () =>
    email.value
      .split('@')[0]
      .split(/[._-]/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]!.toUpperCase())
      .join('') || '?',
)
const roleLabel = computed(() => (['SOC', 'IR_TEAM', 'admin'].includes(session.role ?? '') ? t(`role.${session.role}` as MsgKey) : (session.role ?? '')))

function openAccount() {
  open.value = false
  router.push({ name: 'settings', query: { section: 'account' } })
}

function signOut() {
  open.value = false
  session.logout()
  router.push('/login')
}

function onClickOutside(e: MouseEvent) {
  if (root.value && !root.value.contains(e.target as Node)) open.value = false
}
onMounted(() => document.addEventListener('mousedown', onClickOutside))
onUnmounted(() => document.removeEventListener('mousedown', onClickOutside))
</script>

<template>
  <div ref="root" class="relative">
    <button type="button" class="flex items-center gap-2.5 rounded-lg py-1 pl-1 pr-2 hover:bg-slate-100" :aria-expanded="open" :aria-label="t('user.account')" @click="open = !open">
      <span class="flex size-8 items-center justify-center rounded-full bg-navy-800 text-xs font-bold text-white">{{ initials }}</span>
      <span class="hidden text-left leading-tight sm:block">
        <span class="block max-w-[180px] truncate text-xs font-semibold text-slate-800">{{ email }}</span>
        <span class="block text-[11px] text-slate-400">{{ roleLabel }}</span>
      </span>
      <ChevronDown class="size-3.5 text-slate-400" />
    </button>
    <div v-if="open" class="absolute right-0 z-40 mt-2 w-64 rounded-xl border border-slate-200 bg-white p-1.5 shadow-lg">
      <div class="px-2.5 py-2">
        <p class="truncate text-xs font-semibold text-slate-700">{{ email }}</p>
        <p class="text-[11px] text-slate-400">{{ t('user.role', { role: roleLabel }) }}</p>
      </div>
      <div class="border-t border-slate-100 px-2.5 py-2">
        <button type="button" class="flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-slate-600 hover:bg-slate-50" @click="openAccount">
          <UserRound class="size-3.5" /> {{ t('acc.menu') }}
        </button>
        <button type="button" class="flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-left text-xs text-slate-600 hover:bg-slate-50" @click="signOut">
          <LogOut class="size-3.5" /> {{ t('user.signOut') }}
        </button>
      </div>
    </div>
  </div>
</template>
