<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ShieldCheck } from 'lucide-vue-next'
import { useSessionStore } from '@/stores/session'
import { ApiError } from '@/api/http'
import { safeNext } from '@/utils/session'
import { useI18n } from '@/i18n'
import { LANGS } from '@/i18n/messages'

const session = useSessionStore()
const { locale, setLocale, t } = useI18n()
const router = useRouter()
const route = useRoute()

const email = ref('soc@soar-platform.local')
const password = ref('')
const error = ref('')
const busy = ref(false)

const demoUsers = [
  { email: 'soc@soar-platform.local', role: 'lg.roleSoc' },
  { email: 'irteam@soar-platform.local', role: 'lg.roleIr' },
] as const

async function submit() {
  if (busy.value) return
  error.value = ''
  busy.value = true
  try {
    await session.login(email.value.trim(), password.value)
    const next = safeNext(route.query.next)
    await router.replace(next)
  } catch (e) {
    error.value = e instanceof ApiError && e.status === 401 ? t('lg.wrong') : t('lg.unreachable')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-surface-100 px-4">
    <form class="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-7 shadow-sm" @submit.prevent="submit">
      <div class="-mt-2 mb-3 flex justify-end gap-1" role="group" :aria-label="t('lang.label')">
        <button v-for="l in LANGS" :key="l" type="button" class="rounded px-2 py-0.5 text-[11px] font-semibold" :class="locale === l ? 'bg-navy-800 text-white' : 'text-slate-500 hover:bg-slate-100'" :aria-pressed="locale === l" @click="setLocale(l)">{{ t(`lang.${l}`) }}</button>
      </div>
      <div class="mb-6 flex items-center gap-2.5">
        <span class="flex size-9 items-center justify-center rounded-lg bg-navy-800 text-white"><ShieldCheck class="size-5" /></span>
        <div>
          <h1 class="text-lg font-bold text-slate-900">{{ t('lg.title') }}</h1>
          <p class="text-xs text-slate-500">{{ t('lg.subtitle') }}</p>
        </div>
      </div>

      <label class="mb-1 block text-xs font-semibold text-slate-600" for="email">{{ t('lg.email') }}</label>
      <input id="email" v-model="email" type="email" autocomplete="username" required class="mb-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none" />

      <label class="mb-1 block text-xs font-semibold text-slate-600" for="password">{{ t('lg.password') }}</label>
      <input id="password" v-model="password" type="password" autocomplete="current-password" required class="mb-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:border-accent-500 focus:outline-none" />

      <p v-if="error" class="mb-3 rounded-md bg-rose-50 px-3 py-2 text-xs text-rose-700" role="alert">{{ error }}</p>

      <button type="submit" :disabled="busy" class="w-full rounded-lg bg-navy-800 px-3 py-2 text-sm font-semibold text-white hover:bg-navy-700 disabled:opacity-60">
        {{ busy ? t('lg.signingIn') : t('lg.signIn') }}
      </button>

      <div class="mt-5 border-t border-slate-100 pt-4">
        <p class="mb-2 text-[11px] font-semibold uppercase tracking-wide text-slate-400">{{ t('lg.seeded') }}</p>
        <button
          v-for="u in demoUsers"
          :key="u.email"
          type="button"
          class="flex w-full justify-between rounded-md px-2 py-1 text-left text-xs text-slate-600 hover:bg-slate-50"
          @click="email = u.email"
        >
          <span>{{ u.email }}</span><span class="text-slate-400">{{ t(u.role) }}</span>
        </button>
      </div>
    </form>
  </div>
</template>
