<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { BellRing, Bot, CheckCircle2, Database, KeyRound, Loader2, Monitor, RotateCcw, Save, ShieldCheck, UserRound, Users, XCircle } from 'lucide-vue-next'
import ChangePasswordForm from '@/components/settings/ChangePasswordForm.vue'
import ChangeEmailForm from '@/components/settings/ChangeEmailForm.vue'
import EmailProviderForm from '@/components/settings/EmailProviderForm.vue'
import PageHeader from '@/components/layout/PageHeader.vue'
import { dashboardApi, settingsApi, slaApi, systemApi, type NotificationRecipient, type RehuntHealth } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { dateLocale, useI18n, type MsgKey } from '@/i18n'

/**
 * Settings — configuration overview. Everything shown is either reported by the backend's existing status endpoints or
 * taken from this browser/session. Editable: the signed-in user's own email and password (My account) and the per-role
 * notification email (SOC / IR_TEAM / admin, enforced by the backend). No secret (API keys, webhook secrets, the session
 * token) is ever displayed; the only password ever requested is the user's own, for the change-password form.
 */
type Section = 'account' | 'general' | 'security' | 'integrations'
const { locale: uiLang, t } = useI18n()
const SECTIONS: { key: Section; icon: typeof Monitor }[] = [
  { key: 'account', icon: UserRound },
  { key: 'general', icon: Monitor },
  { key: 'security', icon: ShieldCheck },
  { key: 'integrations', icon: Database },
]

const route = useRoute()
const router = useRouter()
const session = useSessionStore()
const ui = useUiStore()
const active = ref<Section>(SECTIONS.some((s) => s.key === route.query.section) ? (route.query.section as Section) : 'general')
watch(active, (k) => router.replace({ query: { ...route.query, section: k } }))
const health = ref<{ status: string; service: string; timestamp: string } | null>(null)
const healthError = ref(false)
const rehunt = ref<RehuntHealth | null>(null)
const rehuntError = ref(false)
const ai = ref<{ reachable: boolean; latencyMs: number | null } | null>(null)
const aiState = ref<'idle' | 'loading' | 'error' | 'done'>('idle')

onMounted(async () => {
  await Promise.all([
    systemApi.health().then((h) => (health.value = h)).catch(() => (healthError.value = true)),
    slaApi.rehuntHealth().then((h) => (rehunt.value = h)).catch(() => (rehuntError.value = true)),
  ])
})

// The AI orchestrator status only comes with the dashboard summary (a heavier call), so it loads on demand.
async function loadAi() {
  if (aiState.value === 'loading' || aiState.value === 'done') return
  aiState.value = 'loading'
  try {
    ai.value = (await dashboardApi.summary(1)).integrations.aiOrchestrator
    aiState.value = 'done'
  } catch {
    aiState.value = 'error'
  }
}
watch(active, (k) => k === 'integrations' && loadAi(), { immediate: true })

// Session: only non-secret claims are read from the token payload (expiry, tenant). The token itself is never shown.
const claims = computed(() => {
  const token = session.session?.token
  if (!token) return null
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
    return { exp: typeof payload.exp === 'number' ? new Date(payload.exp * 1000) : null, tenantId: typeof payload.tenantId === 'string' ? payload.tenantId : null }
  } catch {
    return null
  }
})

const mode = import.meta.env.MODE
const tz = Intl.DateTimeFormat().resolvedOptions().timeZone
const locale = navigator.language
const fmt = (d: Date | string | null | undefined) => (d ? new Date(d).toLocaleString(dateLocale(), { dateStyle: 'medium', timeStyle: 'medium' }) : '—')

/**
 * What the signed-in role may do. This mirrors the backend's route gates for display only — the backend enforces
 * them on every request, and ticket approval is decided per ticket by Policy.
 */
const role = computed(() => session.role ?? '—')
const isAdmin = computed(() => session.role === 'admin')
const permissions = computed(() => [
  { label: t('set.p.view'), allowed: !!session.session, who: t('set.p.viewWho') },
  { label: t('set.p.triage'), allowed: session.canTriage, who: 'SOC' },
  { label: t('set.p.generate'), allowed: ['SOC', 'IR_TEAM'].includes(session.role ?? '') || isAdmin.value, who: 'SOC, IR_TEAM' },
  { label: t('set.p.handoff'), allowed: session.role === 'SOC' || isAdmin.value, who: 'SOC' },
  { label: t('set.p.execute'), allowed: session.canExecuteResponse, who: 'IR_TEAM' },
  { label: t('set.p.recipients'), allowed: session.canEditRecipients, who: 'SOC, IR_TEAM' },
  { label: t('set.p.decide'), allowed: session.role === 'IR_TEAM', who: t('set.p.decideWho') },
  { label: t('set.p.email'), allowed: ['SOC', 'IR_TEAM'].includes(session.role ?? '') || isAdmin.value, who: 'SOC, IR_TEAM' },
])

// ---------------------------------------------------------------- notification recipients (SOC / IR_TEAM / admin edit, others see masked)
const recipients = ref<NotificationRecipient[]>([])
const recipientsState = ref<'loading' | 'error' | 'done'>('loading')
const drafts = ref<Record<string, string>>({})
const savingRole = ref<string | null>(null)
const recipientErrors = ref<Record<string, string>>({})
const roleLabel = (r: string) => (['SOC', 'IR_TEAM', 'ADMIN'].includes(r) ? t(`set.role.${r}` as MsgKey) : r)
const sourceLabel = (s: string) => (['settings', 'server', 'none'].includes(s) ? t(`set.src.${s}` as MsgKey) : s)

function applyRecipients(items: NotificationRecipient[]) {
  recipients.value = items
  drafts.value = Object.fromEntries(items.map((r) => [r.role, r.source === 'settings' ? (r.email ?? '') : '']))
}
async function loadRecipients() {
  recipientsState.value = 'loading'
  try {
    applyRecipients((await settingsApi.notificationRecipients()).items)
    recipientsState.value = 'done'
  } catch {
    recipientsState.value = 'error'
  }
}
onMounted(loadRecipients)

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const draftInvalid = (role: string) => !!drafts.value[role]?.trim() && !EMAIL_RE.test(drafts.value[role].trim())
const draftChanged = (r: NotificationRecipient) => (drafts.value[r.role] ?? '').trim().toLowerCase() !== (r.source === 'settings' ? (r.email ?? '') : '')

async function saveRecipient(role: string, email: string | null) {
  if (savingRole.value || !session.canEditRecipients) return
  savingRole.value = role
  recipientErrors.value = { ...recipientErrors.value, [role]: '' }
  try {
      await settingsApi.setNotificationRecipient(role, email)
      applyRecipients((await settingsApi.notificationRecipients()).items)
    ui.success(email ? t('set.saved') : t('set.reverted'), t('set.savedBody', { role: roleLabel(role), to: email ? ` → ${email.trim().toLowerCase()}` : '' }))
  } catch (e) {
    const code = e instanceof ApiError ? e.code : 'UNKNOWN'
    recipientErrors.value = {
      ...recipientErrors.value,
      [role]: code === 'INVALID_EMAIL' ? t('set.err.invalid') : code === 'FORBIDDEN' || code === 'HTTP_403' ? t('set.err.forbidden') : t('set.err.refused', { code }),
    }
  } finally {
    savingRole.value = null
  }
}

const rehuntProvider = computed(() => (rehunt.value?.provider === 'mock' || rehunt.value?.clusterStatus === 'mock' ? t('set.mockFixtures') : t('tk.wazuhIndexer')))
</script>

<template>
  <div>
    <PageHeader :title="t('ui.page.settings')" :description="t('set.description')" />

    <div class="flex flex-col gap-5 lg:flex-row">
      <nav class="card flex shrink-0 flex-row gap-0.5 overflow-x-auto p-1.5 lg:w-56 lg:flex-col lg:overflow-visible" :aria-label="t('set.sectionsAria')">
        <button
          v-for="s in SECTIONS"
          :key="s.key"
          type="button"
          class="flex shrink-0 items-center gap-2 whitespace-nowrap rounded-lg px-3 py-2 text-left text-sm font-medium transition"
          :class="active === s.key ? 'bg-accent-50 text-accent-700' : 'text-slate-500 hover:bg-slate-50 hover:text-slate-700'"
          :aria-current="active === s.key ? 'page' : undefined"
          @click="active = s.key"
        >
          <component :is="s.icon" class="size-4" /> {{ t(`set.sec.${s.key}`) }}
        </button>
      </nav>

      <div class="min-w-0 flex-1 space-y-4">
        <!-- ================= My account ================= -->
        <template v-if="active === 'account'">
          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><UserRound class="size-4 text-slate-400" /> {{ t('acc.profile') }}</h2>
            <p class="mt-1 text-xs text-slate-500">{{ t('acc.profileHint') }}</p>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('acc.email') }}</dt><dd class="mt-0.5 truncate text-slate-800">{{ session.session?.email ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.role') }}</dt><dd class="mt-0.5 font-semibold text-slate-900">{{ role }}</dd></div>
              <div><dt class="text-xs text-slate-400">Tenant</dt><dd class="mt-0.5 truncate font-mono text-xs text-slate-800">{{ claims?.tenantId ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.expires') }}</dt><dd class="mt-0.5 text-slate-800">{{ fmt(claims?.exp) }}</dd></div>
            </dl>
          </section>
          <ChangeEmailForm />
          <ChangePasswordForm />
        </template>

        <!-- ================= General ================= -->
        <template v-else-if="active === 'general'">
          <section class="card p-5">
            <h2 class="text-sm font-semibold text-slate-900">{{ t('set.systemInfo') }}</h2>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('set.backendService') }}</dt><dd class="mt-0.5 font-mono text-slate-800">{{ health?.service ?? (healthError ? t('set.unreachable') : '…') }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.backendStatus') }}</dt><dd class="mt-0.5">
                <span v-if="health" class="inline-flex items-center gap-1 font-semibold text-emerald-700"><CheckCircle2 class="size-4" /> {{ health.status }}</span>
                <span v-else-if="healthError" class="inline-flex items-center gap-1 font-semibold text-rose-700"><XCircle class="size-4" /> {{ t('set.unreachable') }}</span>
                <Loader2 v-else class="size-4 animate-spin text-slate-300" />
              </dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.backendClock') }}</dt><dd class="mt-0.5 text-slate-800">{{ fmt(health?.timestamp) }}</dd></div>
              <div><dt class="text-xs text-slate-400">API</dt><dd class="mt-0.5 font-mono text-slate-800">{{ t('set.sameOrigin') }}</dd></div>
              <div><dt class="text-xs text-slate-400">Tenant</dt><dd class="mt-0.5 truncate font-mono text-xs text-slate-800">{{ claims?.tenantId ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">Frontend build</dt><dd class="mt-0.5 font-mono text-slate-800">vite · {{ mode }}</dd></div>
            </dl>
          </section>
          <section class="card p-5">
            <h2 class="text-sm font-semibold text-slate-900">{{ t('set.prefs') }}</h2>
            <p class="mt-1 text-xs text-slate-500">{{ t('set.prefsHint') }}</p>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('set.timezone') }}</dt><dd class="mt-0.5 text-slate-800">{{ tz }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.uiLanguage') }}</dt><dd class="mt-0.5 text-slate-800">{{ t('set.langName') }} ({{ uiLang }})</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.browserLocale') }}</dt><dd class="mt-0.5 text-slate-800">{{ locale }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.dateSample') }}</dt><dd class="mt-0.5 text-slate-800">{{ fmt(new Date()) }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.evidenceTs') }}</dt><dd class="mt-0.5 text-slate-800">{{ t('set.utc') }}</dd></div>
            </dl>
          </section>
        </template>

        <!-- ================= Security ================= -->
        <template v-else-if="active === 'security'">
          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><KeyRound class="size-4 text-slate-400" /> {{ t('set.auth') }}</h2>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('set.method') }}</dt><dd class="mt-0.5 text-slate-800">{{ t('set.methodValue') }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.signedInAs') }}</dt><dd class="mt-0.5 truncate text-slate-800">{{ session.session?.email ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.role') }}</dt><dd class="mt-0.5 font-semibold text-slate-900">{{ role }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.expires') }}</dt><dd class="mt-0.5 text-slate-800">{{ fmt(claims?.exp) }}</dd></div>
            </dl>
            <p class="mt-4 text-xs text-slate-500">{{ t('set.tokenNote') }}</p>
          </section>
          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><Users class="size-4 text-slate-400" /> {{ t('set.permissions') }}</h2>
            <p class="mt-1 text-xs text-slate-500">{{ t('set.permIntro', { role }) }}{{ isAdmin ? t('set.adminPasses') : '' }}</p>
            <div class="mt-4 overflow-x-auto">
              <table class="w-full min-w-[480px] text-sm">
                <thead class="text-left text-xs text-slate-400"><tr><th class="pb-2 pr-3 font-medium">{{ t('set.capability') }}</th><th class="pb-2 pr-3 font-medium">{{ t('set.grantedTo') }}</th><th class="pb-2 text-right font-medium">{{ t('set.you') }}</th></tr></thead>
                <tbody class="divide-y divide-slate-100">
                  <tr v-for="p in permissions" :key="p.label">
                    <td class="py-2 pr-3 text-slate-800">{{ p.label }}</td>
                    <td class="py-2 pr-3 text-xs text-slate-500">{{ p.who }}</td>
                    <td class="py-2 text-right">
                      <CheckCircle2 v-if="p.allowed" class="ml-auto size-4 text-emerald-600" :aria-label="t('set.allowed')" />
                      <XCircle v-else class="ml-auto size-4 text-slate-300" :aria-label="t('set.notAllowed')" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>
        </template>

        <!-- ================= Integrations ================= -->
        <template v-else>
          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><Database class="size-4 text-slate-400" /> Wazuh</h2>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('set.rehuntSource') }}</dt><dd class="mt-0.5 font-semibold text-slate-900">{{ rehunt ? rehuntProvider : rehuntError ? t('set.unavailable') : '…' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.indexPattern') }}</dt><dd class="mt-0.5 font-mono text-slate-800">{{ rehunt?.indexPattern ?? '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.configured') }}</dt><dd class="mt-0.5">{{ rehunt ? (rehunt.configured ? t('c.yes') : t('c.no')) : '—' }}</dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.reachableLabel') }}</dt><dd class="mt-0.5">
                <span v-if="rehunt" class="inline-flex items-center gap-1 font-semibold" :class="rehunt.reachable ? 'text-emerald-700' : 'text-rose-700'"><component :is="rehunt.reachable ? CheckCircle2 : XCircle" class="size-4" /> {{ rehunt.reachable ? t('c.yes') : t('c.no') }}</span>
                <span v-else>—</span>
              </dd></div>
              <div v-if="rehunt?.clusterStatus"><dt class="text-xs text-slate-400">{{ t('set.cluster') }}</dt><dd class="mt-0.5">{{ rehunt.clusterStatus }}</dd></div>
              <div v-if="rehunt?.alertIndices != null"><dt class="text-xs text-slate-400">{{ t('set.alertIndices') }}</dt><dd class="mt-0.5">{{ rehunt.alertIndices }}</dd></div>
              <div v-if="rehunt?.error" class="sm:col-span-2"><dt class="text-xs text-slate-400">{{ t('set.lastError') }}</dt><dd class="mt-0.5 text-rose-700">{{ rehunt.error }}</dd></div>
            </dl>
            <p class="mt-4 text-xs text-slate-500">{{ t('set.webhookNote', { path: '/api/v1/webhooks/siem/wazuh' }) }}</p>
          </section>

          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><BellRing class="size-4 text-slate-400" /> {{ t('set.notification') }}</h2>
            <p class="mt-2 text-sm text-slate-700">{{ t('set.notificationIntro') }}</p>
            <EmailProviderForm v-if="isAdmin" />
            <p v-else class="mt-3 text-xs text-slate-500">การตั้งค่า SMTP ผู้ส่งเป็นสิทธิ์ผู้ดูแลระบบ ส่วนผู้รับ IR ตั้งค่าได้ด้านล่าง</p>
            <h3 class="mt-5 text-xs font-semibold uppercase tracking-wide text-slate-400">{{ t('set.recipientPerRole') }}</h3>
            <p class="mt-1 text-xs text-slate-500">
              <template v-if="session.canEditRecipients">{{ t('set.recipientEditHint') }}</template>
              <template v-else>{{ t('set.recipientReadHint') }}</template>
            </p>
            <p v-if="recipientsState === 'loading'" class="mt-3 flex items-center gap-2 text-sm text-slate-500" role="status"><Loader2 class="size-4 animate-spin" /> {{ t('c.loading') }}</p>
            <p v-else-if="recipientsState === 'error'" class="mt-3 rounded-lg bg-rose-50 px-3 py-2 text-sm text-rose-700" role="alert">{{ t('set.recipientsFailed') }} <button type="button" class="font-semibold underline" @click="loadRecipients">{{ t('c.retry') }}</button></p>
            <ul v-else class="mt-3 divide-y divide-slate-100 rounded-lg border border-slate-200">
              <li v-for="r in recipients" :key="r.role" class="px-3 py-3">
                <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span class="w-44 shrink-0 text-sm font-semibold text-slate-800">{{ roleLabel(r.role) }} <span class="font-mono text-[11px] font-normal text-slate-400">{{ r.role }}</span></span>
                  <span class="min-w-0 flex-1 truncate font-mono text-sm" :class="r.email ? 'text-slate-800' : 'text-slate-400'">{{ r.email ?? t('set.noEmail') }}</span>
                  <span
                    class="rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset"
                    :class="r.source === 'settings' ? 'bg-accent-50 text-accent-700 ring-accent-200' : r.source === 'server' ? 'bg-slate-100 text-slate-600 ring-slate-200' : 'bg-amber-50 text-amber-800 ring-amber-200'"
                  >{{ sourceLabel(r.source) }}</span>
                </div>
                <p v-if="r.updatedAt" class="mt-1 text-[11px] text-slate-400">{{ t('set.changed', { at: fmt(r.updatedAt) }) }}</p>
                <form v-if="session.canEditRecipients" class="mt-2 flex flex-wrap items-start gap-2" @submit.prevent="saveRecipient(r.role, drafts[r.role]?.trim() || null)">
                  <label class="min-w-0 flex-1 basis-56">
                    <span class="sr-only">{{ t('set.emailFor', { role: r.role }) }}</span>
                    <input
                      v-model="drafts[r.role]"
                      type="email"
                      autocomplete="off"
                      :placeholder="r.hasServerDefault ? t('set.useDefaultPlaceholder') : 'name@example.com'"
                      class="w-full rounded-lg border px-3 py-1.5 text-sm focus:outline-none"
                      :class="draftInvalid(r.role) ? 'border-rose-400 focus:border-rose-500' : 'border-slate-300 focus:border-accent-500'"
                      :aria-invalid="draftInvalid(r.role)"
                    />
                  </label>
                  <button type="submit" class="inline-flex items-center gap-1.5 rounded-lg bg-navy-800 px-3 py-1.5 text-sm font-semibold text-white hover:bg-navy-700 disabled:cursor-not-allowed disabled:opacity-40" :disabled="savingRole === r.role || draftInvalid(r.role) || !draftChanged(r)">
                    <Loader2 v-if="savingRole === r.role" class="size-4 animate-spin" /><Save v-else class="size-4" /> {{ t('c.save') }}
                  </button>
                  <button v-if="r.source === 'settings'" type="button" class="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-sm text-slate-700 hover:bg-slate-50 disabled:opacity-40" :disabled="savingRole === r.role" @click="saveRecipient(r.role, null)">
                    <RotateCcw class="size-4" /> {{ t('set.useDefault') }}
                  </button>
                </form>
                <p v-if="recipientErrors[r.role]" class="mt-1 text-xs text-rose-700" role="alert">{{ recipientErrors[r.role] }}</p>
              </li>
            </ul>
            <p class="mt-3 text-xs text-slate-500">{{ t('set.channelsNote') }}</p>
          </section>

          <section class="card p-5">
            <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><Bot class="size-4 text-slate-400" /> AI / LLM</h2>
            <dl class="mt-4 grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
              <div><dt class="text-xs text-slate-400">{{ t('set.aiOrchestrator') }}</dt><dd class="mt-0.5">
                <span v-if="aiState === 'loading'" class="inline-flex items-center gap-1.5 text-slate-500"><Loader2 class="size-4 animate-spin" /> {{ t('set.checking') }}</span>
                <span v-else-if="aiState === 'error'" class="text-rose-700">{{ t('set.statusUnavailable') }} <button type="button" class="ml-1 text-xs underline" @click="aiState = 'idle'; loadAi()">{{ t('c.retry') }}</button></span>
                <span v-else-if="ai" class="inline-flex items-center gap-1 font-semibold" :class="ai.reachable ? 'text-emerald-700' : 'text-rose-700'"><component :is="ai.reachable ? CheckCircle2 : XCircle" class="size-4" /> {{ ai.reachable ? t('set.reachable') : t('set.unreachable') }}</span>
                <span v-else>—</span>
              </dd></div>
              <div><dt class="text-xs text-slate-400">{{ t('set.latency') }}</dt><dd class="mt-0.5">{{ ai?.latencyMs != null ? `${ai.latencyMs} ms` : '—' }}</dd></div>
            </dl>
            <p class="mt-4 text-xs text-slate-500">{{ t('set.aiNote') }}</p>
          </section>
        </template>
      </div>
    </div>
  </div>
</template>
