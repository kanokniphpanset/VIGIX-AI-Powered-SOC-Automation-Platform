<script setup lang="ts">
// Settings → My account → Change password. The backend (POST /api/auth/change-password) is the real check: the account
// is always the signed-in user from the JWT. The policy here (utils/passwordPolicy) only gives clear messages before
// sending. On success the session is ended and the user signs in again with the new password. No password value is
// ever stored, logged or kept after the request.
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { Check, Eye, EyeOff, KeyRound, Loader2, X } from 'lucide-vue-next'
import { authApi } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { hasMsg } from '@/i18n/messages'
import { useI18n, type MsgKey } from '@/i18n'
import { hasChangePasswordErrors, passwordPolicyViolations, validateChangePassword, type ChangePasswordFieldErrors } from '@/utils/passwordPolicy'

type Field = 'currentPassword' | 'newPassword' | 'confirmPassword'
const FIELDS: { key: Field; label: string; autocomplete: string }[] = [
  { key: 'currentPassword', label: 'acc.current', autocomplete: 'current-password' },
  { key: 'newPassword', label: 'acc.new', autocomplete: 'new-password' },
  { key: 'confirmPassword', label: 'acc.confirm', autocomplete: 'new-password' },
]
const RULES = ['MIN_BYTES', 'CHARACTER_TYPES', 'MAX_BYTES', 'SAME_AS_EMAIL', 'UNCHANGED'] as const

const { t } = useI18n()
const router = useRouter()
const session = useSessionStore()
const ui = useUiStore()

const form = reactive({ currentPassword: '', newPassword: '', confirmPassword: '' })
const visible = reactive<Record<Field, boolean>>({ currentPassword: false, newPassword: false, confirmPassword: false })
const touched = reactive<Record<Field, boolean>>({ currentPassword: false, newPassword: false, confirmPassword: false })
const serverErrors = ref<ChangePasswordFieldErrors>({})
const formError = ref('')
const busy = ref(false)

const email = computed(() => session.session?.email ?? null)
const clientErrors = computed(() => validateChangePassword(form, email.value))
/** Shown per field once it was touched (or after a submit attempt); server errors always show. */
const errorsOf = (f: Field) => [...(touched[f] ? clientErrors.value[f] ?? [] : []), ...(serverErrors.value[f] ?? [])]
const msg = (code: string) => (hasMsg(`acc.err.${code}`) ? t(`acc.err.${code}` as MsgKey) : code)

/** Live checklist for the new password (green once satisfied). */
const broken = computed(() => {
  const rules: string[] = passwordPolicyViolations(form.newPassword, email.value)
  if (form.newPassword && form.newPassword === form.currentPassword) rules.push('UNCHANGED')
  return new Set(rules)
})

function edited(f: Field) {
  serverErrors.value = { ...serverErrors.value, [f]: undefined }
  formError.value = ''
}

async function submit() {
  touched.currentPassword = touched.newPassword = touched.confirmPassword = true
  serverErrors.value = {}
  formError.value = ''
  if (hasChangePasswordErrors(clientErrors.value)) return
  busy.value = true
  try {
    await authApi.changePassword({ ...form })
    form.currentPassword = form.newPassword = form.confirmPassword = ''
    ui.success(t('acc.done'), t('acc.doneHint'))
    session.logout()
    await router.push('/login')
  } catch (e) {
    const code = e instanceof ApiError ? e.code : ''
    if (code === 'CURRENT_PASSWORD_INCORRECT') serverErrors.value = { currentPassword: [code] }
    else if (code === 'PASSWORD_UNCHANGED') serverErrors.value = { newPassword: ['UNCHANGED'] }
    else if (code === 'PASSWORD_CONFIRMATION_MISMATCH') serverErrors.value = { confirmPassword: ['mismatch'] }
    else if (code === 'PASSWORD_POLICY_VIOLATION') {
      const rules = ((e as ApiError).body as { rules?: string[] } | null)?.rules ?? []
      serverErrors.value = { newPassword: rules.length ? rules : [code] }
    } else formError.value = t('acc.failed')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card p-5" data-testid="change-password">
    <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><KeyRound class="size-4 text-slate-400" /> {{ t('acc.changePassword') }}</h2>
    <p class="mt-1 text-xs text-slate-500">{{ t('acc.changePasswordHint') }}</p>

    <form class="mt-4 grid gap-5 md:grid-cols-[minmax(0,1fr)_minmax(0,16rem)]" novalidate @submit.prevent="submit">
      <div class="space-y-3">
        <!-- Hidden username field so password managers attach the new password to the right account. -->
        <input type="email" :value="email ?? ''" autocomplete="username" class="hidden" tabindex="-1" aria-hidden="true" readonly />
        <div v-for="f in FIELDS" :key="f.key">
          <label :for="`pw-${f.key}`" class="text-xs font-medium text-slate-600">{{ t(f.label as MsgKey) }}</label>
          <div class="relative mt-1">
            <input
              :id="`pw-${f.key}`"
              v-model="form[f.key]"
              :type="visible[f.key] ? 'text' : 'password'"
              :autocomplete="f.autocomplete"
              :aria-invalid="errorsOf(f.key).length > 0"
              :aria-describedby="errorsOf(f.key).length ? `pw-${f.key}-err` : undefined"
              :disabled="busy"
              class="w-full rounded-lg border px-3 py-2 pr-10 text-sm outline-none focus:ring-2 focus:ring-accent-100"
              :class="errorsOf(f.key).length ? 'border-rose-300' : 'border-slate-300'"
              @input="edited(f.key)"
              @blur="touched[f.key] = true"
            />
            <button
              type="button"
              class="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-slate-400 hover:text-slate-600"
              :aria-label="visible[f.key] ? t('acc.hide') : t('acc.show')"
              @click="visible[f.key] = !visible[f.key]"
            >
              <EyeOff v-if="visible[f.key]" class="size-4" /><Eye v-else class="size-4" />
            </button>
          </div>
          <ul v-if="errorsOf(f.key).length" :id="`pw-${f.key}-err`" class="mt-1 space-y-0.5 text-xs text-rose-600">
            <li v-for="code in errorsOf(f.key)" :key="code">{{ msg(code) }}</li>
          </ul>
        </div>

        <p v-if="formError" class="text-xs text-rose-600" role="alert">{{ formError }}</p>
        <button type="submit" class="primary-button" :disabled="busy">
          <Loader2 v-if="busy" class="size-4 animate-spin" />{{ busy ? t('acc.saving') : t('acc.submit') }}
        </button>
      </div>

      <div class="h-fit rounded-lg bg-slate-50 p-3 text-xs">
        <p class="font-semibold text-slate-600">{{ t('acc.policyTitle') }}</p>
        <ul class="mt-2 space-y-1.5">
          <li v-for="r in RULES" :key="r" class="flex items-start gap-1.5" :class="form.newPassword && !broken.has(r) ? 'text-emerald-700' : 'text-slate-500'">
            <Check v-if="form.newPassword && !broken.has(r)" class="mt-px size-3.5 shrink-0" />
            <X v-else-if="form.newPassword" class="mt-px size-3.5 shrink-0 text-rose-500" />
            <span v-else class="mt-1.5 size-1.5 shrink-0 rounded-full bg-slate-300" />
            {{ t(`acc.rule.${r}` as MsgKey) }}
          </li>
        </ul>
      </div>
    </form>
  </section>
</template>
