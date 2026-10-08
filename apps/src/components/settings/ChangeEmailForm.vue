<script setup lang="ts">
// Settings → My account → Change email. The backend (POST /api/auth/change-email) is the real check: the account is
// always the signed-in user from the JWT, the current password is required, and an email another user has is refused.
// The token carries no email, so on success the session stays and only its stored email label is updated.
import { computed, reactive, ref } from 'vue'
import { Eye, EyeOff, Loader2, Mail } from 'lucide-vue-next'
import { authApi } from '@/api/vigix'
import { ApiError } from '@/api/http'
import { useSessionStore } from '@/stores/session'
import { useUiStore } from '@/stores/ui'
import { hasMsg } from '@/i18n/messages'
import { useI18n, type MsgKey } from '@/i18n'

type Field = 'newEmail' | 'currentPassword'

const { t } = useI18n()
const session = useSessionStore()
const ui = useUiStore()

const form = reactive({ newEmail: '', currentPassword: '' })
const touched = reactive<Record<Field, boolean>>({ newEmail: false, currentPassword: false })
const serverErrors = ref<Partial<Record<Field, string>>>({})
const formError = ref('')
const showPassword = ref(false)
const busy = ref(false)

const current = computed(() => session.session?.email ?? '')
/** Same shape check the backend's zod .email() makes, for a clear message before sending. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
const clientErrors = computed(() => {
  const e: Partial<Record<Field, string>> = {}
  const email = form.newEmail.trim()
  if (!email) e.newEmail = 'emailRequired'
  else if (!EMAIL_RE.test(email) || email.length > 254) e.newEmail = 'emailInvalid'
  else if (email.toLowerCase() === current.value.trim().toLowerCase()) e.newEmail = 'EMAIL_UNCHANGED'
  if (!form.currentPassword) e.currentPassword = 'currentRequired'
  return e
})
const errorOf = (f: Field) => serverErrors.value[f] ?? (touched[f] ? clientErrors.value[f] : undefined)
const msg = (code: string) => (hasMsg(`acc.err.${code}`) ? t(`acc.err.${code}` as MsgKey) : code)

function edited(f: Field) {
  serverErrors.value = { ...serverErrors.value, [f]: undefined }
  formError.value = ''
}

async function submit() {
  touched.newEmail = touched.currentPassword = true
  serverErrors.value = {}
  formError.value = ''
  if (Object.keys(clientErrors.value).length) return
  busy.value = true
  try {
    const res = await authApi.changeEmail({ newEmail: form.newEmail.trim(), currentPassword: form.currentPassword })
    session.setEmail(res.email)
    form.newEmail = form.currentPassword = ''
    touched.newEmail = touched.currentPassword = false
    ui.success(t('acc.emailDone'), t('acc.emailDoneHint', { email: res.email }))
  } catch (e) {
    const code = e instanceof ApiError ? e.code : ''
    if (code === 'CURRENT_PASSWORD_INCORRECT') serverErrors.value = { currentPassword: code }
    else if (code === 'EMAIL_TAKEN' || code === 'EMAIL_UNCHANGED' || code === 'VALIDATION_ERROR') serverErrors.value = { newEmail: code }
    else formError.value = t('acc.failed')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <section class="card p-5" data-testid="change-email">
    <h2 class="flex items-center gap-2 text-sm font-semibold text-slate-900"><Mail class="size-4 text-slate-400" /> {{ t('acc.changeEmail') }}</h2>
    <p class="mt-1 text-xs text-slate-500">{{ t('acc.changeEmailHint') }}</p>

    <form class="mt-4 max-w-xl space-y-3" novalidate @submit.prevent="submit">
      <div>
        <p class="text-xs font-medium text-slate-600">{{ t('acc.currentEmail') }}</p>
        <p class="mt-1 truncate rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-700">{{ current || '—' }}</p>
      </div>

      <div>
        <label for="em-new" class="text-xs font-medium text-slate-600">{{ t('acc.newEmail') }}</label>
        <input
          id="em-new"
          v-model="form.newEmail"
          type="email"
          autocomplete="email"
          inputmode="email"
          :aria-invalid="!!errorOf('newEmail')"
          :aria-describedby="errorOf('newEmail') ? 'em-new-err' : undefined"
          :disabled="busy"
          class="mt-1 w-full rounded-lg border px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-accent-100"
          :class="errorOf('newEmail') ? 'border-rose-300' : 'border-slate-300'"
          @input="edited('newEmail')"
          @blur="touched.newEmail = true"
        />
        <p v-if="errorOf('newEmail')" id="em-new-err" class="mt-1 text-xs text-rose-600">{{ msg(errorOf('newEmail')!) }}</p>
      </div>

      <div>
        <label for="em-pw" class="text-xs font-medium text-slate-600">{{ t('acc.current') }}</label>
        <div class="relative mt-1">
          <input
            id="em-pw"
            v-model="form.currentPassword"
            :type="showPassword ? 'text' : 'password'"
            autocomplete="current-password"
            :aria-invalid="!!errorOf('currentPassword')"
            :aria-describedby="errorOf('currentPassword') ? 'em-pw-err' : undefined"
            :disabled="busy"
            class="w-full rounded-lg border px-3 py-2 pr-10 text-sm outline-none focus:ring-2 focus:ring-accent-100"
            :class="errorOf('currentPassword') ? 'border-rose-300' : 'border-slate-300'"
            @input="edited('currentPassword')"
            @blur="touched.currentPassword = true"
          />
          <button
            type="button"
            class="absolute inset-y-0 right-0 flex w-9 items-center justify-center text-slate-400 hover:text-slate-600"
            :aria-label="showPassword ? t('acc.hide') : t('acc.show')"
            @click="showPassword = !showPassword"
          >
            <EyeOff v-if="showPassword" class="size-4" /><Eye v-else class="size-4" />
          </button>
        </div>
        <p v-if="errorOf('currentPassword')" id="em-pw-err" class="mt-1 text-xs text-rose-600">{{ msg(errorOf('currentPassword')!) }}</p>
      </div>

      <p class="text-[11px] text-slate-500">{{ t('acc.emailNote') }}</p>
      <p v-if="formError" class="text-xs text-rose-600" role="alert">{{ formError }}</p>
      <button type="submit" class="primary-button" :disabled="busy">
        <Loader2 v-if="busy" class="size-4 animate-spin" />{{ busy ? t('acc.saving') : t('acc.emailSubmit') }}
      </button>
    </form>
  </section>
</template>
