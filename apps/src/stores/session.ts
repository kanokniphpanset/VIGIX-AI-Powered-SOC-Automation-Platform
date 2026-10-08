import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { authApi } from '@/api/vigix'
import { currentSession, setSession, type StoredSession } from '@/api/http'

/** Real session against apps/backend (POST /api/auth/login). Role gates in the UI are hints; the backend enforces them. */
export const useSessionStore = defineStore('session', () => {
  const session = ref<StoredSession | null>(currentSession())
  const isAuthenticated = computed(() => !!session.value)
  const role = computed(() => session.value?.role ?? null)
  // Display hint only; the backend verifies the JWT and enforces ownership on every mutation.
  const userId = computed<string | null>(() => {
    try { return JSON.parse(atob((session.value?.token.split('.')[1] ?? '').replace(/-/g, '+').replace(/_/g, '/'))).id ?? null } catch { return null }
  })
  const canTriage = computed(() => role.value === 'SOC')
  /** Mirrors the backend gate on POST /api/responses/:id/start|complete|fail and re-hunt (requireOperationalRole("IR_TEAM")): admin is a system role and never executes. */
  const canExecuteResponse = computed(() => role.value === 'IR_TEAM')
  /** Mirrors the backend IR hand-off gate (IR_HANDOFF_SENDER_ROLES = SOC; admin passes): send article / guide / hand-off. */
  const canSendToIr = computed(() => role.value === 'SOC' || role.value === 'admin')
  /** Mirrors AI_ANALYSIS_RUN_ROLES (SOC, IR_TEAM; admin passes): Run / Re-run AI Analysis. */
  const canRunAiAnalysis = computed(() => role.value === 'SOC' || role.value === 'IR_TEAM' || role.value === 'admin')
  /** Mirrors NOTIFICATION_RECIPIENT_EDITOR_ROLES (SOC, IR_TEAM; admin passes): edit per-role notification emails. */
  const canEditRecipients = computed(() => role.value === 'SOC' || role.value === 'IR_TEAM' || role.value === 'admin')

  async function login(email: string, password: string) {
    const res = await authApi.login(email, password)
    session.value = { token: res.token, role: res.role, email }
    setSession(session.value)
  }

  /** After a successful self-service email change: the token carries no email, so only the stored session label changes. */
  function setEmail(email: string) {
    if (!session.value) return
    session.value = { ...session.value, email }
    setSession(session.value)
  }

  function logout() {
    session.value = null
    setSession(null)
  }

  return { session, userId, isAuthenticated, role, canTriage, canExecuteResponse, canSendToIr, canEditRecipients, canRunAiAnalysis, login, setEmail, logout }
})
