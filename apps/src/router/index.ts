import { createRouter, createWebHistory } from 'vue-router'
import { currentSession, setUnauthorizedHandler } from '@/api/http'
import { useSessionStore } from '@/stores/session'
import { isExpiredToken } from '@/utils/session'
import { tr, type MsgKey } from '@/i18n'

declare module 'vue-router' {
  interface RouteMeta {
    /** Page name as a message key (shown in the current language). */
    title?: MsgKey
    /** Reachable without signing in, rendered without the app shell (login). */
    public?: boolean
  }
}

/**
 * Every route below runs on the real VIGIX backend (no mock data).
 * Flow (two roles): Alert Inbox (SOC) -> Incident (SOC investigation, AI analysis, recommendation, Send to IR)
 *   -> Response Tickets (IR APPROVE / REJECT, execution) -> Verification (re-hunt).
 * The sidebar shows each role its own workspace (utils/workspace.ts); the backend enforces every action.
 */
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  scrollBehavior() {
    return { top: 0 }
  },
  routes: [
    { path: '/', redirect: '/dashboard' },
    { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue'), meta: { title: 'ui.page.login', public: true } },
    { path: '/dashboard', name: 'dashboard', component: () => import('@/views/dashboard/OperationsDashboardView.vue'), meta: { title: 'ui.page.dashboard' } },
    { path: '/alerts', name: 'alerts', component: () => import('@/views/alerts/AlertInboxView.vue'), meta: { title: 'ui.page.alerts' } },
    { path: '/alerts/:id', name: 'alert-detail', component: () => import('@/views/alerts/AlertDetailView.vue'), meta: { title: 'ui.page.alert' } },
    // SOC LOW triage now lives in the Alert Inbox (tabs Awaiting triage / Monitoring / Triaged); old links still work.
    { path: '/triage', redirect: '/alerts?triage=pending' },
    // The IR decision happens on the Response Ticket itself; the old approval-queue link lands on the tickets awaiting it.
    { path: '/approvals', redirect: '/tickets?queue=awaiting-decision' },
    // The former Verification page now lives on the Response Tickets page ("awaiting re-hunt" queue + recent verdicts).
    { path: '/verification', redirect: { path: '/tickets', query: { queue: 'awaiting-rehunt' } } },
    { path: '/incidents', name: 'incidents', component: () => import('@/views/incidents/IncidentsView.vue'), meta: { title: 'ui.page.incidents' } },
    { path: '/incidents/:id', name: 'incident-detail', component: () => import('@/views/incidents/IncidentDetailView.vue'), meta: { title: 'ui.page.incident' } },
    // IR Ticket queue: IR decision (approve / reject, note required) -> respond -> re-hunt -> resolved / new cycle / escalated.
    { path: '/tickets', name: 'tickets', component: () => import('@/views/tickets/TicketQueueView.vue'), meta: { title: 'ui.page.tickets' } },
    { path: '/tickets/:id', name: 'ticket-detail', component: () => import('@/views/tickets/TicketDetailView.vue'), meta: { title: 'ui.page.ticket' } },
    { path: '/reports', name: 'reports', component: () => import('@/views/reports/ReportBuilderView.vue'), meta: { title: 'ui.page.reports' } },
    // Read-only: knowledge libraries from the backend's list endpoints; settings = configuration overview.
    { path: '/knowledge', name: 'knowledge', component: () => import('@/views/knowledge/KnowledgeView.vue'), meta: { title: 'ui.page.knowledge' } },
    { path: '/settings', name: 'settings', component: () => import('@/views/settings/SettingsView.vue'), meta: { title: 'ui.page.settings' } },
    { path: '/:pathMatch(.*)*', name: 'not-found', component: () => import('@/views/NotFoundView.vue'), meta: { title: 'ui.page.notFound' } },
  ],
})

router.beforeEach((to) => {
  const session = currentSession()
  if (session && isExpiredToken(session.token)) useSessionStore().logout()
  if (!to.meta.public && !currentSession()) return { name: 'login', query: { next: to.fullPath } }
  if (to.name === 'login' && currentSession()) return '/dashboard'
  return true
})

// An expired/invalid token anywhere sends the user back to sign in.
setUnauthorizedHandler(() => {
  useSessionStore().logout()
  if (router.currentRoute.value.name !== 'login') void router.push({ name: 'login', query: { next: router.currentRoute.value.fullPath } })
})

/** Browser tab title in the current language (App.vue calls it again when the language changes). */
export function applyTitle(title: MsgKey | undefined = router.currentRoute.value.meta.title) {
  const base = 'VIGIX'
  document.title = title ? `${tr(title)} · ${base}` : base
}
router.afterEach((to) => applyTitle(to.meta.title))

export default router
