import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";
import { useAuthStore } from "../../modules/auth/stores/auth.store";
import AuthenticatedLayout from "../layout/AuthenticatedLayout.vue";

const routes: RouteRecordRaw[] = [
  {
    path: "/login",
    name: "login",
    component: () => import("../../modules/auth/views/LoginView.vue"),
    meta: { public: true },
  },
  {
    path: "/",
    component: AuthenticatedLayout,
    redirect: "/dashboard",
    children: [
      {
        path: "dashboard",
        name: "dashboard",
        component: () => import("../../modules/dashboard/views/DashboardView.vue"),
        meta: { title: "SOC Overview" },
      },
      {
        path: "alerts",
        name: "alerts",
        component: () => import("../../modules/alerts/views/AlertsView.vue"),
        meta: { title: "Alerts & Incidents" },
      },
      {
        path: "incidents",
        name: "incidents",
        component: () => import("../../modules/incidents/views/IncidentsView.vue"),
        meta: { title: "Incidents", subtitle: "Grouped cases under active investigation" },
      },
      {
        path: "incidents/:id",
        name: "incident-detail",
        component: () => import("../../modules/incidents/views/IncidentDetailView.vue"),
        meta: { title: "Incident Detail" },
      },
      {
        path: "analytics",
        name: "analytics",
        component: () => import("../../modules/analytics/views/AnalyticsView.vue"),
        meta: { title: "Analytics", subtitle: "MTTR, automation, approval, and execution metrics — live from the database" },
      },
      {
        path: "approval",
        name: "approval",
        component: () => import("../../modules/approval/views/ApprovalView.vue"),
        meta: { title: "Approval Queue", subtitle: "AI-recommended response actions awaiting sign-off" },
      },
      {
        path: "playbooks",
        name: "playbooks",
        component: () => import("../../modules/playbooks/views/PlaybooksView.vue"),
        meta: { title: "Playbooks", subtitle: "Automated response actions and execution history" },
      },
      {
        path: "automation-runs",
        name: "automation-runs",
        component: () => import("../../modules/automation-runs/views/AutomationRunsView.vue"),
        meta: { title: "Automation Runs", subtitle: "Every decision-triggered automation execution — real vs. dry-run, clearly distinguished" },
      },
      {
        path: "automation-runs/:runId",
        name: "automation-run-detail",
        component: () => import("../../modules/automation-runs/views/AutomationRunDetailView.vue"),
        meta: { title: "Automation Run" },
      },
      {
        path: "threat-intelligence",
        name: "threat-intelligence",
        component: () => import("../../modules/threat-intel/views/ThreatIntelView.vue"),
        meta: { title: "Threat Intelligence", subtitle: "Analyze and investigate indicators across threat intelligence sources" },
      },
      {
        path: "mitre",
        name: "mitre",
        component: () => import("../../modules/mitre/views/MitreView.vue"),
        meta: { title: "MITRE ATT&CK", subtitle: "Technique coverage observed across ingested alerts" },
      },
      {
        path: "mitre/matrix",
        name: "mitre-matrix",
        component: () => import("../../modules/mitre/views/MitreMatrixView.vue"),
        meta: { title: "ATT&CK Matrix", subtitle: "Every tactic and technique in the synced MITRE Enterprise knowledge base" },
      },
      {
        path: "mitre/search",
        name: "mitre-search",
        component: () => import("../../modules/mitre/views/MitreSearchView.vue"),
        meta: { title: "Technique Search", subtitle: "Search the synced MITRE knowledge base by ID, name, or description" },
      },
      {
        path: "mitre/techniques/:id",
        name: "mitre-technique-detail",
        component: () => import("../../modules/mitre/views/MitreTechniqueDetailView.vue"),
        meta: { title: "Technique Detail" },
      },
      {
        path: "audit",
        name: "audit",
        component: () => import("../../modules/audit/views/AuditView.vue"),
        meta: { title: "Audit Log", subtitle: "System and user activity history" },
      },
      {
        path: "settings",
        name: "settings",
        component: () => import("../../modules/settings/views/SettingsView.vue"),
        meta: { title: "Settings", subtitle: "Profile, integrations, and system health" },
      },
    ],
  },
  {
    path: "/:pathMatch(.*)*",
    redirect: "/dashboard",
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});

let hasHydrated = false;
router.beforeEach(async (to) => {
  const authStore = useAuthStore();
  if (!hasHydrated) {
    hasHydrated = true;
    await authStore.hydrate();
  }

  if (!to.meta.public && !authStore.isAuthenticated) {
    return { name: "login", query: { redirect: to.fullPath } };
  }
  if (to.name === "login" && authStore.isAuthenticated) {
    return { name: "dashboard" };
  }
  return true;
});
