import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";

const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/alerts",
  },
  {
    path: "/alerts",
    name: "alerts",
    component: () => import("../../modules/alerts/views/AlertsView.vue"),
  },
  {
    path: "/incidents",
    name: "incidents",
    component: () => import("../../modules/incidents/views/IncidentsView.vue"),
  },
  {
    path: "/incidents/:id",
    name: "incident-detail",
    component: () => import("../../modules/incidents/views/IncidentDetailView.vue"),
  },
];

export const router = createRouter({
  history: createWebHistory(),
  routes,
});
