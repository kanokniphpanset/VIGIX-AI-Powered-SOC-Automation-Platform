# VIGIX — AI-Powered Security Operations Platform

A frontend-only, mock-data build of an enterprise SOC/SOAR platform: incident
intake, AI-assisted investigation, response, manager approval, and
Wazuh re-hunt verification, wrapped in a role-aware Vue 3 application shell.

This build intentionally does **not** connect to Wazuh, PostgreSQL, an LLM/RAG
service, threat intel APIs, email, or Slack. Every screen is driven by an
in-memory mock dataset (8 realistic incidents spanning every lifecycle stage),
accessed through a service layer designed to be swapped for real REST calls
without touching any component or view.

## Tech stack

- Vue 3 (`<script setup>`, Composition API) + TypeScript
- Vite
- Vue Router 4 (nested routes for the incident workspace)
- Pinia (auth/role state, UI/toast state, incident cache)
- Tailwind CSS v4
- Chart.js / vue-chartjs (dashboard + report charts)
- lucide-vue-next (icons)

## Running it

```bash
npm install
npm run dev       # http://localhost:5173
```

```bash
npm run build      # type-checks with vue-tsc, then builds to dist/
npm run preview    # serves the production build locally
```

## Project layout

```
src/
  types/        Domain model — Incident, Investigation, Response, Approval,
                 Verification, KnowledgeItem, Settings, Notification, Report…
  mock/         Seed data: 8 incidents, users, knowledge base, settings,
                 notification config, the monthly report
  services/     incidentService, investigationService, responseService,
                 approvalService, verificationService, reportService,
                 knowledgeService, settingsService, notificationService,
                 dashboardService — every function is `async` and shaped
                 like a REST call (see "Swapping in a real API" below)
  stores/       Pinia stores: auth (current user + role switcher), ui
                 (toasts), incidents (list/current incident cache)
  components/   Reusable UI: common/ (SeverityBadge, StatusBadge, RiskScore,
                 DataTable, Modal, Timeline, charts, …), plus feature folders
                 (incidents/, investigation/, response/, approval/,
                 verification/, settings/, reports/, layout/)
  views/        One file per route, incident sub-views under views/incident/
  router/       All application routes
```

## Demo script — one complete incident lifecycle

1. **Dashboard** — KPIs, trend, severity/type/MITRE/verification charts, recent
   incidents and activity feed.
2. **Sidebar → Create Incident** — simulates a new Wazuh alert. Fill in a rule
   ID/level and asset; VIGIX evaluates it against the Qualification threshold
   immediately and opens the new incident's Investigation tab.
3. **Investigation** (`/incidents/:id/investigation`) — walk the 6 steps:
   Qualification → Classification (editable) → Evidence (Wazuh / IOC / Threat
   Intel / Asset / Timeline tabs) → Risk Assessment (validate) → Recommendation
   (with policy/RAG basis) → Human Validation (Approve / Modify / Reject /
   Request More Evidence).
4. Approving routes the incident to **Assignment**, and to **Approval**
   (`/incidents/:id/approval`) if the severity/asset combination requires it —
   switch the user menu to **Manager** to approve.
5. Switch to **IR Team** and open **Response** (`/incidents/:id/response`). The
   page is a guided **response runbook**: steps 1→6 (Containment → Investigation →
   Threat Hunting → Eradication → Recovery → Verification) are done in order — the
   next step stays locked until the previous one is completed or skipped. Each step
   lists the concrete tasks the team should do, tagged with the duty that owns
   them (IR Lead, IR Engineer, Malware Analyst, Threat Hunter, System Owner),
   plus the evidence to collect, the expected result and a target time. Pick an
   owner (VIGIX suggests one by duty and current load), tick off tasks, and
   complete the step — required tasks must be checked first. The side panel shows
   who does what, the affected asset's owner to notify, and the IOCs to act on.
   The final Verification step hands off to the Verification tab.
6. Once response finishes, **Verification** (`/incidents/:id/verification`)
   unlocks — click **RUN RE-HUNT** to see a mock before/after event comparison
   resolve to Resolved, Activity Reduced, or Still Active. Still-active cases
   can **Re-investigate** to generate a new recommendation cycle (capped at 3
   cycles, after which the incident is **Escalated** — no infinite loops).
7. Once resolved, **Close Incident** finalizes the record.
8. **Reports → View Report** rolls everything up into a monthly report with
   executive summary, KPIs, distributions, findings, and recommendations.

The **role switcher** lives in the top-right user menu — SOC Analyst, IR Team,
Manager, and Executive all see the same incident data with role-appropriate
actions, not separate apps.

## Swapping in a real API

Every file in `src/services/` starts with a `REPLACE WITH API` comment block
mapping its functions to the intended REST endpoint, e.g.:

```ts
// REPLACE WITH API: getIncident -> GET /api/incidents/:id
export async function getIncident(id: string): Promise<Incident | undefined> {
  return delay(findIncident(id))
}
```

To go live: replace the body of each function with a `fetch`/`axios` call to
the real endpoint and keep the same signature and return shape. Nothing in
`components/`, `views/`, or `stores/` needs to change, since they only ever
call through the service layer (never the mock data directly).

`src/services/mockDb.ts` holds the in-memory "database" (cloned from
`src/mock/*` at startup) that today's service functions read and mutate; it
has no equivalent in a real backend and can be deleted once every service is
backed by a real API.

## Assumptions made

- No existing frontend project was present, so a fresh Vue 3 + TypeScript +
  Vite + Tailwind stack was chosen (the brief's default recommendation).
- Dashboard KPI tiles (Total Alerts, Total Incidents, Critical, High, Closed)
  use the example figures from the brief to represent a full month of
  historical volume; the 8 detailed mock incidents represent the current
  "recent incidents" window rather than the entire 86-incident history.
- The global nav's **Investigation** / **Response** / **Verification** items
  are role-focused work queues (`/investigation`, `/response`,
  `/verification`) that filter the same incident list by lifecycle stage,
  distinct from the full **Incidents** list — the brief lists both a global
  nav entry and per-incident sub-routes for each.
- The response runbook's task lists come from `src/mock/responsePlaybook.mock.ts`
  (generic tasks per step plus extras per incident type, filled in with the
  incident's asset / IPs / hashes). `responseService.getRunbook()` attaches them
  to each step the first time an incident's response is opened; a real backend
  would return the same `Runbook` shape from the Response Recommendation policy.
- Settings edits (severity policy toggles, incident policy, notification
  channels) update local component state only and show a "demo only" toast;
  there is no settings-write endpoint in the service layer yet.
- Re-hunt outcomes are computed by a small deterministic mock formula in
  `verificationService.ts` (`computeMockRehunt`) rather than a fixed script,
  so results are consistent but still demonstrate all four outcomes
  (Resolved / Activity Reduced / Still Active / Escalated after 3 cycles).
