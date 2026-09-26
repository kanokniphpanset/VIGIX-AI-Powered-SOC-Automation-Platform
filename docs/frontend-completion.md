# Frontend completion inventory

Scope: real backend routes, current routed Vue pages and orchestrator integration. No backend rewrites or live mutations during validation. Earlier provider-switch acceptance was interrupted: .env now selects wazuh, but backend restart/workflow acceptance was not completed.

| Area | Existing UI/client | Completion work / contract limitation |
|---|---|---|
| Sidebar/pages | Dashboard, Alerts, Incidents, Tickets, Reports, Knowledge, Settings | Keep existing navigation/style |
| Incident | Overview, alerts, timeline, investigation tabs | Manual status API accepts status only; reason/audit contract gap |
| Investigation | Evidence/IOC read views | Add DTO-based manual forms |
| AI | Run/re-run, permission gates, progress/error/reload, tests | Preserve; no live calls |
| Recommendation | Generate/regenerate with tests; steps/instructions | Preserve generation; add standalone ticket action and correct Policy label |
| Policy | Knowledge list, plan assignment/approval status | Show stored plan result; expose existing library write/evaluate routes only |
| Approval | Queue approve/reject | Detail decisions, required reason, request-more-evidence, exact role checks |
| Response ticket | Queue/detail, create via handoff | Separate ticket creation from handoff email; duplicate guard |
| IR execution | Start/complete in queue/detail | Confirm failure with reason; backend reload |
| Re-hunt | Existing ticket action, provider/health/evidence | Preserve; use fakes for tests |
| Verification | Existing result/history | Manual evidence submission through existing endpoint |
| Alerts/scenarios | Search, filters, scenario editor, create/group/open incident | Audit existing connections and UX |
| Dashboard | Real summary | Filtered deep links; no invented counters |
| Reports | Real summary with period/export/edit | Summary days is not a custom-period report API; distinguish fixed/global metrics |
| Knowledge | Read libraries, article details/send-to-IR | Existing Manager CRUD endpoints; no delete route: backend gap |
| Settings | Health, recipients GET/PUT with role guards | General/security/integration writes have no endpoints: backend gap |
| Notifications | Real handoff/article/guide; recipients | Preserve; never send during tests |
| Session | Login, token store, 401 redirect | Clear session and reject expired JWT before routing |
| Audit/history | Incident timeline | No general audit-list API: backend gap |
| Tooling | 17 existing utility tests; Vite build | Add vue-tsc, typecheck; remove proven-unreachable demo graph |

Backend remains the authority for every role and transition. Availability claims require a routed control, handler, existing API, error/loading feedback and reload. Synthetic/fake transports are confined to tests.
