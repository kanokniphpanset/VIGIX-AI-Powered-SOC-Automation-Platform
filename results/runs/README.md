# Evaluation run register (Real-Wazuh)

| label | status | why |
|---|---|---|
| `clean-real-wazuh-20260930` | **SUPERSEDED — kept as evidence** | Run #1. The harness built `RecommendationContextBuilder` WITHOUT `responseSetup` and `compliancePolicy` (as the older evaluation scripts do), i.e. a different code path from production (`container.ts`). Playbook selection ignored the alert's own MITRE techniques; ACTION_COMPLIANCE evidence rules were not applied. Also ran with the original custom-rule regex (TC-02) and the un-indexable `data.process` telemetry (TC-08). Its findings are still valid as findings. |
| `postfix-clean-real-wazuh-20260930` | **SUPERSEDED — kept as evidence** | Post-fix attempt for TC-02/08/09 on the same defective wiring; TC-08 crashed on the harness honesty guard (readlink /proc/PID/exe needs CAP_SYS_PTRACE). |
| `clean-v2-real-wazuh-20260930` | **PRIMARY Clean Run** | Production-parity wiring + fixes (rule pcre2, TC-08 telemetry layout, PlaybookSelector tie-break). No analyst corrections. |
| `intervention-v2-real-wazuh-20260930` | Intervention Run | Same environment as v2; reactive analyst IOC correction only when a recommendation is blocked. Reported separately. |
