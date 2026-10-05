# VIGIX — CLAUDE.md

> **Purpose:** Master development specification for Claude Code.
>
> This file defines the VIGIX product logic, architecture, security boundaries, current development status, remaining work, testing strategy, and exact development priority.
>
> **IMPORTANT:** Do not redesign the system from scratch. Inspect the existing implementation first, reuse existing modules/use cases/repositories/services/tests, and modify only what is required to make the current architecture work end-to-end.

---

# 1. PROJECT IDENTITY

## Project

**VIGIX — AI-Powered SOC Recommendation Platform**

VIGIX is a cybersecurity platform that assists Security Operations Center (SOC) teams with:

* Alert ingestion
* Incident creation
* Investigation
* Evidence collection
* AI-assisted analysis
* Risk assessment
* Response recommendation
* Policy evaluation
* Approval workflow
* Response planning
* Response ticket management
* Human execution
* Verification
* Re-hunting
* Reporting
* Knowledge management
* Audit logging

## What VIGIX IS NOT

VIGIX is **NOT a SIEM**.

Wazuh is an external security monitoring / detection source.

VIGIX consumes security alerts from Wazuh or test/mock sources and manages the investigation and response decision workflow.

---

# 2. CORE PRODUCT PRINCIPLE

The most important architectural principle is:

> **AI recommends. Humans decide. Humans execute. VIGIX verifies.**

AI must never become the final authority for security actions.

### AI MAY

* Analyze evidence
* Enrich indicators
* Query threat intelligence
* Map MITRE ATT&CK techniques
* Retrieve knowledge
* Calculate/estimate risk
* Explain findings
* Recommend response processes
* Recommend playbooks/runbooks
* Provide reasoning/evidence

### AI MUST NOT

* Approve its own recommendation
* Override Policy Engine
* Bypass approval
* Execute containment
* Block an IP directly
* Isolate an endpoint directly
* Disable an account directly
* Modify firewall rules directly
* Modify EDR directly
* Close an incident automatically
* Mark verification as resolved without evidence
* Invent unsupported response procedures

The human roles are responsible for final decisions.

---

# 3. HUMAN-IN-THE-LOOP MODEL

VIGIX follows:

```text
AI Analysis
     ↓
AI Recommendation
     ↓
Policy Evaluation
     ↓
Human Review / Approval when required
     ↓
Response Plan
     ↓
Human Execution
     ↓
Verification
     ↓
Re-hunt
```

The system may automate administrative operations such as:

* Creating a response ticket
* Sending notification emails
* Updating workflow status
* Recording audit logs

Administrative automation is NOT equivalent to automated security containment.

---

# 4. SYSTEM ARCHITECTURE

Current major components:

```text
                         ┌─────────────────────┐
                         │ Wazuh / Mock Alert  │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Alert Ingestion     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Alert / Incident    │
                         │ Management          │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ Investigation       │
                         │ Evidence / IOC      │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ AI Orchestrator     │
                         │ LangGraph           │
                         └──────────┬──────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    ▼               ▼               ▼
                  RAG             MITRE       Threat Intel
                    │               │               │
                    └───────────────┼───────────────┘
                                    ▼
                              Risk Analysis
                                    │
                                    ▼
                            AI Recommendation
                                    │
                                    ▼
                           Policy Evaluation
                                    │
                                    ▼
                         Approval / Decision
                                    │
                                    ▼
                            Response Plan
                                    │
                                    ▼
                           Response Ticket
                                    │
                                    ▼
                          Human IR Execution
                                    │
                                    ▼
                              Verification
                                    │
                                    ▼
                              Re-Hunting
                                    │
                         ┌──────────┴──────────┐
                         ▼                     ▼
                      Resolved             Abnormal
                                               │
                                               ▼
                                      New Investigation
                                               │
                                               ▼
                                      New Recommendation
```

---

# 5. TECHNOLOGY STACK

## Backend

```text
Node.js
Express
TypeScript
Clean Architecture
Prisma
PostgreSQL
```

Backend:

```text
apps/backend
```

Default port:

```text
4000
```

---

## AI Orchestrator

```text
Python
FastAPI
LangGraph
LLM
RAG
Threat Intelligence
ML Risk Scoring
```

Location:

```text
apps/ai-orchestrator
```

Default port:

```text
8000
```

---

## Supporting Services

```text
PostgreSQL
Redis
Qdrant
n8n
Wazuh / Wazuh Indexer
```

Typical ports:

```text
PostgreSQL   15432
Backend      4000
AI           8000
Qdrant       6333
Redis        6379
n8n          5678
```

---

# 6. CANONICAL VIGIX WORKFLOW

This is the canonical system workflow.

## Step 1 — Alert Ingestion

Input can come from:

```text
Wazuh
Mock Wazuh Alert
External Wazuh JSON fixture
Future security integrations
```

The system must normalize incoming data into the VIGIX internal alert format.

Do NOT allow external JSON to directly become trusted internal domain objects without validation.

---

# 7. ALERT VS INCIDENT

An Alert is a detection event.

An Incident is a case that requires investigation/workflow.

Conceptually:

```text
Alert
 ↓
Validation / Classification
 ↓
Incident
```

Do not assume every raw alert automatically represents a full incident unless the existing implementation explicitly defines that behavior.

SOC ownership and incident promotion rules must follow the existing domain implementation/policy.

---

# 8. INCIDENT MANAGEMENT

An Incident should contain enough information to support:

* Identification
* Severity
* Risk
* Priority
* Status
* Evidence
* Investigation
* Recommendation
* Policy evaluation
* Response
* Verification
* Audit history

Incident lifecycle may include states such as:

```text
OPEN
INVESTIGATING
WAITING_APPROVAL
READY_FOR_RESPONSE
IN_RESPONSE
VERIFYING
RESOLVED
REOPENED
ESCALATED
```

Use the actual enum/status definitions already present in Prisma/domain code.

Do NOT create duplicate status systems.

---

# 9. SEVERITY ≠ RISK ≠ PRIORITY

These are different concepts.

## Severity

Represents incident/detection severity.

Example:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

## Risk

Represents calculated/assessed security risk.

Current project thresholds:

```text
>= 75
>= 50
>= 25
< 25
```

Do not change these thresholds without checking existing implementation and tests.

## Priority

Represents operational urgency.

Priority must not simply be treated as a synonym for risk.

---

# 10. INVESTIGATION

Investigation is responsible for collecting and presenting evidence.

Minimum IOC/evidence categories:

```text
IP
URL
HASH
REGISTRY
DOMAIN
```

Investigation UI should support:

```text
Evidence
AI Analysis
```

AI Analysis should explain:

* What happened
* Why it may be malicious
* Relevant evidence
* Threat intelligence
* MITRE mapping
* Risk reasoning
* Recommended response

AI analysis must remain explainable and evidence-based.

---

# 11. AI ORCHESTRATOR

Current intended LangGraph pipeline:

```text
Threat Intelligence
        ↓
MITRE Mapping
        ↓
RAG
        ↓
ML Risk
        ↓
LLM Analyst
        ↓
Validation
        ↓
Decision
        ↓
Recommendation Agent
```

The exact implementation must be inspected before modification.

---

# 12. AI COMPONENT RESPONSIBILITIES

## Threat Intelligence

Potential sources:

```text
VirusTotal
OTX
MISP
AbuseIPDB
```

Threat intelligence is evidence enrichment.

It must not independently authorize security actions.

---

## MITRE

Used to identify/map relevant:

```text
Tactics
Techniques
Sub-techniques
```

MITRE mapping is supporting evidence.

---

## RAG

Qdrant contains knowledge used to provide contextual information.

Current known environment:

```text
Qdrant
Embedding: bge-small-en-v1.5
```

Known project state includes approximately:

```text
2469 vector points
21 playbook documents
```

These values must be verified against the actual environment before being treated as authoritative.

---

## ML Risk

The ML layer may calculate risk on a 0–100 scale.

XGBoost exists as a risk scoring/fallback component.

Risk scoring must not bypass deterministic policy rules.

---

## LLM Analyst

The LLM may:

* Explain
* Summarize
* Correlate
* Interpret evidence
* Suggest investigation direction

The LLM is NOT the policy authority.

---

# 13. RECOMMENDATION AGENT

Recommendation Agent generates a response recommendation.

The recommendation should be based on:

```text
Incident Type
+
Severity
+
Risk
+
Evidence
+
Threat Intelligence
+
MITRE
+
RAG Knowledge
+
Playbook
+
Policy Constraints
```

The AI must not invent arbitrary security actions.

Recommendation should reference known:

```text
Playbook
Runbook
Response Process
```

where available.

---

# 14. POLICY ENGINE

Policy is deterministic business logic.

Policy is more authoritative than AI output.

Policy determines:

```text
Responsible Role
Review Required
Approval Required
Approval Role
SLA
```

Known conceptual assignment:

```text
LOW / MEDIUM → SOC
HIGH / CRITICAL → IR_TEAM
```

However:

> Claude Code MUST inspect the current Policy implementation and tests before changing these rules.

Do not assume the above is already fully implemented.

---

# 15. APPROVAL LEVELS

Current intended model:

```text
Level 0
No approval

Level 1
IR Review

Level 2
Manager Approval
```

General intended behavior:

### Level 0

Routine response.

No approval required.

### Level 1

IR review for cases such as:

```text
HIGH severity
or
risk >= 50
```

Exact rule must follow current Policy implementation.

### Level 2

Manager approval for cases such as:

```text
Critical asset
High-impact action
Critical incident
Very high risk
```

The exact conditions must be verified against the actual repository.

---

# 16. IMPORTANT POLICY PRINCIPLE

Do not assume:

```text
HIGH risk = Manager approval
```

Risk alone is not necessarily sufficient.

Policy may depend on:

```text
Severity
Risk
Asset Criticality
Action Impact
Incident Type
Role
```

If `assetCriticality` or `actionImpactLevel` is missing from the current request contract, inspect whether the current architecture already has an equivalent field before introducing a new one.

Do not add unnecessary schema complexity.

---

# 17. PLAYBOOK VS RUNBOOK VS RECOMMENDATION

These concepts must remain separate.

## Policy

Defines rules.

```text
WHO
WHEN
APPROVAL
SLA
```

## Playbook

Defines response process.

Example:

```text
Validate Incident
↓
Assess Containment Need
↓
Select Containment Action
↓
Prepare Response Plan
↓
Decision / Approval
↓
Execute
↓
Verify
```

## Runbook

Contains operational instructions.

Example:

```text
How to investigate SSH brute force
How to block an IP
How to isolate an endpoint
How to collect evidence
```

## AI Recommendation

Selects/recommends an appropriate process for the current case.

AI must not create unsupported operational procedures.

---

# 18. RESPONSE PLAN

Response Plan is created after recommendation and policy/approval logic.

Conceptually:

```text
Recommendation
      ↓
Policy Evaluation
      ↓
Approval if required
      ↓
Response Plan
```

Response Plan should define:

```text
Objective
Actions
Responsible Role
Approval State
Execution Steps
Expected Result
Verification Criteria
```

The Response Plan must not automatically execute security containment.

---

# 19. APPROVAL WORKFLOW

When approval is required:

```text
Recommendation
      ↓
Request Approval
      ↓
WAITING_APPROVAL
      ↓
Manager / IR Review
      ↓
Approve / Reject
```

If approved:

```text
Approved
 ↓
Response Plan
 ↓
Response Ticket
```

If rejected:

```text
Rejected
 ↓
Record reason
 ↓
Audit
```

The system must not silently continue after rejection.

---

# 20. RESPONSE TICKET

Response Ticket represents operational execution work.

It should identify:

```text
Incident
Response Plan
Responsible Role
Assigned User/Team
Status
Actions
Execution Notes
Evidence
Timeline
```

Example lifecycle:

```text
OPEN
 ↓
ASSIGNED
 ↓
IN_PROGRESS
 ↓
EXECUTED
 ↓
VERIFYING
 ↓
COMPLETED
```

Use actual repository enums if different.

---

# 21. HUMAN EXECUTION

IR/SOC executes the recommended response manually.

Example:

```text
Block malicious IP
Isolate endpoint
Disable compromised account
Remove malicious file
Reset credentials
```

VIGIX may show instructions and record execution.

VIGIX must NOT directly execute these actions unless a future explicitly authorized integration is introduced.

Current project requirement:

> Security actions remain human-controlled.

---

# 22. N8N

n8n is NOT a security execution engine.

Use n8n for:

```text
Email Notification
```

Potential administrative automation:

```text
Approval completed
      ↓
Email notification
      ↓
Response ticket created
```

Do NOT use n8n for:

```text
Firewall block
EDR isolation
Account disable
Endpoint containment
Security infrastructure modification
```

---

# 23. VERIFICATION

After human response:

```text
Response Execution
       ↓
Verification
       ↓
Re-hunt
```

Verification determines whether the response actually worked.

Possible outcomes include:

```text
RESOLVED
NOT_RESOLVED
SPREAD
NOT_CONTAINED
```

The actual enum values in code must be preserved.

---

# 24. RE-HUNT

Re-hunt checks whether abnormal activity remains after response.

For real Wazuh:

```text
VIGIX
 ↓
Wazuh Indexer
 ↓
Search relevant events
 ↓
Return evidence
```

For Mock mode:

```text
VIGIX
 ↓
Mock Re-hunt Provider
 ↓
Search fixture events
 ↓
Return MATCH / NO_MATCH
```

Important:

```text
NO_MATCH != BENIGN
```

No matching event means:

> No matching event was found within the queried scope.

It must not automatically be interpreted as:

> The system is clean.

---

# 25. RE-HUNT ERROR SAFETY

These states must never be interpreted as clean:

```text
ERROR
TIMEOUT
CONNECTION FAILURE
QUERY FAILURE
INDEXER UNAVAILABLE
```

For example:

```text
Wazuh query timeout
```

must NOT become:

```text
NO_MATCH
```

It must become an explicit failure state.

---

# 26. VERIFICATION LOOP

If verification is:

```text
RESOLVED
```

then:

```text
Incident → RESOLVED
```

If verification is:

```text
NOT_RESOLVED
SPREAD
NOT_CONTAINED
```

then:

```text
Verification
 ↓
New Investigation
 ↓
New Evidence
 ↓
New AI Analysis
 ↓
New Recommendation
 ↓
Policy
 ↓
Approval if required
 ↓
New Response Plan
 ↓
New Response Ticket
```

Never automatically execute a new response.

---

# 27. MAXIMUM RE-HUNT / INVESTIGATION ROUNDS

Current intended maximum:

```text
3 rounds
```

or stop when:

```text
RESOLVED
```

If quota is reached without resolution:

```text
Escalate to IR
```

Do not create an infinite loop.

Check the actual implementation before changing the limit.

---

# 28. KNOWLEDGE BASE

Knowledge can be created/updated from approved security knowledge.

Knowledge may include:

```text
Incident Type
Investigation Method
Playbook
Runbook
Response Procedure
MITRE Information
SOC Lessons Learned
```

Knowledge feeds:

```text
RAG
```

Do not allow arbitrary unverified AI output to automatically become trusted knowledge.

---

# 29. REPORTING

Reports should provide operational visibility.

Examples:

```text
Total Incidents
Closed Cases
Open Cases
IR-handled Cases
Manager Reviewed
Manager Approved
Manager Rejected
Response Time
Resolution Time
Verification Result
Re-hunt Result
```

Monthly reports should be supported.

---

# 30. KPI

Primary KPIs:

```text
Investigation Time
Analyst Workload
Time-to-Decision
Automation Success Rate
```

When presenting these KPIs, do not imply that VIGIX autonomously executes security response.

---

# 31. ROLES

## SOC

Responsible for:

```text
Alert triage
Investigation
Evidence review
Initial analysis
Routine cases
```

## IR

Responsible for:

```text
Response execution
Complex incidents
High/critical response
Containment activities
Verification
```

## Manager

Responsible for:

```text
High-impact approval
Critical cases
Approval decisions
```

## AI

Responsible for:

```text
Analysis
Enrichment
Risk support
Recommendation
```

AI is never a final decision-maker.

---

# 32. AUDIT LOG

Important workflow actions must be auditable.

Examples:

```text
Alert created
Incident created
Severity changed
Investigation started
Evidence added
AI analysis generated
Recommendation generated
Policy evaluated
Approval requested
Approval approved
Approval rejected
Response plan created
Response ticket created
Execution recorded
Verification completed
Re-hunt performed
Incident reopened
```

Important:

> Changing incident severity must be permission-controlled and auditable.

---

# 33. MOCK ALERT STRATEGY

VIGIX does NOT need real Wazuh to finish the core application workflow.

Mock Wazuh alerts can be used during development.

External sources such as:

```text
GitHub Wazuh SOC lab examples
Wazuh sample alerts
Wazuh alert datasets
```

may be used as test fixtures.

However:

> External JSON is test data, not trusted executable input.

---

# 34. MOCK ALERT NORMALIZATION

Do not directly inject arbitrary external JSON into the domain.

Use:

```text
External Wazuh JSON
       ↓
Validation
       ↓
Wazuh Alert DTO
       ↓
VIGIX Alert Ingestion
       ↓
Domain Alert
```

Example conceptual fixture:

```json
{
  "source": "wazuh",
  "ruleId": "5710",
  "ruleLevel": 10,
  "description": "sshd: authentication failed",
  "agent": {
    "id": "001",
    "name": "ubuntu-endpoint"
  },
  "sourceIp": "192.168.1.50",
  "mitre": {
    "technique": "T1110",
    "name": "Brute Force"
  },
  "timestamp": "2026-09-18T10:30:00Z"
}
```

This is an example only.

Use the actual DTO/schema already existing in the repository.

---

# 35. MOCK RE-HUNT

Mock re-hunting should support controlled scenarios.

Example:

```text
Scenario A
Same malicious IP appears after response
→ MATCH
→ NOT_RESOLVED / NOT_CONTAINED

Scenario B
No matching event after response
→ NO_MATCH
→ candidate for RESOLVED

Scenario C
Events continue with additional indicators
→ SPREAD

Scenario D
Provider failure
→ QUERY_ERROR

Scenario E
Provider timeout
→ TIMEOUT
```

Mock data should be deterministic.

Do not create random results for tests.

---

# 36. MOCK FIXTURE LOCATION

Before creating a new folder:

> Search the repository for an existing `resources`, `fixtures`, `test-data`, `mock`, `wazuh`, or similar directory.

Reuse existing conventions.

Possible structure if no equivalent exists:

```text
resources/
  mock-alerts/
    ssh-auth-failure.json
    ssh-bruteforce.json
    malware.json
  mock-rehunt/
    match.json
    no-match.json
    spread.json
    error.json
    timeout.json
```

Do not create duplicate data directories.

---

# 37. REAL WAZUH

Real Wazuh is a later integration phase.

Expected architecture:

```text
Wazuh Agent
     ↓
Wazuh Manager
     ↓
Wazuh Indexer
     ↓
VIGIX
```

For local development/demo:

```text
Wazuh Docker
```

may be used.

The company production Wazuh server must NOT become a mandatory development dependency.

---

# 38. UBUNTU ENDPOINT

A real Ubuntu Wazuh Agent is useful for final validation.

However:

> Ubuntu Agent is NOT required to finish the core VIGIX workflow.

Core development can be completed using:

```text
Mock Wazuh Alert
+
Mock Re-hunt
```

Real Wazuh should be added after the application workflow is working.

---

# 39. CURRENT INFRASTRUCTURE

Known environment:

```text
D:\soar-platform
```

Important directories:

```text
apps/backend
apps/ai-orchestrator
apps/frontend
```

Supporting infrastructure previously used:

```text
PostgreSQL
Qdrant
Redis
n8n
Wazuh Docker
```

Known Wazuh Docker work:

```text
wazuh-docker v4.14.7
single-node configuration
indexer certificates generated
vm.max_map_count = 262144
```

However:

> Claude Code MUST verify actual running containers and current configuration instead of assuming Wazuh is currently running.

---

# 40. DATABASE RULE

Prisma/PostgreSQL is the source of truth for persistent application state.

Before changing schema:

```text
1. Search current Prisma schema
2. Search domain entity
3. Search repository
4. Search use cases
5. Search controllers
6. Search tests
```

Do not add duplicate entities.

Do not create a new table simply because an existing table is difficult to use.

---

# 41. CURRENT POLICY DATA

Known historical policy examples include:

```text
POL-011
No approval for LOW/MEDIUM

POL-012
IR review

POL-001 / POL-013 / POL-014
Manager-related critical/high-risk rules
```

These are NOT automatically assumed to be the final production rules.

Claude Code must inspect:

```text
Policy
PolicyRule
Policy Engine
PolicyEvaluator
Policy tests
```

before modifying them.

---

# 42. CURRENT RESPONSE ARCHITECTURE

Known backend areas include:

```text
application/approval
ResponsePlan
ResponseTicket
Verification
Policy
```

Known code previously found includes:

```text
ApprovalService.ts
DecideApproval.usecase.ts
ResponsePlanRepository
```

Again:

> Inspect the current implementation before changing it.

---

# 43. HISTORICAL TEST STATUS

Previously reported project tests:

```text
Policy          14/14
Response Plan    7/7
Approval         7/7
Verification     9/9
Re-hunt         15/15
--------------------
Total           52/52
```

IMPORTANT:

These numbers are historical.

Claude Code MUST rerun the actual current tests before claiming:

```text
52/52
```

as the current status.

---

# 44. CURRENT PROJECT STATUS

This section represents the latest known project state.

Claude Code must verify each item against the repository before changing the status.

| Area                       | Current status                                        |
| -------------------------- | ----------------------------------------------------- |
| Overall architecture       | Substantially implemented                             |
| Backend Clean Architecture | Exists                                                |
| Prisma/PostgreSQL          | Exists                                                |
| Policy domain              | Exists                                                |
| Approval domain            | Exists                                                |
| Response Plan              | Exists                                                |
| Response Ticket            | Exists / integration needs verification               |
| Verification               | Exists                                                |
| Re-hunt concept            | Exists                                                |
| AI Orchestrator            | FIXED 2026-09-23 — imports, starts, /pipeline/alerts runs full LangGraph (see §45) |
| Recommendation Agent       | FIXED 2026-09-23 — `run()` reconstructed, produces evidence-gated report |
| Backend → AI               | VERIFIED 2026-09-23 — webhook → /pipeline/run → Postgres (§45.2) |
| Incident → Investigation → Evidence | DONE 2026-09-23 — synced at ingestion, IOC-linked (§45.3) |
| AI → Recommendation        | DONE 2026-09-23 — real LLM, validated, persisted, failure-safe; 10/10 cases (§45.4) |
| Recommendation → Policy    | DONE 2026-09-23 — assetCriticality wired, Policy authoritative (§45.5) |
| Policy → Approval          | DONE 2026-09-23 — approve/reject/role/audit verified live (§45.5) |
| Approval → Response Plan   | DONE 2026-09-23 — approved → READY_FOR_EXECUTION, rejected → REJECTED/blocked (§45.5) |
| Response Plan → Ticket     | Needs E2E verification                                |
| Ticket → Verification      | DONE 2026-09-23 — start/complete/fail + verification verified live (§45.6) |
| Verification → Re-hunt     | DONE 2026-09-23 — Mock re-hunt provider, loop + 3-round cap, error safety (§45.6) |
| Mock Wazuh Alert           | DONE 2026-09-23 — 10 fixtures in resources/mock-attacks/ (§45.2) |
| Mock Re-hunt               | DONE 2026-09-23 — MockRehuntAdapter, REHUNT_PROVIDER=mock (§45.6) |
| Mock Re-hunt               | Should be implemented/verified                        |
| Real Wazuh                 | Later Phase 14                                        |
| Email                      | Partial/pending                                       |
| Gmail App Password         | Previously pending                                    |
| Jira                       | Previously encountered 401                            |
| Teams                      | Not confirmed complete                                |
| LINE                       | Not confirmed complete                                |
| Discord/Telegram           | Not confirmed live                                    |
| Reports                    | Concept/module exists; integration needs verification |
| Frontend                   | Needs final E2E verification                          |
| Production Wazuh           | NOT a development dependency                          |

---

# 45. CURRENT AI BLOCKER

A recent test was run:

```bash
cd /d/soar-platform/apps/ai-orchestrator

python -c "from src.agents.recommendation_agent.agent import run; print('IMPORT_OK')"
```

The import produced a traceback.

Therefore:

> **AI Orchestrator runtime/import must be treated as the immediate blocker until reproduced and fixed.**

Do not assume Recommendation Agent is working merely because the source files exist.

First reproduce the exact error.

Then fix the smallest root cause.

Then rerun the import.

Then run the AI service.

Then test the actual endpoint.

## 45.1 VERIFIED AUDIT — 2026-09-23 (TASKS 1–4 DONE)

Root causes found and fixed (smallest fix each, no architecture change):

1. `src/agents/recommendation_agent/agent.py` was truncated to 2 helper
   functions (no `run`, no imports) → `NameError: Any`. Reconstructed `run()`
   from selector/summary/models; writes `investigation_recommendation_report`
   (the key `api/database.py` and `api/output_contract.py` already read).
2. `threat_intel_agent/ioc_extractor.py` iterated `extract_iocs_from_text()`
   as a list, but the tool now returns a `ToolResult` → ThreatIntelAgent
   always failed (`'ToolResult' object is not iterable`). Adapted to `.data["iocs"]`.
3. `mitre_agent/agent.py` built `MitreKnowledgeBaseClient()` without the
   required `backend_url` → MitreAgent always failed. Now passes `settings.backend_url`.
4. Backend had NO `GET /api/v1/mitre/techniques` route (MITRE client got 404).
   Added read-only route over the existing `mitre_techniques` table
   (domain/mitre repository + ListMitreTechniques use case + MitreController).
   Seed extended with techniques for the 10 attack cases (13 rows in dev DB).
5. `contracts/error_builder.py::build_errors` ignored `state["structured_errors"]`,
   so agent crashes were reported as `status: SUCCESS, errors: []`. Now included (dedup by id).

Verified:

* `python -c "from src.agents.recommendation_agent.agent import run"` → IMPORT_OK
* every `src.*` module imports except 3 needing undeclared `opensearchpy`
  (`tools/wazuh_query_tool`, `tools/rehunt_tool`, `services/verification_service`
  — real-Wazuh re-hunt path, Phase 14, not on the live graph)
* AI service: `GET /health` OK; `POST /pipeline/alerts` with a Wazuh SSH
  brute-force alert → MITRE T1110 mapped, both IPs through TI, classification
  CREDENTIAL_ATTACK, 5 recommendations, status PARTIAL_SUCCESS (TI providers
  NOT_CONFIGURED — no API keys set). ~100s per run (remote LLM).
* Backend jest: 52/52 tests pass in 6 suites. `test/Approval.integration.test.ts`
  is a 0-byte file (truncated) → counted as a failed suite.

Known open issues (not yet fixed):

* AI `decision` output from `/pipeline/alerts` is degenerate
  (`severity: ""`, `policy_id: ""`) — address in TASK 8 (Policy). Backend Policy
  Engine remains the authority.
* Recommendation priority is bumped by `asset_tier_high` even at
  LOW_CONFIDENCE classification; `always`-condition entries' reason text says
  "confidently classified" regardless of confidence (selector/catalog wording).
* Wazuh normalizer sets `asset_id` = attacker source IP.
* `apps/ai-orchestrator/tests/` and `apps/frontend/` are deleted in the
  uncommitted working tree (frontend now lives directly under `apps/`).
  AI orchestrator currently has NO automated test suite.
* Postgres runs on 5432 (not 15432); Redis is not running.
* Real Wazuh Docker (v4.x single-node) containers ARE running — untouched.

## 45.2 TASK 5 — MOCK WAZUH FIXTURES — DONE 2026-09-23

No prior fixture convention existed (`apps/src/mock/*` is frontend UI mock
data only). Created `resources/mock-attacks/` (shared resource tree, same
layout as §43) with a README documenting the case-file shape:

```text
resources/mock-attacks/
  ssh-bruteforce/      case-01-resolved.json (ATK-01)  case-02-not-resolved.json (ATK-02)
  malware/             case-01-resolved.json (ATK-03)  case-02-not-resolved.json (ATK-04)
  sql-injection/       case-01-resolved.json (ATK-05)  case-02-spread.json       (ATK-06)
  account-compromise/  case-01-suspicious-login.json (ATK-07)  case-02-privilege-escalation.json (ATK-08)
  powershell/          case-01-suspicious-command.json (ATK-09)  case-02-persistence.json (ATK-10)
```

Each case = Wazuh alert (+ optional `relatedAlerts`), `expected`
(severity, host, MITRE, IOCs incl. ip/domain/url/hash/registry/file/process/
command/user/request, policy inputs, approval expectation, primary + final
outcome), simulated human `response` (action + target), and deterministic
`rehunt.rounds[]` (NO_MATCH / MATCH / SPREAD, ≤3 rounds, each with noise
events). Re-hunt matching semantics mirror `WazuhIndexerAdapter.buildRehuntDsl`.
Loop coverage: ATK-02/06/10 resolve in round 2; ATK-04 exhausts 3 rounds →
ESCALATED_TO_IR. ATK-08 carries APPROVED + REJECTED decisions.

Tests (all passing):

* `apps/ai-orchestrator/tests/fixtures/test_mock_attack_fixtures.py` — 103
  tests: pydantic schema, existing `WazuhAlertNormalizer`, TI IOC extraction,
  re-hunt round self-consistency, outcome/loop rules, 10-case matrix.
  Mutation-checked (injected IOC / rule-on-other-host / agent-IP / removed
  spread event are all detected).
* `apps/backend/test/MockAttackFixtures.test.ts` — 32 tests: `WazuhAdapter`
  normalization + severity, `IngestAlertFromSiemUseCase` (in-memory fakes),
  AI-unavailable (alert still stored, `pipelineDispatched=false`), invalid payload.
* Backend jest total: 84/84 pass in 7 suites (+ the 0-byte Approval file).

Live verification: all 10 primary alerts POSTed to
`/api/v1/webhooks/siem/wazuh` → `pipelineDispatched: true`; each produced 1
incident, correct severity, MITRE mappings (incl. sub-techniques) and TI IOCs
in Postgres, agent execution SUCCESS. **ATK-01 passes the fixture →
ingestion → AI → persistence layer.** (Dev DB now contains these test
alerts/incidents; ATK-01 was ingested 4× while debugging.)

Fix required during Task 5: `/pipeline/run` returned 500 once MITRE started
producing techniques (Task 3 fix) — `api/database.py` wrote
`mitre_mappings` with snake_case keys and 3 columns that do not exist in
Prisma (`decision_id`, `mapping_status`, `sub_technique_id`). Insert now
matches the Prisma `MitreMapping` model and reads MitreAgent's camelCase keys.
(uvicorn `--reload` did not pick up this change — the AI service had to be restarted.)

Observations for later tasks (not changed):

* Webhook `POST /api/v1/webhooks/siem/:source` has NO HMAC verification mounted
  (scripts/send-test-alert.sh signs, nothing checks) — security gap.
* Backend awaits the whole AI pipeline synchronously inside the webhook request.
* TI extractor's `_IP_FIELDS` lacks Wazuh `srcip`/`dstip` (IPs only found via
  `full_log` text); it also stores the agent's own IP as an IOC, which the
  re-hunt will then search for (fixture noise avoids host IPs for this reason).
* Mock re-hunt PROVIDER (MATCH/NO_MATCH/SPREAD from these fixtures, plus
  ERROR/TIMEOUT/INDEXER_UNAVAILABLE modes) is TASK 9 — not built yet.
* Approval outcomes (ATK-08/10) are declared as expectations only; the backend
  Policy Engine must be verified to produce them in TASK 8.

## 45.3 TASK 6 — INCIDENT → INVESTIGATION → EVIDENCE — DONE 2026-09-23

Existing implementation found and REUSED (no schema change, no new tables):
Prisma `Investigation` (one row per cycle), `Evidence` (`alertId`, `origin`
SYSTEM/MANUAL), `EvidenceIoc` (M:N), `IncidentAlert`, `ThreatIntelIoc.investigationId`;
`domain/investigation/alertEvidence.ts::buildAlertEvidence`;
`IInvestigationRepository.syncIncident` (built for orchestrator-created incidents).

Gap (verified in DB): the AI orchestrator creates `incidents` rows directly, and
`syncIncident` ran only lazily on READ (GET investigations) → after ingestion
there was no Investigation, no Evidence, no alert link, and IOCs had no cycle.

Changes:

* `application/alert/use-cases/IngestAlertFromSiem.usecase.ts` — after a
  successful (synchronous) AI dispatch, finds the incident for the alert
  (`findLinkedIncidents`) and runs `syncIncident`. Failures are logged; the
  alert is never lost; the read path still syncs as fallback. Output/webhook
  response gain `incidentId`, `investigationSynced` (additive).
* `infrastructure/.../InvestigationRepository.prisma.ts::syncIncident` — also
  writes the primary `incident_alerts` row; assigns orchestrator IOCs to
  cycle #1 BEFORE adding alert IOCs (unique (investigation,type,value) safe);
  new `linkAlertIocs`: IOCs stated in the alert are created (source `ALERT`)
  or reused, and linked to the WAZUH_ALERT evidence via `evidence_iocs`. Idempotent
  (verified: 2 re-syncs → identical counts).
* `domain/investigation/alertIocs.ts` (new, pure) — `extractAlertIocs`: IP,
  DOMAIN (dns + URL host), URL, HTTP_REQUEST (relative url), MD5/SHA1/SHA256,
  FILE_PATH, PROCESS_NAME, COMMAND_LINE, REGISTRY_KEY/VALUE, USERNAME (group
  names on membership events excluded). Validated by existing `checkIocValue`.
* `domain/investigation/Investigation.types.ts` — IOC_TYPES + `COMMAND_LINE`,
  `HTTP_REQUEST` (free-text validation; `ioc_type` is a string column → no migration).
* `application/verification/use-cases/RunRehuntVerification.usecase.ts` —
  re-hunt IOC criteria limited to `REHUNT_IOC_TYPES` (IP/IPV4/IPV6/DOMAIN/URL/
  HASH/MD5/SHA1/SHA256). Reason: host facts (e.g. USERNAME `root`, the
  powershell.exe path) phrase-matched across ALL hosts would fake recurrence/
  spread on real data. (None of the 10 fixtures' NO_MATCH rounds is affected
  either way — checked.)
* `infrastructure/config/container.ts` — `investigationRepository` constructed
  earlier and injected into the ingestion use case.

Tests: new `apps/backend/test/AlertInvestigationEvidence.test.ts` (37): IOC
extraction for all 10 fixtures × every expected type, all extracted IOCs pass
`checkIocValue`, alert IOCs never turn a NO_MATCH round into a match (fields
read from the real `buildRehuntDsl`), ATK-08 group≠user, ingestion→sync
hook incl. no-incident / dispatch-failed / sync-failed paths.
Backend jest: 121/121 (+ the 0-byte Approval file). AI fixtures: 103/103. tsc OK.

Live DB verification (real webhook → AI → Postgres), all 10 cases: 1
`incident_alerts` row, Investigation #1 ACTIVE, 1 WAZUH_ALERT evidence
(origin SYSTEM, alert_id set), 0 cycle-less IOCs, evidence↔IOC links.
IOC types persisted+linked across the suite: IPV4, DOMAIN, URL, MD5, SHA1,
SHA256, FILE_PATH, PROCESS_NAME, COMMAND_LINE, REGISTRY_KEY, REGISTRY_VALUE,
USERNAME, HTTP_REQUEST. **ATK-01 passes Alert → Incident → Investigation →
Evidence/IOC in PostgreSQL.**

Known limitations / blockers (not fixed):

* No alert correlation: each `relatedAlerts` entry (ATK-04/08/10) would open
  its OWN incident (AI creates one incident per alert). Grouping only exists
  via manual `createWithAlerts`.
* AI threat intel stores relative request paths as `URL` (e.g. ATK-05
  `/products.php?...`) — invalid per backend `checkIocValue`; duplicates the
  correct `HTTP_REQUEST` IOC. AI also stores the agent's own IP as an IOC.
* AI-created incidents leave the alert `status = received` (manual incident
  creation sets `escalated`).
* Evidence rows are not yet part of the recommendation context (see below).

Task 7 needs:

* Backend runs `RECOMMENDATION_AGENT="fake"` (`FakeRecommendationAgent`) —
  switch/verify `llm` (`LlmRecommendationAgent` → AI `/recommendations/generate`).
* Two recommendation paths exist: AI pipeline `recommendation_agent` output
  (stored only in `agent_results`) vs backend `Recommendation` table via
  `RecommendationContextBuilder` — decide which is authoritative, don't duplicate.
* `RecommendationContextBuilder` consumes cycle IOCs (now incl. alert IOCs) +
  MITRE, but NOT Evidence rows, risk score or AI analysis — evaluate adding.
* Verify AI failure/timeout/invalid response never persists a fake recommendation.

## 45.4 TASK 7 — EVIDENCE → AI ANALYSIS → LLM RECOMMENDATION — DONE 2026-09-23

**Source of truth (decided from existing architecture, no new path):**
backend `recommendations` table, produced ONLY by `GenerateRecommendationUseCase`
(context → `IRecommendationAgentPort` → `RecommendationValidator` → persist →
supersede → audit). It is the only path with catalog validation, per-cycle
numbering/supersession, and it is what Approval/ResponsePlan reference.
The LangGraph pipeline's `recommendation_agent` report is **AI Analysis**
(stays in `agent_results` only, never written to `recommendations`) — no
duplicate recommendation path. Generation trigger is unchanged by design:
human SOC/IR request (`POST /api/recommendations/generate`, RBAC) + automatic
after NOT_RESOLVED (`CreateVerificationUseCase`). Not auto-generated at ingestion.

Changes:

* AI `src/api/routes/recommendations.py` — was RAG + deterministic
  `_propose_candidate` (NO LLM; target = `iocs[0]`, could be the agent's own
  IP). Now: backend prompt + RAG-retrieved runbooks → ONE LLM call → strict
  JSON parse + shape check (mirrors backend candidate schema, extra keys
  rejected). No fallback candidate: 503 LLM_UNAVAILABLE / 504 LLM_TIMEOUT /
  502 INVALID_LLM_OUTPUT (not JSON, wrong shape, empty steps) / 422 PROMPT_MISSING.
  System prompt: `resources/prompts/recommendation-agent/generate-system.md`.
* AI `src/api/routes/run_pipeline.py` — `incident_id` now in the graph's
  initial state (the Task-3 `recommendation_agent` report recorded the alert id
  as incidentId — regression fixed, verified in DB).
* Backend context (`RecommendationContextDto`/`IRecommendationContextRepository`/
  `RecommendationContextRepository.prisma.ts`/`RecommendationContextBuilder`) +
  `riskScore` (existing `getLatestRiskScore`), `evidence` (current cycle, with
  linked IOC values), `affectedHosts` (from evidence), `aiAnalysis`
  (latest `agent_results.llm_analyst` summary + findings). Spec §13 basis.
  Not added: playbooks (only runbooks/actions exist as recommendation input
  today), incident classification (`/pipeline/run` has no classification node).
* `RecommendationPromptBuilder` — renders risk/evidence/hosts; AI analysis
  explicitly marked "NOT evidence"; target must be an IOC value or affected host.
* `RecommendationValidator` — new RULE-002 target check (unknown target → discarded + violation).
* `GenerateRecommendationUseCase` — AI error/timeout → `AI_UNAVAILABLE`,
  INVALID candidate → `INVALID_AI_OUTPUT`: **nothing persisted, nothing
  superseded**, audit `RECOMMENDATION_GENERATION_FAILED` (previously an INVALID
  row was persisted AND superseded the prior valid recommendation).
  Controller: 404 / 503 / 502.
* `LlmRecommendationAgent` — request timeout (`RECOMMENDATION_AGENT_TIMEOUT_MS`,
  default 180 s), error body kept; stale "not wired" comment removed.
* `container.ts` — comment updated, LLM agent version `LlmRecommendationAgent/v2.0.0`.
* `apps/backend/.env` — `RECOMMENDATION_AGENT="llm"` (`.env.example` keeps `fake`).

Tests: backend `test/RecommendationGeneration.test.ts` (15: valid persist,
supersede only after valid, target rule, 7 failure modes persist nothing,
context/prompt contents, missing facts left empty); AI
`tests/api/test_recommendations_generate.py` (14: valid, fenced JSON, 8
invalid-output variants → 502, 503, 504, 422, RAG failure disclosed).
Backend jest 136/136 (+0-byte Approval file); AI pytest 117/117; tsc OK.

Live verification (real webhook → AI pipeline → Postgres → real stack
`GenerateRecommendationUseCase` → live AI/LLM → Postgres; HTTP route not
used because it requires a SOC/IR login):

* **ATK-01 passes Alert → Incident → Investigation → Evidence/IOC → AI Analysis
  → LLM Recommendation → persisted Recommendation**: VALIDATED, 0 violations,
  `ACT-BLOCK-SOURCE-IP` on 185.220.101.45 (attacker, not the agent IP),
  evidence [185.220.101.45, T1110], runbook RB-BRUTEFORCE-001, linked to Investigation #1.
* ATK-01…ATK-10: all VALIDATED, 0 violations, 1 recommendation per incident,
  every target grounded in that incident's IOCs/hosts, outputs differ per attack
  (block IP / isolate host + block domain / block IP+URL / disable j.smith /
  isolate + block C2). 7–16 s per generation.
* Live failure safety (ATK-01 incident holding Rec #1): AI unreachable, 1 ms
  timeout vs live AI, live AI 422 → all `AI_UNAVAILABLE`, Rec #1 still
  VALIDATED (not superseded), no new rows, 3 failure audits with the cause.

Known limitations / blockers (not fixed):

* ATK-05/06: LLM targets the relative request path with ACT-BLOCK-URL — grounded
  (AI TI stores it as `URL`, see §45.3) but not a real URL.
* ATK-07: investigation-only step (no action) — acceptable, conservative.
* Steps carry `requiresApproval` = the AI's advisory hint only.
* `RiskScore` has no timestamp → "latest" risk is arbitrary if >1 row.
* AI pipeline `decision` output still degenerate (`severity: ""`, `policy_id: ""`).
* The 10-case E2E runner must call generation explicitly (human-triggered by design).

Task 8 needs:

* Recommendation → Policy: backend Policy Engine (`PolicyEvaluator`, POL-xxx)
  evaluated with severity, risk (`getLatestRiskScore`), asset criticality,
  action impact (`actions.impact_level`, `default_approval_required`) — the AI
  hint must not decide approval. Verify ATK-08 (DC-01 tier1, critical,
  ACT-DISABLE-ACCOUNT) and ATK-10 (critical) reach approval.
* Approval approve/reject (ATK-08 both), rejection stores reason + audit, no response.
* Approved → ResponsePlan (existing `CreateResponsePlan`) → Response Ticket, linked to incident/plan/role.
* Decide what to do with the AI pipeline's degenerate `decision` output (Policy stays backend-authoritative).

## 45.5 TASK 8 — RECOMMENDATION → POLICY → APPROVAL DECISION — DONE 2026-09-23

Existing implementation reused (no new approval system): `PolicyEvaluator`
(Assignment/Approval/SLA evaluators, `PolicyPrecedence`: priority most urgent,
roles most restrictive, booleans OR), live DB rules = `prisma/seeds/policy.seed.ts`
`POLICIES` (POL-001/003/005/007, RULE-R01..R04, RULE-A01..A04, RULE-P01..P06,
RULE-V01..V03; `POL-QA-HIGH-APPROVAL` exists but disabled). `ApprovalService.evaluate`
is the single Policy path for `CreateResponsePlan` and `RequestApproval`;
`DecideApproval` (role must equal the policy's approvalRole, or admin);
`StartResponse` (blocks PENDING/REJECTED). Architecture note: a ResponsePlan
(the "ticket") is created per recommendation step FIRST as `PENDING_APPROVAL`
when Policy requires approval, the Approval is tied to it; approve →
`READY_FOR_EXECUTION`, reject → `REJECTED` (cannot start). No separate
Response Ticket entity exists.

Root-cause gap found (verified live): `ApprovalService` never supplied
`assetCriticality`, and the only approval-granting rules need it (RULE-P04
CRITICAL asset + HIGH/CRITICAL action, RULE-P06 CRITICAL severity + CRITICAL
asset; RULE-P05 needs a CRITICAL-impact action and no catalog action is CRITICAL).
→ NO approval could ever be required. Live: ATK-08 disable-account on DC-01
evaluated `approvalRequired: false` before the fix.

Changes:

* `application/approval/ports/IAssetCriticalityProvider.ts` (new) +
  `infrastructure/assets/ResourceAssetCriticalityProvider.ts` (new): the
  backend's own loader for the shared `resources/assets/asset-criticality-catalog.yaml`
  (per resources/README convention; NOT the AI-written `decisions.asset_criticality`,
  so AI output can't influence approval). tier1..4 → CRITICAL/HIGH/MEDIUM/LOW;
  several hosts → most critical; unknown host → catalog `default_tier`
  (tier2_high); catalog unreadable → fails CLOSED to CRITICAL.
* `ApprovalService.evaluate` — passes `assetCriticality` for the hosts named by the
  incident's current-cycle evidence; audits every evaluation as `POLICY_EVALUATED`
  (inputs, assets, matched rules, role/review/approval/priority/SLA); approval
  reason records assetCriticality. Signature unchanged.
* `CreateResponsePlan` — audit adds approvalRole/assetCriticality; stale docstring fixed.
* `container.ts` — provider wired. `apps/backend/package.json` — `js-yaml`
  declared (was only transitive; installed `--offline`, lock only drops `dev` flags);
  `src/types/js-yaml.d.ts` minimal typing.
* Fixture correction: ATK-10 `approval` `APPROVAL_EXPECTED` → `POLICY_DECIDES`
  (my Task-5 guess; the authoritative Policy gives IR review only for CRITICAL
  severity on a tier2 asset — documented intent in ApprovalEvaluator).

Results (live PostgreSQL, real stack, notifications no-op'd):

| Case | Inputs (sev / risk / asset / action impact) | Policy | Plan |
|---|---|---|---|
| ATK-01 block 185.220.101.45 | MEDIUM / 25 / MEDIUM (WKS-DEV-12) / MEDIUM | SOC, no review, no approval, P2 (POL-005, RULE-R03, RULE-A02) | READY_FOR_EXECUTION, NOT_REQUIRED |
| ATK-08 disable j.smith | CRITICAL / 39 / CRITICAL (DC-01) / HIGH | IR_TEAM owner, IR review, **MANAGER approval** (RULE-P04+P06), P0 | PENDING_APPROVAL → **REJECTED** (reason stored, cannot start: INVALID_STATE) |
| ATK-08 block 185.220.101.90 | CRITICAL / 39 / CRITICAL / MEDIUM | MANAGER approval (RULE-P06) | PENDING_APPROVAL → **APPROVED** → READY_FOR_EXECUTION |
| ATK-10 isolate FILESRV-01 | CRITICAL / 39 / HIGH (FILESRV-01) / HIGH | IR_TEAM, IR review, **no approval**, P0 | READY_FOR_EXECUTION, NOT_REQUIRED |

IR_TEAM deciding the MANAGER approval → ROLE_MISMATCH. Audit trail per plan:
POLICY_EVALUATED → RESPONSE_PLAN_CREATED → APPROVAL_REQUESTED → APPROVAL_DECIDED.
Policy vs AI (live): the LLM set `requires_approval=true` on every step; ATK-01
and ATK-10 still need no approval. Tests also prove AI `false` + Policy `true`
(ATK-08) → approval required.

Tests: `apps/backend/test/PolicyApprovalWorkflow.test.ts` (19, real
PolicyEvaluator on the canonical POLICIES + real catalog): ATK-01/08/10,
approve/reject/pending/role, both AI-vs-Policy conflicts, edge cases (LOW/P01,
high risk alone ≠ approval, CRITICAL asset + LOW action, P04, P05, unknown host,
multi-host, catalog unavailable). Backend jest 155/155 (+ 0-byte Approval file),
AI pytest 117/117, tsc OK.

Known limitations / blockers (not fixed):

* `actions.default_approval_required` (true for DISABLE-ACCOUNT/ISOLATE) is NOT
  consumed by any policy rule — a policy decision for the owner, not changed here.
* Severity input = alert severity (backend WazuhAdapter rule-level mapping);
  incident priority/severity changes are not re-fed.
* Denied decide attempts (ROLE_MISMATCH) are not audited.
* HTTP routes (`/api/approvals/:id/approve|reject`, `/api/responses`) need
  role tokens — verified via the same use cases, not over HTTP.
* `RequestApproval` (recommendation-level legacy path) lists steps by the AI
  hint for the notification body only; the approval decision itself is Policy.
* AI pipeline `decision` output still degenerate; it is not used for approval.

Task 9 needs:

* Human execution simulation on READY_FOR_EXECUTION plans (`StartResponse` →
  `CompleteResponse`/`FailResponse`), approved ATK-08 plan and ATK-01/10 plans.
* Verification via re-hunt: build a **Mock re-hunt provider** implementing
  `ISiemRehuntPort` from `resources/mock-attacks/*/rehunt.rounds` (MATCH /
  NO_MATCH / SPREAD) plus ERROR / TIMEOUT / INDEXER_UNAVAILABLE modes that map
  to `RehuntError` — never to NO_MATCH. Select it via config, not by editing
  `WazuhIndexerAdapter`.
* Confirm `CreateVerification` result rule (RESOLVED only if contained, no spread,
  no recurrence, 0 events) and RULE-V01..V03 re-open Investigation #2 +
  auto-regenerate the recommendation.

## 45.6 TASK 9 — EXECUTION → VERIFICATION → MOCK RE-HUNT — DONE 2026-09-23

Reused unchanged: `StartResponse` (READY/approved only; REJECTED → INVALID_STATE),
`CompleteResponse`/`FailResponse` (IN_PROGRESS only), `CreateVerification`
(RESOLVED derived: contained ∧ ¬spread ∧ ¬recurrence ∧ 0 events; plan must be
COMPLETED; one verification per plan), RULE-V01..V03, `RunRehuntVerification`.

Gaps found and fixed:

1. No loop limit: `incrementInvestigationNumber` could open cycles forever; RULE-V02
   `requireEscalation` was computed but never used.
   → `CreateVerification`: `MAX_INVESTIGATION_ROUNDS = 3`; when the incident is already
   on cycle 3 and Policy asks for a new investigation: no new cycle, no new
   recommendation, incident stays unresolved, audit `INVESTIGATION_ESCALATED`
   (reasons `MAX_INVESTIGATION_ROUNDS_REACHED` / `POLICY_REQUIRE_ESCALATION`,
   escalatedTo IR_TEAM). No incident status was added (none exists for "escalated").
2. Ordering: Recommendation #2 was generated BEFORE the recurrence evidence was
   recorded → built from an empty cycle. → `CreateVerification` input hook
   `onInvestigationReopened` (runs after the new cycle exists, before generation);
   `RunRehunt` records evidence through it (old post-hoc path kept as fallback).
3. No TIMEOUT: `RehuntErrorCode` + `TIMEOUT` → `REHUNT_TIMEOUT`; failed re-hunts are
   audited `REHUNT_FAILED` (no Verification, incident untouched, plan stays COMPLETED
   → retryable).

Additions:

* `ISiemRehuntPort` (additive): `RehuntQuery.investigationNumber`, `RehuntEvent.matchedIocValues`,
  `RehuntResult.source` `"WAZUH_INDEXER" | "MOCK_REHUNT"` (provenance recorded honestly in
  `verifications.after_state.evidenceSource` and evidence `source`).
* `infrastructure/external-services/siem/MockRehuntAdapter.ts` (new, dev/test only):
  answers from `resources/mock-attacks/*/rehunt.rounds`; case = original rule id + host,
  IOC overlap breaks ties (ATK-01 vs ATK-02); round = investigation cycle; matching uses
  the real `buildRehuntDsl` fields. Modes ERROR→QUERY_FAILED, TIMEOUT→TIMEOUT,
  INDEXER_UNAVAILABLE→UNREACHABLE; unknown/ambiguous fixture or missing round → QUERY_FAILED
  (never an empty "clean" result). `WazuhIndexerAdapter` untouched.
* `RunRehunt`: IOCs a re-hunt event provably contained (`matchedIocValues`) are created in the
  NEW cycle (source `REHUNT`) and linked to the recurrence evidence.
* `container.ts`: `REHUNT_PROVIDER=mock` (+ `REHUNT_MOCK_MODE`) selects the mock, default is
  the real indexer; the same provider feeds `VerificationController`'s health endpoint.
  `apps/backend/.env` now sets `REHUNT_PROVIDER="mock"`; `.env.example` documents it (commented).

Tests: `test/MockRehuntAdapter.test.ts` (25: all 15 fixture rounds reproduce their
expected numbers, spread hosts, case selection, every failure mode is a RehuntError);
`test/ResponseVerificationLoop.test.ts` (14, real Start/Complete/Fail + RunRehunt +
CreateVerification + canonical POLICIES + mock): execution states/audit, failed and
rejected plans can't be verified, ATK-01 + ATK-08-approved happy paths, ATK-02/06/10
loops (evidence + carried IOC before Rec #2, no auto-execution), ATK-04 3-round cap,
ERROR/TIMEOUT/UNAVAILABLE, ALREADY_VERIFIED, manual "contained but events" → NOT_RESOLVED.
Backend jest 194/194 (+ 0-byte Approval file), AI pytest 117/117, tsc OK.

Live PostgreSQL (real Prisma stack, mock re-hunt, real LLM for Rec #2, notifications no-op'd):

* **ATK-01 happy path**: plan READY → IN_PROGRESS → COMPLETED (executed_at/completed_at,
  execution_result) → re-hunt round 1 NO_MATCH → Verification RESOLVED (evidenceSource
  MOCK_REHUNT) → incident `resolved`, Investigation #1 COMPLETED. Audit: RESPONSE_PLAN_CREATED
  → RESPONSE_STARTED → RESPONSE_COMPLETED → VERIFICATION_COMPLETED.
* ATK-08 approved plan: executed → RESOLVED. ATK-08 rejected plan: start → INVALID_STATE,
  executed_at null, 0 verifications.
* **ATK-02 unresolved**: MATCH (2 events) → NOT_RESOLVED → Investigation #2 ACTIVE (#1
  COMPLETED) → 2 WAZUH_EVENT evidence rows (MOCK_REHUNT) linked to IOC 185.220.101.46
  (source REHUNT) → LLM Recommendation #2 VALIDATED for cycle 2 (its summary cites the
  cycle-2-only "non-existent user" event), #1 SUPERSEDED → no new plan, nothing started.
* ATK-10 with forced TIMEOUT: `REHUNT_TIMEOUT`, 0 verifications, incident `investigating`,
  audit REHUNT_FAILED{code: TIMEOUT}.

Known limitations / blockers (not fixed):

* ATK-04 live: without alert correlation (§45.3) the C2 indicators live only in the
  related alert's own incident, so a live ATK-04 round 3 (C2-only traffic) would NOT match
  the primary incident — the 3-round escalation is proven with the correlated IOC set in tests.
* No "escalated" incident status / escalation queue — escalation is audit-only today.
* The real Wazuh Indexer cannot report `matchedIocValues`, so with the real provider
  cycle-2 evidence carries no IOC links (the mock can).
* HTTP routes for start/complete/rehunt need role tokens; verified via the same use cases.
* No Response Ticket entity separate from ResponsePlan (see §45.5).

Task 10 needs:

* A repeatable 10-case E2E runner (script/test) driving: ingest fixture → (sync) →
  generate recommendation → create plans via Policy → approve/reject where required →
  start/complete → mock re-hunt per round → assert final DB state vs fixture
  `expected.primaryResult/finalOutcome` (ATK-04 needs correlation or an explicit
  "uncorrelated" expectation).
* Negative E2E: AI timeout/invalid, re-hunt ERROR/TIMEOUT, invalid alert payload.
* Decide how the runner authenticates (role tokens) or keep it at the use-case layer.

## 45.7 TASK 10 — 10-CASE E2E + CORE FLOW AUDIT — DONE 2026-09-23

Runner: `apps/backend/scripts/e2e-mock-attacks.ts` → `npm run e2e:mock-attacks [ATK-xx ...]`
(set `E2E_REPORT_PATH` for a JSON report). Needs Postgres + running AI orchestrator (LLM).
Drives every fixture through the REAL use cases on the REAL database: WazuhAdapter →
IngestAlertFromSiem (AI `/pipeline/run` + investigation sync) → GenerateRecommendation (LLM)
→ CreateResponsePlan (Policy/asset catalog) → DecideApproval (manager) → Start/Complete (IR)
→ RunRehunt (MockRehuntAdapter, round = cycle) → CreateVerification → loop/escalation.
Only notifications are no-op'd. Decision: the runner stays at the use-case layer (the HTTP
routes need role tokens; the runner never handles credentials). Each case is a fresh incident,
so the runner is repeatable (dev DB accumulates rows). Results are PASS / FAIL / GAP; GAP =
documented product gap, never counted as PASS. No production code changed in Task 10.

Result of the full run (391 PASS, 0 FAIL, 3 GAP, 289 s, exit 0):

| ATK | Flow | Approval | Verification | Final state | Result |
|---|---|---|---|---|---|
| ATK-01 | 1 cycle, 1 plan | not required | RESOLVED | RESOLVED | PASS |
| ATK-02 | 2 cycles, 2 plans | not required | NOT_RESOLVED → RESOLVED | RESOLVED | PASS |
| ATK-03 | 1 cycle | not required | RESOLVED | RESOLVED | PASS |
| ATK-04 (production, uncorrelated) | 3 cycles | not required | NOT_RESOLVED → NOT_RESOLVED → **RESOLVED** | **RESOLVED (fixture: ESCALATED)** | **GAP** |
| ATK-04 (analyst-correlated) | 3 cycles, 3 plans | not required | NOT_RESOLVED ×3 | ESCALATED, incident investigating | PASS |
| ATK-05 | 1 cycle | not required | RESOLVED | RESOLVED | PASS |
| ATK-06 | 2 cycles | not required | NOT_RESOLVED+SPREAD → RESOLVED | RESOLVED | PASS |
| ATK-07 | 1 cycle (+1 FAILED plan) | not required | RESOLVED | RESOLVED | PASS |
| ATK-08 | 1 cycle | MANAGER reject (plan A) + approve (plan B) | RESOLVED | RESOLVED | PASS |
| ATK-09 | 1 cycle (+ERROR/TIMEOUT/UNAVAILABLE) | not required | RESOLVED | RESOLVED | PASS |
| ATK-10 | 2 cycles | not required (IR review) | NOT_RESOLVED → RESOLVED | RESOLVED | PASS |

Per case the runner asserts in Postgres: incident↔alert + `incident_alerts`, Investigation #1,
SYSTEM WAZUH_ALERT evidence, expected IOCs linked, no cycle-less IOC, AI results
(llm_analyst/ml_risk/recommendation_agent) for this incident, VALIDATED recommendation for the
cycle, policy/approval, READY plan, executed_at/completed_at, verification vs fixture round,
MOCK_REHUNT provenance, no auto-created/auto-started plan, and on NOT_RESOLVED: next cycle ACTIVE /
previous COMPLETED, new-cycle evidence = re-hunt events, carried IOCs, Recommendation #n for the new
cycle created AFTER its evidence, previous SUPERSEDED; on round 3: no 4th cycle, no new
recommendation, INVESTIGATION_ESCALATED. Negative E2E (live): invalid payload → 422 + no alert;
AI timeout / unreachable → AI_UNAVAILABLE; malformed / empty / self-approval-key → INVALID_AI_OUTPUT;
none persisted, each audited, valid recommendation never superseded; re-hunt
ERROR/TIMEOUT/UNAVAILABLE (ATK-09) → no verification; FAILED plan (ATK-07) and REJECTED plan
(ATK-08) → never started/verified. Integrity (15 SQL invariants over the run's incidents): all 0
violations; `syncIncident` re-run → no duplicates.

**ATK-04 correlation decision.** The C2 IOCs (45.155.205.233, vigix-mock-c2.net,
…/stage2.bin) exist only in the RELATED alert, which VIGIX ingests as a separate incident (no
alert correlation). The primary incident's re-hunt therefore misses the round-3 C2-only traffic:
production behaviour is a **false RESOLVED at round 3** (security-relevant gap). The fixture was
NOT changed. The runner reports that variant as GAP, and additionally runs an
"analyst-correlated" variant where an analyst adds the related alert's C2 IOCs to Investigation #1
through the existing manual-IOC path (`CreateIocUseCase`, created_by `analyst-e2e`) — no DB
shortcut; that variant matches the fixture (3 rounds → escalated).

CORE FLOW CHECK (code audit + E2E + DB):

| Link | Data / mechanism | Result |
|---|---|---|
| Alert → Incident | alertId; AI `ensure_incident_for_alert` + `incident_alerts` via sync | PASS |
| Incident → Investigation | incidentId; `syncIncident` at ingestion (cycle 1) / `incrementInvestigationNumber` | PASS |
| Investigation → Evidence/IOC | investigationId; WAZUH_ALERT evidence + `extractAlertIocs` links | PASS |
| Evidence → AI | LangGraph runs on the alert at ingestion; recommendation context = cycle evidence/IOCs | PASS with issue (see 1) |
| AI → Recommendation | context → LLM → validator → persist/supersede | PASS |
| Recommendation → Policy | severity, risk, assetCriticality (catalog), actionImpact via ApprovalService | PASS |
| Policy → Approval | approval only when Policy requires; role enforced | PASS |
| Approval → Response Plan | APPROVED→READY, REJECTED→blocked | PASS |
| Response Plan → Execution | Start/Complete/Fail; executed_at/completed_at | PASS |
| Execution → Re-hunt | COMPLETED plan only; hosts/IOCs/rule/round → provider | PASS |
| Re-hunt → Verification | derived verdict; errors → no verification | PASS |
| Verification → New Investigation | cycle n+1 → evidence + carried IOCs → Rec #n+1 | PASS |
| Max 3 rounds | no 4th cycle, escalation audited | PASS |
| Error safety | ERROR/TIMEOUT≠NO_MATCH, FAILED≠RESOLVED, REJECTED≠EXECUTED, AI failure≠recommendation | PASS |
| PostgreSQL integrity | 15 invariants, idempotent sync | PASS |

**CORE FLOW STATUS: CONNECTED WITH ISSUES.** Remaining issues (not fixed in Task 10):

1. No per-cycle AI re-analysis: the LangGraph analysis runs once per alert; for cycle ≥2 the
   recommendation uses the new cycle's evidence but the `aiAnalysis` in its context is the
   cycle-1 analysis of the original alert (spec §26 "New AI Analysis" not implemented).
2. ~~No alert correlation → related alerts become separate incidents; ATK-04 can be falsely
   RESOLVED (see decision above).~~ FIXED 2026-10-05 — automatic correlation at ingestion (§45.11).
3. No escalated status / escalation queue — escalation is audit-only.
4. HTTP layer of the workflow routes not exercised end-to-end (role tokens); use cases are.
5. Real Wazuh Indexer cannot report `matchedIocValues` → no carried IOCs with the real provider.
6. AI threat intel stores relative request paths as `URL` (ATK-05/06) and the agent's own IP as an IOC.
7. `actions.default_approval_required` not used by any policy rule; `RiskScore` has no timestamp.
8. Webhook has no HMAC verification; ingestion waits synchronously for the AI pipeline.

Next (not started): Task 11/12 per §68 — decide on issues 1–3 (correlation is the
security-relevant one), then Email / Reports / Frontend; Real Wazuh last.

## 45.8 DEV DATABASE LOSS + REBUILD — 2026-09-23

During Task 10.3 the dev DB `soar_platform` was wiped by passing it as Prisma's
`--shadow-database-url` (Prisma drops/recreates the shadow DB). No WAL archive / dump existed →
not recoverable. Rebuilt with additive-only steps:
- 10 migrations recorded via `migrate resolve --applied` (1–8 original; 9
  `20260923120000_response_process_recommendation_v2`; 10
  `20260923163000_reconcile_ai_orchestrator_drift` = the AI-only columns: decisions (18 cols),
  agent_executions.output_contract/error_code/error_message, risk_scores.decision_id FK), now also
  in `schema.prisma` so Prisma proposes no DROP. LangGraph checkpoint tables are created at runtime.
- Seed made idempotent (alert/incident found-or-created) and re-run.
- Backups: `D:\vigix-forensics\2026-09-23\*.sql`.
**Rule:** never use `soar_platform` as a shadow DB; only `soar_platform_shadow`. No `migrate
reset` / `db push`. `pg_dump` before any migration or seed.

## 45.9 TASK 10.3 — RESPONSE PROCESS RECOMMENDATION v2 — DONE 2026-09-23

A Recommendation is now the **action-level expansion of the selected Action(s)** and never
restates the Core Flow. 1 Recommendation → 1..N RecommendationSteps; each step = ONE containment
Action on ONE target with `instructions[] {order, instruction, target, expectedResult}` +
`verificationCriteria`.

Catalog (seed, idempotent upserts):
- Action-level runbooks RB-BLOCK-SOURCE-IP / RB-BLOCK-DOMAIN / RB-BLOCK-URL / RB-ISOLATE-ENDPOINT
  / RB-DISABLE-ACCOUNT (tool-agnostic), linked via `actions.runbook_id`. RB-QUARANTINE-FILE was NOT
  created: there is no quarantine-file action in the catalog (ACT-006 was retired); malware routes
  to Isolate Endpoint. ACT-QUARANTINE-EMAIL has no runbook yet.
- Incident-level playbooks PB-SSH-BRUTEFORCE / PB-MALWARE / PB-SQL-INJECTION /
  PB-ACCOUNT-COMPROMISE / PB-POWERSHELL (`trigger_conditions`: scope INCIDENT, incidentType,
  mitreTechniques, allowedActions). STC-001 stays the generic Core Flow and is never selectable.

Flow: `RecommendationContextBuilder` → `PlaybookSelector` (deterministic from MITRE) + per allowed
action: its runbook + Policy result via `ApprovalService.evaluate` (the single Policy path) →
`RecommendationPromptBuilder` (mandatory v2 statements, targetable values, citable evidence) → AI
`/recommendations/generate` (strict v2 schema) → `RecommendationValidator` v2 → persist steps
(instructions, verification_criteria, phase=ACTION, requiresApproval = Policy) + PlaybookSnapshot
per cycle (`recommendations.snapshot_id`).

Validator v2 rejects the WHOLE candidate on any of the following. Nothing is persisted, no plan is
created, and the failure is audited as `RECOMMENDATION_GENERATION_FAILED`:
- invented action or disabled action; action not allowed by the playbook
- Core Flow repetition: an INVESTIGATION/VERIFICATION action, or validate/monitor/re-hunt/approval/close
  wording in the objective or instructions, or a summary naming ≥4 lifecycle phases
- runbook ≠ the action's runbook; playbook ≠ the selected playbook
- target not an **evidence-linked** IOC or affected host, or the wrong kind for the action
- IP/hash/URL/domain/email/port/host/command in free text that the evidence does not contain
- invented or missing evidence refs
- responsibleRole ≠ Policy
- policy bypass: waive/skip/auto/pre-approved wording, or approval=false where Policy requires it
- empty or mis-ordered instructions; duplicate action+target
Live E2E showed why the strictness matters: the LLM produced a mistyped IP (185.20.101.45) and
proposed blocking the victim agent's own IP (an unlinked IOC) — both rejected.

Traceability: `ResponsePlan.recommendationStepId` is persisted/read (repo + mapper) and is the
source of truth; RequestApproval resolves the step by id (action+target only for legacy null rows).
Start/Complete/Fail write `step_executions` (planId, recommendationStepId, status, executedBy,
times, actualResult). Incident → Recommendation → RecommendationStep → Action → ResponsePlan →
StepExecution is asserted by the E2E + SQL invariants.

Also: prompt marks non-targetable IOCs "CONTEXT ONLY" and lists exact citable refs; analyst-added
IOCs (created_by = a user) are targetable; evidence refs match escape/case-insensitively and are
stored canonically; the AI route re-asks the LLM once on unparseable JSON (still strict-validated);
action-level runbooks no longer mention re-hunt (that is the Core Flow's verification).

Tests: backend jest 236 passed (the 0-byte `Approval.integration.test.ts` suite remains a
pre-existing FAIL-to-load); AI pytest 125 passed; `tsc --noEmit` clean; AI import OK.

E2E ATK-01..10 (real PostgreSQL + live LLM, final run): **586 PASS, 3 FAIL, 3 GAP** (584 s).
The 3 FAILs are the runner's "generation attempt 1" checks for ATK-03/04/05, where the validator
rejected the LLM's first output: an altered evidence path, a normalization bug of mine (fixed
afterwards; see below), and a mistyped IP `18.220.101.77`. The re-requested recommendation
validated each time and all 11 flows completed. 3 GAP = known ATK-04 correlation gap
(§45.7). 21 SQL invariants (6 new for v2 traceability) → 0 violations. 9 live v2 negative
cases rejected with nothing persisted and no plan.

| ATK | Playbook | Actions (Policy role / approval) | Verification | Final |
|---|---|---|---|---|
| 01 | PB-SSH-BRUTEFORCE | Block IP (SOC) — LLM declined Disable root: no successful logon | RESOLVED | RESOLVED |
| 02 | PB-SSH-BRUTEFORCE | Block IP (SOC) | NOT_RESOLVED → RESOLVED | RESOLVED |
| 03 | PB-MALWARE | Isolate WKS-HR-03 + Block domain (IR_TEAM) | RESOLVED | RESOLVED |
| 04 prod | PB-MALWARE | Isolate WKS-FIN-07 (IR_TEAM) | NR → NR → RESOLVED | RESOLVED (GAP) |
| 04 correlated | PB-MALWARE | + analyst C2 IOCs | NR ×3 | ESCALATED |
| 05 | PB-SQL-INJECTION | Block IP (SOC) | RESOLVED | RESOLVED |
| 06 | PB-SQL-INJECTION | Block IP (SOC) | NR+SPREAD → RESOLVED | RESOLVED |
| 07 | PB-ACCOUNT-COMPROMISE | Disable j.smith + Block IP (SOC) | RESOLVED | RESOLVED |
| 08 | PB-ACCOUNT-COMPROMISE | Disable j.smith + Block IP (IR_TEAM, MANAGER approval) reject+approve | RESOLVED | RESOLVED |
| 09 | PB-POWERSHELL | Isolate + Block domain + Block URL + Disable account (IR_TEAM) | RESOLVED | RESOLVED |
| 10 | PB-POWERSHELL | Isolate + Block domain/URL/IP (IR_TEAM, no approval) | NR → RESOLVED | RESOLVED |

Known GAPs after 10.3: ATK-04 alert correlation (unchanged); LLM (gemma via gateway) sometimes
mistypes IPs, garbles long Windows-path evidence titles (ATK-04 re-run: "fin.anal_analyst",
"svchot32.exe") or breaks JSON: rejected safely, and a human re-request is needed (a possible fix is to cite
evidence by short id instead of full title); no JSON mode
on the gateway; RB-QUARANTINE-FILE / quarantine-email runbook absent (no catalog action);
StepExecution is 1 row per plan (instruction-level progress not tracked); ATK-10 Run-key removal
has no catalog action (the re-hunt is fixture-driven). Next: Task 11 per §68.

**Stabilization (2026-09-23):** evidence is cited ONLY by backend-assigned stable ids — `E<n>` (cycle
evidence row), `I<n>` (IOC), recorded MITRE technique id — resolved by the validator to the recorded
value that is persisted; unknown ids / raw titles / raw values → INVENTED_EVIDENCE (the earlier
escape-tolerant title matching was removed: stricter). Prompt de-duplicated (evidence/IOCs listed once
with ids, catalog description dropped, ≤6 short instructions per step): 11.6 KB → 9.6 KB. Timeout
unchanged. Files: RecommendationContextDto.ts (`ref`, `citableEvidence`), RecommendationContextBuilder.ts,
RecommendationValidator.ts, RecommendationPromptBuilder.ts, FakeRecommendationAgent.ts,
generate-system.md, RecommendationGeneration.test.ts. Tests: backend 240 passed, recommendation 60, AI 125.

**Final full E2E after stabilization (real PostgreSQL + real LLM): 586 PASS / 1 FAIL / 3 GAP (611 s).**
ATK-01/02/03/05/06/07/09/10 PASS; ATK-04 correlated PASS; ATK-04 production GAP (correlation, unchanged);
ATK-08 flow fully completed (MANAGER reject + approve, RESOLVED) — the single FAIL is the runner's
"generation attempt 1" check: the validator rejected an LLM IP typo `185.22.101.90` (recorded
`185.220.101.90`) as INVENTED_IOC; the re-request validated. 0 LLM timeouts, 0 INVENTED_EVIDENCE,
0 invented targets, 0 role/policy, 0 recommendationStepId, 0 verification-loop failures; 22 SQL
invariants 0 violations; 17 negative checks PASS.

---

# 46. DEVELOPMENT PLAN

The project must be completed in this order.

---

## PHASE 0 — CURRENT STATE AUDIT

First inspect the repository.

Check:

```text
apps/backend
apps/ai-orchestrator
apps/frontend
prisma
tests
docker-compose
resources
fixtures
```

Search for:

```text
Policy
Recommendation
ResponsePlan
ResponseTicket
Approval
Verification
Rehunt
Wazuh
Mock
```

Do not modify architecture during Phase 0.

Output:

```text
What exists
What works
What fails
What is missing
```

---

# 47. PHASE 1 — FIX AI ORCHESTRATOR

Priority:

```text
CRITICAL
```

Tasks:

1. Reproduce Recommendation Agent import failure.
2. Identify root cause.
3. Fix import/module/configuration issue.
4. Verify:

```bash
python -c "from src.agents.recommendation_agent.agent import run; print('IMPORT_OK')"
```

5. Start FastAPI.
6. Verify AI endpoint.
7. Run a real sample analysis.
8. Verify LangGraph execution.

Do not rewrite the AI architecture unless the existing architecture is fundamentally broken.

---

# 48. PHASE 2 — MOCK ALERT + BACKEND → AI

Use Mock Wazuh Alert as the development input.

Flow:

```text
Mock Wazuh JSON
 ↓
Alert Ingestion
 ↓
Incident
 ↓
Investigation
 ↓
AI API
```

Verify the actual request/response contract.

Check:

```text
DTO
Controller
Use Case
HTTP client
AI endpoint
Error handling
Timeout
Validation
```

---

# 49. PHASE 3 — AI → RECOMMENDATION PERSISTENCE

Verify:

```text
AI Analysis
 ↓
Recommendation
 ↓
Database
 ↓
Incident
```

The recommendation must be persisted and retrievable.

Verify that:

```text
AI failure
AI timeout
Invalid AI response
```

do not create fake successful recommendations.

---

# 50. PHASE 4 — RECOMMENDATION → POLICY

Connect:

```text
Recommendation
 ↓
Policy Evaluation
```

Policy must remain deterministic.

Test:

```text
LOW
MEDIUM
HIGH
CRITICAL
```

and relevant:

```text
Risk
Asset Criticality
Action Impact
```

if these fields already exist.

---

# 51. PHASE 5 — POLICY → APPROVAL

Verify:

```text
No approval
IR review
Manager approval
```

Test both:

```text
Approve
Reject
```

A rejected approval must not proceed to execution.

---

# 52. PHASE 6 — APPROVAL → RESPONSE PLAN

Verify:

```text
Approved
 ↓
Response Plan created
```

and:

```text
Rejected
 ↓
No response execution
```

The response plan must preserve:

```text
Responsible role
Actions
Expected result
Verification criteria
```

---

# 53. PHASE 7 — RESPONSE PLAN → RESPONSE TICKET

Verify:

```text
Response Plan
 ↓
Response Ticket
 ↓
Assignment
 ↓
Execution status
```

The ticket must be linked to:

```text
Incident
Response Plan
User/Role
```

---

# 54. PHASE 8 — RESPONSE TICKET → VERIFICATION

Simulate human execution.

Example:

```text
IR marks action as executed
 ↓
Verification
```

No actual firewall/EDR/security infrastructure modification is required.

---

# 55. PHASE 9 — MOCK RE-HUNT

Implement/verify:

```text
MATCH
NO_MATCH
ERROR
TIMEOUT
```

Expected behavior:

```text
MATCH
 ↓
Not resolved / continue investigation

NO_MATCH
 ↓
Candidate for resolved verification

ERROR/TIMEOUT
 ↓
Verification failure
```

Never silently convert error into no-match.

---

# 56. PHASE 10 — ITERATIVE RESPONSE LOOP

Verify:

```text
NOT_RESOLVED
```

causes:

```text
New Investigation
 ↓
New AI Analysis
 ↓
New Recommendation
 ↓
Policy
 ↓
Approval
 ↓
Response Plan
 ↓
Response Ticket
 ↓
Verification
```

Maximum:

```text
3 rounds
```

Then escalate to IR if still unresolved.

---

# 57. PHASE 11 — EMAIL

After core E2E works:

```text
Approval
 ↓
Administrative notification
 ↓
Email
```

n8n may be used for email notification.

Do not block core application development on Gmail credentials.

If credentials are unavailable:

```text
Mock Email Adapter
```

may be used for tests.

---

# 58. PHASE 12 — REPORTING

Verify reports for:

```text
Total incidents
Closed cases
IR cases
Manager approvals
Manager rejections
Response time
Resolution time
Verification
Re-hunt
```

Verify monthly reporting.

---

# 59. PHASE 13 — FRONTEND E2E

Frontend must connect to the actual backend.

Verify:

```text
Dashboard
Incidents
Investigation
AI Analysis
Recommendation
Approval
Response Tickets
Verification
Reports
Knowledge
Settings
```

Role-specific views:

```text
SOC
IR
Manager
```

Do not redesign UI unnecessarily.

Focus on completing existing screens and API integration.

---

# 60. PHASE 14 — REAL WAZUH

Only after the core system works.

Deploy local/dev Wazuh:

```text
Wazuh Manager
Wazuh Indexer
Wazuh Agent
```

Test:

```text
Agent
 ↓
Manager
 ↓
Indexer
 ↓
VIGIX
```

Then implement real:

```text
Re-hunt
```

against Wazuh Indexer.

Real Wazuh integration is the final infrastructure validation.

---

# 61. ACCEPTANCE TEST A — COMPLETE MOCK FLOW

The complete system must support:

```text
Mock Wazuh Alert
 ↓
Alert
 ↓
Incident
 ↓
Investigation
 ↓
Evidence
 ↓
AI Analysis
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Approval if required
 ↓
Response Plan
 ↓
Response Ticket
 ↓
Human Execution Simulation
 ↓
Verification
 ↓
Mock Re-hunt
 ↓
RESOLVED
```

This is the most important acceptance test.

---

# 62. ACCEPTANCE TEST B — UNRESOLVED LOOP

Test:

```text
Mock Alert
 ↓
Response
 ↓
Verification
 ↓
NOT_RESOLVED
```

Expected:

```text
New Investigation
 ↓
New Evidence
 ↓
New Recommendation
```

The system must NOT directly execute another response.

---

# 63. ACCEPTANCE TEST C — APPROVAL REJECTION

Test:

```text
Recommendation
 ↓
Manager Approval
 ↓
REJECT
```

Expected:

```text
Response is NOT executed.
Audit log is created.
Reason is stored.
```

---

# 64. ACCEPTANCE TEST D — RE-HUNT FAILURE

Test:

```text
Re-hunt
 ↓
TIMEOUT
```

Expected:

```text
Verification does NOT become RESOLVED.
```

Same for:

```text
ERROR
QUERY_FAILURE
INDEXER_UNAVAILABLE
```

---

# 65. ACCEPTANCE TEST E — REAL WAZUH

After Phase 14:

```text
Real Wazuh Alert
 ↓
VIGIX
 ↓
Investigation
 ↓
AI
 ↓
Recommendation
 ↓
Policy
 ↓
Approval
 ↓
Response
 ↓
Verification
 ↓
Real Wazuh Re-hunt
```

---

# 66. MINIMUM FAILURE TESTS

Every critical integration must test failure.

Required cases:

```text
AI timeout
AI invalid response
AI unavailable
Database failure
Policy failure
Approval rejection
Response ticket failure
Wazuh unavailable
Indexer unavailable
Re-hunt timeout
Re-hunt query error
Missing evidence
Invalid alert
Unknown alert format
```

---

# 67. CLAUDE CODE DEVELOPMENT RULES

## Rule 1 — Inspect before modifying

Always:

```text
Search
Read
Understand
Test
Modify
Test again
```

---

## Rule 2 — Do not rewrite working architecture

Do NOT:

```text
Replace Clean Architecture
Replace Prisma
Replace LangGraph
Replace Policy Engine
Replace existing domain models
```

unless the repository proves the current design is unusable.

---

## Rule 3 — Reuse existing code

Before creating:

```text
Service
Use Case
Repository
DTO
Entity
Adapter
Controller
```

search for an existing implementation.

---

## Rule 4 — No duplicate domains

Do not create:

```text
Second Policy system
Second Approval system
Second Response Plan
Second Verification system
Second Re-hunt system
```

---

## Rule 5 — Preserve safety boundaries

Never implement:

```text
AI → automatic security action
```

without an explicit future architectural decision.

Current system is:

```text
AI recommendation
+
Human approval
+
Human execution
```

---

## Rule 6 — Tests are mandatory

After modifying backend logic:

```text
Run unit tests
Run integration tests
Run relevant E2E tests
```

Do not report success without testing.

---

# 68. IMMEDIATE TASK ORDER

Claude Code should start from here.

> Status 2026-09-23: TASKS 1–10 DONE (see §45.1–§45.7). Core flow: CONNECTED WITH ISSUES
> (§45.7). Next (not started): TASK 11/12 — see §45.7 "Next".

### TASK 1

Inspect current repository state.

### TASK 2

Reproduce the current AI Recommendation Agent import failure.

### TASK 3

Fix the AI runtime/import blocker.

### TASK 4

Start AI service and verify endpoint.

### TASK 5

Find existing Mock/Wazuh fixtures.

If none exist:

```text
Create minimal deterministic Mock Wazuh fixture.
```

### TASK 6

Connect:

```text
Mock Alert
 ↓
Backend
 ↓
AI
```

### TASK 7

Verify:

```text
AI
 ↓
Recommendation
 ↓
Database
```

### TASK 8

Complete:

```text
Recommendation
 ↓
Policy
 ↓
Approval
 ↓
Response Plan
 ↓
Response Ticket
```

### TASK 9

Complete:

```text
Response Ticket
 ↓
Verification
 ↓
Mock Re-hunt
```

### TASK 10

Complete unresolved loop.

### TASK 11

Run full backend + AI E2E test.

### TASK 12

Finish Email / Reports / Frontend.

### TASK 13

Only then integrate real Wazuh Docker.

---

# 69. DEFINITION OF DONE

VIGIX is considered functionally complete when this works:

```text
Wazuh / Mock Alert
        ↓
Alert Ingestion
        ↓
Incident
        ↓
Investigation
        ↓
Evidence
        ↓
AI Analysis
        ↓
Risk
        ↓
Recommendation
        ↓
Policy
        ↓
Approval
        ↓
Response Plan
        ↓
Response Ticket
        ↓
Human Execution
        ↓
Verification
        ↓
Re-hunt
        ↓
Resolved
```

And when unresolved:

```text
NOT_RESOLVED
        ↓
New Investigation
        ↓
New Recommendation
        ↓
Policy
        ↓
Approval
        ↓
New Response
        ↓
Verification
```

with a maximum investigation/re-hunt loop.

---

# 70. FINAL ARCHITECTURAL PRINCIPLE

The final VIGIX system must behave like:

```text
              ┌───────────────────────┐
              │       WAZUH           │
              │ Detection / Events    │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │        VIGIX          │
              │ Alert / Incident      │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Investigation      │
              │ Evidence + IOC        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    AI Orchestrator    │
              │ RAG + TI + MITRE      │
              │ ML + LLM              │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │    Recommendation     │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │     Policy Engine     │
              └───────────┬───────────┘
                          │
                    Approval?
                     /       \
                   No         Yes
                   │           │
                   │      Human Decision
                   │           │
                   └─────┬─────┘
                         ▼
              ┌───────────────────────┐
              │    Response Plan      │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Response Ticket     │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Human IR Execution   │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │      Verification     │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │       Re-hunt         │
              └───────────┬───────────┘
                          │
                 ┌────────┴────────┐
                 ▼                 ▼
              RESOLVED          ABNORMAL
                                   │
                                   ▼
                            New Investigation
```

## NON-NEGOTIABLE RULE

> **Do not start by building Wazuh.**
>
> **First make the VIGIX application workflow work end-to-end using Mock Wazuh Alerts and Mock Re-hunt.**
>
> **Then integrate real Wazuh Docker in Phase 14.**

## NON-NEGOTIABLE DEVELOPMENT ORDER

```text
1. Fix AI runtime
2. Verify Backend ↔ AI
3. Verify Recommendation
4. Verify Policy
5. Verify Approval
6. Verify Response Plan
7. Verify Response Ticket
8. Verify Verification
9. Verify Mock Re-hunt
10. Verify unresolved loop
11. Verify E2E
12. Email / Reports / Frontend
13. Real Wazuh
```

Claude Code must continue from the **actual repository state**, not from assumptions in this document.

When a task is completed, update this file's status section if necessary.
35. 5 ATTACK TYPES × 2 CASES
REQUIRED E2E TEST SUITE

VIGIX MUST be tested using:

5 Attack Types
×
2 Cases per Attack Type
=
10 Test Cases

These are not merely alert-ingestion tests.

Each case should attempt to exercise the VIGIX workflow:

Mock Wazuh Alert
 ↓
Alert Ingestion
 ↓
Incident
 ↓
Investigation
 ↓
Evidence / IOC
 ↓
AI Analysis
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Approval if required
 ↓
Response Plan
 ↓
Response Ticket
 ↓
Human Execution Simulation
 ↓
Verification
 ↓
Mock Re-hunt
 ↓
Final Result
36. ATTACK TYPE 1 — SSH BRUTE FORCE
Case 1A — SSH Brute Force → Resolved

Scenario:

Multiple failed SSH authentication attempts
from a suspicious source IP.

Expected:

Alert
 ↓
Incident
 ↓
Investigation
 ↓
IOC = Source IP
 ↓
AI identifies brute-force behavior
 ↓
MITRE mapping
 ↓
Risk assessment
 ↓
Recommendation
 ↓
Policy
 ↓
Response
 ↓
Human execution simulation
 ↓
Verification
 ↓
Mock Re-hunt
 ↓
NO_MATCH
 ↓
RESOLVED

Test objectives:

SSH attack classification
IP extraction
MITRE mapping
Recommendation generation
Response workflow
Successful verification
Case 1B — SSH Brute Force → NOT_RESOLVED

Scenario:

SSH brute-force activity continues after response.

Expected:

Response
 ↓
Verification
 ↓
Mock Re-hunt
 ↓
MATCH
 ↓
NOT_RESOLVED
 ↓
New Investigation
 ↓
New Recommendation

Must verify:

No automatic containment
New investigation is created
New recommendation is generated
Policy is evaluated again
Loop counter increases
37. ATTACK TYPE 2 — MALWARE / MALICIOUS FILE
Case 2A — Malware → Resolved

Scenario:

A suspicious/malicious file is detected.

Evidence may include:

File Hash
File Path
Endpoint
Process
Threat Intelligence

Expected:

Alert
 ↓
Incident
 ↓
Investigation
 ↓
Hash enrichment
 ↓
Threat Intelligence
 ↓
AI Analysis
 ↓
Recommendation
 ↓
Policy
 ↓
Response Plan
 ↓
Ticket
 ↓
Human execution simulation
 ↓
Verification
 ↓
Re-hunt
 ↓
NO_MATCH
 ↓
RESOLVED
Case 2B — Malware → NOT_RESOLVED

Scenario:

Malicious activity remains after response.

Expected:

Verification
 ↓
Re-hunt MATCH
 ↓
NOT_RESOLVED
 ↓
New Investigation
 ↓
New Evidence
 ↓
New Recommendation

Must verify that the second response does not bypass Policy/Approval.

38. ATTACK TYPE 3 — SQL INJECTION / WEB ATTACK
Case 3A — SQL Injection → Resolved

Scenario:

Web application receives suspicious SQL injection requests.

Evidence:

Source IP
URL
Request pattern
Target endpoint

Expected:

Alert
 ↓
Incident
 ↓
Investigation
 ↓
IOC extraction
 ↓
AI Analysis
 ↓
MITRE / threat context
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Response
 ↓
Verification
 ↓
Re-hunt
 ↓
NO_MATCH
 ↓
RESOLVED
Case 3B — SQL Injection → SPREAD

Scenario:

Similar malicious requests are observed against multiple
application endpoints after initial response.

Expected:

Verification
 ↓
Re-hunt
 ↓
MATCH / additional indicators
 ↓
SPREAD
 ↓
New Investigation
 ↓
New Recommendation
 ↓
Policy
 ↓
Possible escalation

Must verify:

Multiple affected resources can be represented
Incident is not incorrectly closed
New evidence is attached
Response recommendation is regenerated
39. ATTACK TYPE 4 — ACCOUNT COMPROMISE
Case 4A — Suspicious Login

Scenario:

Unusual authentication activity from a suspicious source.

Evidence:

Username
Source IP
Timestamp
Authentication result
Location/context if available

Expected:

Alert
 ↓
Incident
 ↓
Investigation
 ↓
IOC enrichment
 ↓
AI Analysis
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Response
 ↓
Verification
Case 4B — Privilege Escalation / High Impact

Scenario:

Suspicious login followed by privilege escalation
or high-impact account activity.

Expected:

Investigation
 ↓
AI Analysis
 ↓
HIGH / CRITICAL assessment where justified
 ↓
Policy evaluation
 ↓
Approval if policy requires it
 ↓
Manager/IR decision
 ↓
Response Plan

This case specifically tests:

High-risk workflow
Approval logic
Human decision
Rejection/approval behavior
Audit logging

Do not assume Manager approval solely from an AI-generated label.

The actual Policy Engine is authoritative.

40. ATTACK TYPE 5 — POWERSHELL / COMMAND EXECUTION
Case 5A — Suspicious PowerShell

Scenario:

Suspicious PowerShell execution is detected.

Evidence may include:

Command line
Process
User
Endpoint
Hash
Parent process

Expected:

Alert
 ↓
Incident
 ↓
Investigation
 ↓
Evidence
 ↓
AI Analysis
 ↓
MITRE
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Response
 ↓
Verification
 ↓
Re-hunt
Case 5B — PowerShell + Persistence Indicator

Scenario:

Suspicious PowerShell execution combined with
a persistence indicator.

Expected:

Investigation
 ↓
Multiple evidence
 ↓
AI Analysis
 ↓
Risk
 ↓
Recommendation
 ↓
Policy
 ↓
Approval if required
 ↓
Response Plan
 ↓
Response Ticket
 ↓
Verification
 ↓
Re-hunt

This case tests more complex correlation and approval logic.

41. 10-CASE TEST MATRIX

The complete test matrix is:

ID	Attack Type	Scenario	Main Expected Result
ATK-01	SSH Brute Force	Initial brute force	RESOLVED
ATK-02	SSH Brute Force	Activity continues	NOT_RESOLVED
ATK-03	Malware	Malicious file removed	RESOLVED
ATK-04	Malware	Malicious activity remains	NOT_RESOLVED
ATK-05	SQL Injection	Single web attack	RESOLVED
ATK-06	SQL Injection	Multiple affected endpoints	SPREAD
ATK-07	Account Compromise	Suspicious login	Response + Verification
ATK-08	Account Compromise	Privilege escalation/high impact	Approval workflow
ATK-09	PowerShell	Suspicious command execution	RESOLVED
ATK-10	PowerShell	PowerShell + persistence	Approval/complex response
42. TEST CASE DATA REQUIREMENTS

Each test case should provide enough evidence for the system to work.

Minimum:

Alert ID
Timestamp
Rule ID
Rule Level
Description
Agent
Source IP if applicable
Destination IP if applicable
Username if applicable
File Hash if applicable
URL if applicable
Domain if applicable
Command Line if applicable
MITRE data if available

Do not force irrelevant fields into every attack type.

For example:

SSH → source IP / username
Malware → hash / file
SQL Injection → URL / source IP
Account Compromise → username / source IP
PowerShell → command line / process
43. TEST FIXTURE STRUCTURE

Before creating directories, search the repository for existing test/fixture conventions.

If none exist, a possible structure is:

resources/
└── mock-attacks/
    ├── ssh-bruteforce/
    │   ├── case-01-resolved.json
    │   └── case-02-not-resolved.json
    │
    ├── malware/
    │   ├── case-01-resolved.json
    │   └── case-02-not-resolved.json
    │
    ├── sql-injection/
    │   ├── case-01-resolved.json
    │   └── case-02-spread.json
    │
    ├── account-compromise/
    │   ├── case-01-suspicious-login.json
    │   └── case-02-privilege-escalation.json
    │
    └── powershell/
        ├── case-01-suspicious-command.json
        └── case-02-persistence.json

Do not create duplicate fixture locations if an existing convention is already present.

44. E2E TEST REQUIREMENTS

Each of the 10 cases must verify more than HTTP 200.

At minimum verify:

1. Alert accepted
2. Incident created
3. Evidence available
4. AI analysis generated
5. Recommendation generated
6. Policy evaluated
7. Approval state correct
8. Response plan created when appropriate
9. Response ticket created
10. Verification executed
11. Re-hunt executed
12. Correct final state
13. Audit trail exists

Not every case needs every step to have the same state.

For example:

Approval not required

is a valid expected result.

45. NEGATIVE TESTS FOR THE 10 ATTACK CASES

Each attack family should also test failures where practical.

Examples:

Missing IOC
Invalid Wazuh JSON
AI timeout
AI invalid response
Threat Intelligence timeout
Policy evaluation failure
Approval rejection
Response ticket failure
Re-hunt timeout
Re-hunt error

Important:

Re-hunt ERROR

must never result in:

RESOLVED
46. REAL WAZUH

Real Wazuh is a later integration phase.

Expected:

Wazuh Agent
     ↓
Wazuh Manager
     ↓
Wazuh Indexer
     ↓
VIGIX

For development/demo, local Wazuh Docker may be used.

The company production Wazuh server must NOT be a mandatory development dependency.

47. UBUNTU ENDPOINT

A real Ubuntu Wazuh Agent is useful for final validation.

It is NOT required for the initial 10-case Mock E2E test suite.

Core application development must be able to run using:

Mock Wazuh Alert
+
Mock Re-hunt
48. CURRENT INFRASTRUCTURE

Known project root:

D:\soar-platform

Major directories:

apps/backend
apps/ai-orchestrator
apps/frontend

Previously used infrastructure:

PostgreSQL
Qdrant
Redis
n8n
Wazuh Docker

Previously performed Wazuh Docker work included:

wazuh-docker v4.14.7
single-node configuration
indexer certificates
vm.max_map_count = 262144

Claude Code must verify actual running state instead of assuming Wazuh is running.

49. DATABASE RULE

Before modifying Prisma:

1. Search Prisma schema
2. Search domain entity
3. Search repository
4. Search use cases
5. Search controllers
6. Search tests

Do not create duplicate entities.

Do not add new tables simply because an existing table is difficult to use.

50. HISTORICAL TEST STATUS

Previously reported:

Policy          14/14
Response Plan    7/7
Approval         7/7
Verification     9/9
Re-hunt         15/15
--------------------
Total           52/52

These are historical.

Claude Code MUST rerun tests before claiming the current project is 52/52.

The new 10-case attack E2E suite is an additional validation layer.

51. CURRENT PROJECT STATUS

Claude Code must verify these statuses against the repository.

Area	Status
Overall architecture	Substantially implemented
Backend Clean Architecture	Exists
Prisma/PostgreSQL	Exists
Policy domain	Exists
Approval domain	Exists
Response Plan	Exists
Response Ticket	Exists / integration needs verification
Verification	Exists
Re-hunt concept	Exists
AI Orchestrator	FIXED 2026-09-23 — runtime verified (see §45.1)
Recommendation Agent	FIXED 2026-09-23 — run() reconstructed and verified
Backend → AI	Needs E2E verification
AI → Recommendation	Needs E2E verification
Recommendation → Policy	Needs E2E verification
Policy → Approval	Needs E2E verification
Approval → Response Plan	Needs E2E verification
Response Plan → Ticket	Needs E2E verification
Ticket → Verification	Needs E2E verification
Verification → Re-hunt	Needs E2E verification
Mock Attack Suite	DONE 2026-09-23 — fixtures + fixture/ingestion tests (§45.2)
5 × 2 attack E2E	DONE 2026-09-23 — `npm run e2e:mock-attacks`: 391 PASS / 0 FAIL / 3 GAP (ATK-04 uncorrelated) (§45.7)
Real Wazuh	Later Phase 14
Email	Partial/pending
Reports	Needs integration verification
Frontend	Needs final E2E verification
Production Wazuh	NOT a development dependency








## 45.10 FRONTEND ON REAL DATA — DASHBOARD / ALERTS / SET GROUP / INCIDENT / IR TICKETS — 2026-09-23

The Vue app (apps/src, `npm run dev --workspace=apps`, Vite proxy `/api` → :4000) now signs in against the real
backend (JWT, `POST /api/auth/login`) and these screens run on real data; the older mock screens remain under
`/demo/*` and are badged "demo" in the sidebar (Knowledge Base, Settings).

| Screen | Route | Backend |
|---|---|---|
| Operations dashboard (home) | `/dashboard` | `GET /api/v1/dashboard/summary` — alerts/incidents/responses/verifications counts, 14/7/30-day alert volume by severity, Policy SLA watchlist, top MITRE/sources, activity, integration health (AI orchestrator, re-hunt provider) |
| Alert Inbox | `/alerts` | `GET /api/v1/alerts/inbox` (summary + incident + best related hint) |
| Alert Detail | `/alerts/:id` | `GET /api/v1/alerts/:id/view`, `/related` |
| Set Group / Create Incident | modal | `POST /api/v1/incidents/:id/alerts` (merge: related alerts' auto-created incidents are absorbed, closed as `dismissed`, audited `ALERTS_MERGED`; refused if a source has response plans or is resolved), `POST /api/v1/incidents` |
| Incidents / Incident Detail (= Investigation) | `/incidents`, `/incidents/:id` | incident, alerts, timeline, investigations, evidence, IOC, MITRE, `GET …/ai-analysis`, recommendations (+ regenerate), responses (`?incidentId=`), verifications, `GET …/sla` |
| Hand off to IR (SOC) | Incident tab | creates tickets per step (`POST /api/responses`, Policy sets role/approval) + editable email via `POST /api/notifications/ir-handoff` (recipient = server `IR_TEAM_EMAIL`, confirm step) |
| IR Tickets | `/tickets` | approval per Policy (NONE / IR_TEAM / MANAGER — only the named role sees Approve/Reject), Start → Mark eradicated → **Re-hunt** (`POST /api/incidents/:id/verifications/rehunt`, source shown from `GET /api/verifications/rehunt-health`), SLA clocks per ticket |

Backend additions (additive; no schema change): alert summary/relatedness (domain/alert/alertSummary.ts), inbox /
related / view read models, `MergeAlertsIntoIncidentUseCase` + `IIncidentRepository.absorbIntoIncident`,
`GetIncidentAiAnalysisUseCase`, `IncidentSlaService` (Policy SLA, read-only, no audit), dashboard read repository +
`GetDashboardSummaryUseCase`, response-plan `incidentId` filter, and **incident status `escalated`** set by
CreateVerification when MAX_INVESTIGATION_ROUNDS is reached (loop ends, not closed). Tests: backend 252 passed
(+AlertInboxSetGroup, IncidentSla; ResponseVerificationLoop asserts `escalated`). ATK-04 E2E: correlated variant
ends `escalated` (191 PASS / 1 FAIL = LLM IP typo rejected, retry passed / 3 GAP correlation).

UI verified in the browser (SOC session): dashboard at 1280 px and at the narrow pane width (no page overflow), inbox
related hint (`…602.93 → Related to …602.91`), Set Group merged 2 incidents into INC-BBEDC52B (Alerts (3), activity,
3 WAZUH_ALERT evidence, `ALERTS_MERGED` audit), ticket SLA (P1: first response Met, resolution On track).
Not yet exercised in the UI: IR/Manager ticket actions (need those accounts signed in), the handoff email send
(needs explicit OK — it emails the real IR_TEAM_EMAIL). Re-hunt currently uses REHUNT_PROVIDER=mock (dev .env);
switching to the real Wazuh index is an .env change (REHUNT_PROVIDER unset/`wazuh` + WAZUH_INDEXER_*).
Open: report export with editable template; in-app "alert became incident" notification; AI-analysis re-run
(Retry currently refreshes the stored analysis); per-alert working severity (would need a column).

**Demo removed from the web app (2026-09-24):** router now serves only real-data screens (/dashboard, /alerts,
/alerts/:id, /incidents, /incidents/:id, /tickets, /login); all /demo/* routes, mock incident/ticket/report/knowledge/
settings screens, sidebar Quick Actions (mock), "DEMO DATA" pill, mock notifications, demo persona and "Demo
workspace" footer are gone; UserMenu shows the signed-in account; top search goes to the Alert Inbox. The mock source
files (views/*View.vue legacy, services/*, mock/*) are no longer imported (absent from the build) but still on disk —
apps/src is not in git, so they were not deleted. DB still holds the seed demo alert/incident (wazuh-demo-0001) and
the E2E mock-attack incidents; removing them needs an explicit decision (DELETE is gated).

**Dashboard verification (2026-09-24, real dataset, frontend-only change):** added Approvals and Verification &
escalation cards (existing summary fields only). Browser values = PostgreSQL: open 55 (54 investigating + 1
escalated), alerts 106 / 4 in 24 h, pending approvals 0, plans 94 completed / 5 failed / 4 rejected, re-hunts 48/46
(51%), escalated 1, SLA 44 breached / 7 at risk / 4 on track. Gaps found (backend untouched, awaiting decision):
approval outcomes not in API (DB: MANAGER approved 4 / rejected 4); escalation events not in API (audit: 7 max-round,
5 policy/spread) and 6 incidents escalated before the `escalated` status existed still show `investigating`
(backfill = DB UPDATE, needs approval); spread count not in API (5); summary takes ~7.8 s (per-incident Policy SLA
evaluation). Dev-server note: frontend launch config now targets `--workspace=@soar-platform/frontend` (the old
`--workspace=apps` also matched apps/backend); do not run `vite build` into apps/dist while the dev server runs.

**UI flow items completed (2026-09-24, frontend-only):** (1) Report builder `/reports` (+ Dashboard "Export report"):
system template filled from `/api/v1/dashboard/summary`, every section/title editable, export = standalone HTML
download or Print → Save as PDF; draft kept per browser. It is an "as of" snapshot (API has no period filter — the
totals are to date; 24 h / 7-day figures are labelled). (2) In-app "alert became an incident" notifications (bell):
polls the Alert Inbox every 30 s, diffs alert→incident links against the last seen state (per browser), toasts +
lists "Now in / Moved to INC-…" (covers Policy auto-incident, Create Incident, Set Group). Verified live: ingesting
test alert 1790184557.84 (203.0.113.62) → bell "Now in INC-66EAA3EA". Still open: AI analysis re-run (needs an
additive backend endpoint to re-dispatch the LangGraph pipeline for an incident — awaiting decision); dashboard API
gaps 1–4 (§ above); report period filtering (API).

**Real Wazuh re-hunt — VIGIX IOC type normalization (2026-09-24):** provider-switch acceptance found the adapter
only accepted the categories ip/domain/url/hash, but VIGIX stores IOC types as IPV4/IPV6/MD5/SHA1/SHA256/DOMAIN/URL,
so a real workflow re-hunt failed INSUFFICIENT_CRITERIA. Fix (WazuhRehuntAdapter.ts only): `iocSearchCategory()`
maps IPV4/IPV6→ip, MD5/SHA1/SHA256→hash, DOMAIN→domain, URL→url (case-insensitive; lowercase categories still
accepted); unsupported types (USERNAME, FILE_PATH, …) are skipped, and if nothing searchable remains the re-hunt is
INSUFFICIENT_CRITERIA (never NO_MATCH). Port, MockRehuntAdapter, workflow, time bounds, timestamp handling, error
semantics unchanged. Tests: WazuhRehuntAdapter 63/63 (new: each VIGIX type, mixed types with ioc_N naming by original
index, unsupported-only, empty list, IPV4 time bounds, IPV4 incomplete shards rejected); re-hunt group 117/117; full
backend 315 pass (only failing suite = empty Approval.integration.test.ts, pre-existing); tsc clean.
Real workflow NO_MATCH (REHUNT_PROVIDER=wazuh, .env unchanged): incident c6e1817c (IOCs IPV4:10.10.10.50,
IPV4:10.0.5.44, USERNAME:root), completed plan 9b2260d5 → RunRehuntVerificationUseCase → WazuhRehuntAdapter →
wazuh-alerts-4.x-* window 2026-09-23T19:08:56.821Z..19:25:16.811Z, both IPV4 IOCs queried as ip terms, USERNAME
skipped → 0 events → verification RESOLVED (source WAZUH_INDEXER) → incident resolved. Real MATCH workflow still
pending: needs a new Wazuh event containing a VIGIX IOC generated after a plan's completion.

**Real MATCH preparation — findings (2026-09-24, read-only inspection):** only agent 000 (wazuh.manager) is
registered; no endpoint agent. Index holds 190 docs: 185 SCA + 4 monitord from the manager, plus ONE hand-indexed
doc `_id mock-not-resolved-001` (10.10.10.50, agent "001 WKS-DEMO-02" not registered, @timestamp only) — the earlier
"live MATCH 10.10.10.50" read the pipeline against that inserted doc, so no genuine Wazuh event with an IP IOC exists
yet. Manager pipeline healthy (analysisd/logcollector running, filebeat→indexer OK, log_alert_level 3, data.srcip
keyword-searchable) but wazuh-integratord is not running on this manager (single-node wazuh-docker, not
infra/docker), so alerts do not auto-forward to VIGIX. Proposed genuine source: controlled lab Ubuntu container with
sshd + wazuh-agent 4.14.7 enrolled to this manager; failed SSH logins from a lab-only attacker container at a fixed
private IP → sshd rules 5760/5763 with data.srcip = that IP. Awaiting approval before any setup.

**Real MATCH lab setup (2026-09-24, approved, isolated, reversible):** docker network `vigix-lab` 172.31.250.0/24
(--internal: no gateway/internet/host), label vigix-lab=1. `vigix-lab-ubuntu` (ubuntu:22.04; lab 172.31.250.10 +
single-node_default 172.19.0.5 to reach wazuh.manager:1514/1515): openssh-server, rsyslog → /var/log/auth.log,
wazuh-agent 4.14.7-1 from packages.wazuh.com (apt-mark hold), enrolled via authd (use_password=no, no secret) as agent
001 `vigix-lab-ubuntu`, Active; extra <localfile> /var/log/auth.log (syslog). Target account `labuser` has a random,
never-displayed password. `vigix-lab-attacker` (ubuntu:22.04, openssh-client/sshpass/netcat) on vigix-lab only,
172.31.250.50: reaches 172.31.250.10:22 only (manager, Wazuh net, host, internet all blocked). Pipeline probe
2026-09-23T19:41:38–54Z (ONE wrong-password login + one nc port check): manager + indexer
wazuh-alerts-4.x-2026.09.23 hold rules 5762/5503/5760, agent 001 vigix-lab-ubuntu, data.srcip 172.31.250.50,
location /var/log/auth.log, timestamp == @timestamp. These precede any plan completion. Brute force (5763) NOT yet
generated. Services were started by `docker exec` (no systemd): after a container restart rerun
`rsyslogd; mkdir -p /run/sshd; /usr/sbin/sshd; /var/ossec/bin/wazuh-control start` in vigix-lab-ubuntu.
Teardown: `docker rm -f vigix-lab-attacker vigix-lab-ubuntu; docker network rm vigix-lab`, then remove agent 001 on
the manager (`/var/ossec/bin/manage_agents -r 001`). No VIGIX code/.env/DB/Wazuh-manager config changed.

**Real MATCH step 1 — first genuine Wazuh alert into VIGIX (2026-09-24):** alert 1790193059.842603 (rule 5763, agent
001 vigix-lab-ubuntu, srcip 172.31.250.50) extracted as the single matching line from the manager's alerts.json and
sent ONCE with an unmodified copy of infra/wazuh-integration/custom-vigix.py (signed, SIEM_WEBHOOK_SECRET not shown)
to http://localhost:4000/api/v1/webhooks/siem/wazuh. Script result: exit 4, client read timeout (10 s) — no HTTP
status received; the backend processed it anyway (alert row 19:55:37.192 → incident_alerts link 19:55:52.998, ≈15.8 s
synchronous). Not resent. Records: alert 02d975af-9883-48b1-bf77-69438b841a68 (rule 5763, received); incident
298f2678-3f7d-4913-96f4-cf2045ae0ecb (investigating, medium, cycle 1, auto-opened by AI pipeline); investigation
bd2cee1b… #1 ACTIVE; evidence d13da1b0… WAZUH_ALERT; agent_execution SUCCESS (decision=auto_response, risk 25.0);
IOCs IPV4 172.31.250.50 + USERNAME labuser (ALERT, linked to evidence) and — from the AI "aggregated" source —
DOMAIN vigix-lab-ubuntu (agent name) + IPV4 172.19.0.5 (agent.ip), not linked to evidence. No recommendation /
response plan / verification. Findings (not fixed): (1) webhook synchronous latency > the integration's 10 s timeout;
(2) aggregated IOC extraction treats agent.name/agent.ip as indicators (contradicts alertIocs.ts "the agent is not an
indicator"); both would also be re-hunted as DOMAIN/IPV4.

**Real MATCH step 2 — recommendation + response plan (2026-09-24):** incident 298f2678 (cycle 1). Existing AI analysis:
PARTIAL_SUCCESS (T1110 Brute Force, ML risk 25/100, decision responsible_role SOC, no approval; validation agent
error "'CheckResult' object has no attribute 'name'" — orchestrator defect, not fixed). Temporary script (deleted) with
container.ts wiring, real LLM + real PolicyEvaluator, notifications no-op (1 suppressed, 0 deliveries):
recommendation fd5886f8-0065-4b2b-80bd-6ada1de20f97 #1 VALIDATED (playbook PB-SSH-BRUTEFORCE), 1 step a8c76cb6…
"Block Source IP — 172.31.250.50" (target 172.31.250.50). Response plan 738060ff-182b-47ad-a6bc-1938265646ba:
READY_FOR_EXECUTION, approvalStatus NOT_REQUIRED, assignedRole SOC; Policy matched RULE-A02 (Medium Severity
Assignment → SOC), POL-005 (Medium → P2, SOC), RULE-R03 (risk 25–50 → P2, SOC); assetCriticality HIGH; no approval
record. Not started/completed, no re-hunt. Note: Start/Complete API + Ticket UI actions require IR_TEAM (or admin)
although Policy's responsible role is SOC — existing behavior, not changed.

**IR Ticket Detail UI (2026-09-24, frontend only, real API):** new route `/tickets/:id` (views/tickets/TicketDetailView.vue):
header (INC, title, lifecycle badge + backend status, severity, risk, Policy responsible role, View incident), lifecycle
stepper (Approval if Policy requires → Ready → In progress → Awaiting re-hunt → verdict), Response action + instruction
checklist with progress (browser-local working state; changes no backend status), execution notes (draft local; persisted
only inside executionResult on completion — backend has no notes endpoint), Start (POST /api/responses/:id/start),
Mark eradicated with confirmation (POST …/complete, executionResult {outcome, note, by, checklist}), Completed panel
with backend completedAt, Run re-hunt (POST /api/incidents/:id/verifications/rehunt) + MATCH / NO MATCH / RE-HUNT ERROR
panels (events, matched IOC, source, index, window, hosts from the verification's afterState), incident summary
(IOCs/indicators/MITRE/risk/SLA/source alert), plan card (IDs, approval NOT REQUIRED vs approval info, created/started/
completed). Stage is derived only from plan status + verification + incident status (utils/ticket.ts), shared with the
list. List: stage lanes, risk score, updated time, Open ticket link. Incident Detail Response tab + Hand-off panel: View
response ticket link. Role gate = session.canExecuteResponse (IR_TEAM/admin, mirrors backend requireRole) with "You are
not authorized to execute this response." No backend change. Checks: vite build OK; frontend has no vue-tsc/eslint/
vitest (tsc clean for changed .ts files); browser: real ticket 738060ff renders (12 API calls 200), SOC session sees
disabled Start + message, mobile 375 px no overflow, list 105 tickets/234 calls/0 failures. Notes: Mark eradicated via
the live backend emits RESPONSE_COMPLETED → real email to SOC_EMAIL (SMTP configured). Recommendation #2 39277037 was
generated 20:08:19Z (not by the acceptance script), superseding #1 of ticket 738060ff; the ticket still executes.

**Sidebar Knowledge + Settings (2026-09-24, frontend only):** sidebar order Dashboard, Alert Inbox, Incidents, IR Tickets,
Reports (kept), Knowledge (LibraryBig), Settings (Settings icon); routes /knowledge, /settings (plural, project
convention; /setting → 404, no duplicate). KnowledgeView (views/knowledge): read-only libraries from existing endpoints
— playbooks 6 (/api/playbooks), policies 21 (/api/policies), runbooks 10 (/api/runbooks), MITRE 13
(/api/v1/mitre/techniques); Threat Intelligence has no library endpoint → "—" + empty state; search is client-side.
SettingsView (views/settings, reuses the legacy settings left-nav pattern): General (backend /api/v1/health, tenant +
session expiry from JWT claims — token never shown, browser tz/locale), Security (auth method, role, permission table
mirroring backend gates), Integrations (Wazuh = rehunt-health, notification = no status endpoint, AI orchestrator =
dashboard summary integrations). No secrets displayed. Legacy mock views/KnowledgeBaseView.vue + views/SettingsView.vue
untouched and still unimported. Verified: all routes highlight the right menu (incl. /tickets/:id, ?section=),
sidebar no overflow at 1280 / 768 (expanded + collapsed) / 375. Backend dev process died silently once during testing
(ts-node-dev wrapper still "running", port refused); restarted via preview — no backend code touched.
Open request (awaiting decision): edit per-role notification emails in Settings — role emails are read from .env
(SOC_EMAIL / IR_TEAM_EMAIL / MANAGER_EMAIL) once at startup (container.ts roleEmail); no DB column exists for them.

**Settings: per-role notification email (2026-09-24, approved: new DB table, admin-only):** pg_dump first
(backups/soar_platform_before_notification_recipients_20260923T204952Z.dump — backups/ is NOT git-ignored, do not
commit). Hand-written additive migration 20260924090000_notification_recipients (table notification_recipients:
tenant_id+role unique, email, updated_by, timestamps; FK tenants) — verified equal to a read-only
`migrate diff --from-schema-datasource` (no shadow DB), applied with `migrate deploy`; data intact. Backend:
RoleEmailDirectory (Settings value per tenant → else .env SOC_EMAIL/IR_TEAM_EMAIL/MANAGER_EMAIL; read failure falls back
to .env), MultiChannelNotificationDispatcher + IrHandoffController resolve at send time (no restart needed);
GET /api/v1/settings/notification-recipients (any signed-in role; non-admin gets masked addresses, .env value never
revealed separately), PUT /api/v1/settings/notification-recipients/:role {email|null} (requireRole() = admin only;
zod email, lower-cased; null/blank clears → .env default; audited NOTIFICATION_RECIPIENT_UPDATED/CLEARED with
previous/new). Tests: NotificationRecipients.test.ts 10/10; full backend 325 pass (only empty Approval suite fails);
tsc clean. Frontend: Settings → Integrations → Notification "Email recipient per role" (admin: input + Save + Use server
default; others read-only masked); Security permission table row added. Live: SOC GET 200 masked, SOC PUT 403, no-auth
401; table still 0 rows. Admin edit UI not exercised in the browser (no admin sign-in by the assistant).

**Send article / response guide to IR by email (2026-09-24):** reuses the existing notification architecture — one
IrEmailService (application/notification/services): recipient = RoleEmailDirectory IR_TEAM (admin Settings value, else
IR_TEAM_EMAIL; never from the client), delivery via the existing EmailNotificationAdapter (SMTP password redaction),
row in notification_deliveries (eventType ARTICLE_SENT_TO_IR / RESPONSE_GUIDE_SENT_TO_IR), audit event for EVERY
attempt (actor, entity/id, recipientRole IR_TEAM, deliveryStatus SENT/FAILED/NOT_SENT, error code, subject, sentAt —
never SMTP text or the full address; caller gets a masked recipient). Articles = playbooks/runbooks
(GetKnowledgeArticleUseCase); response guide (GetResponseGuideUseCase) = incident + severity/priority + risk + MITRE +
current-cycle IOCs + current VALIDATED recommendation steps (action, target, reason, instructions, verification) +
source runbook (sourceRunbookId) + playbook (PlaybookSnapshot via PrismaPlaybookSnapshotReader). Endpoints (router
mounted at /api/v1, paths new): GET /knowledge/articles/:id and GET /incidents/:id/response-guide (preview = exact
email; any signed-in role); POST /knowledge/articles/:id/send-to-ir and POST /incidents/:id/send-response-guide (body
{subject?} strict; requireRole(...IR_HANDOFF_SENDER_ROLES) — shared constant now also used by the existing
/api/notifications/ir-handoff; SOC, admin passes). Responses: 200 SENT; 400 IR_TEAM_EMAIL_NOT_CONFIGURED /
CHANNEL_NOT_CONFIGURED; 502 DELIVERY_FAILED; 404 not found. Subject CR/LF stripped. Frontend: components/ir/
SendToIrModal (recipient "IR Team", subject, server preview, Send/Cancel, sent panel with backend sentAt + status),
ResponseGuidePanel (full guide in Incident → Hand off to IR tab; compact send block on Ticket detail), Knowledge
playbook/runbook rows "Send to IR" (session.canSendToIr mirrors the backend gate); utils/irEmail.ts send-state logic.
Tests: backend IrEmail.test.ts 13/13 (article, guide, unauthorized via real route stack, missing IR email, channel
missing, provider failure, audit, no secret/address leakage) — fake adapters only; full backend 338 pass (only the
empty Approval suite fails); tsc clean. Frontend: `npm test` (node --test, native TS, no new deps) 4/4; vite build OK;
tsconfig.app excludes *.test.ts. Live (no email sent): previews 200, unknown article 404, client "recipient" field 400;
0 deliveries / 0 audits of the new types.

**Notification recipients — editors changed (2026-09-24, user request):** SOC and IR_TEAM (plus admin) may edit the
per-role notification emails; MANAGER is read-only. Backend: NOTIFICATION_RECIPIENT_EDITOR_ROLES = ["SOC","IR_TEAM"]
in settings.routes.ts (PUT requireRole(...)); canEditNotificationRecipients() decides full vs masked addresses in GET.
Frontend: session.canEditRecipients mirrors it (Settings editor + permission table). Every change stays audited
(NOTIFICATION_RECIPIENT_UPDATED/CLEARED, actor, previous/new). Tests: NotificationRecipients.test.ts 12/12 (route gate:
SOC/IR_TEAM/admin 200, MANAGER 403, anonymous 401); full backend 340 pass (only the empty Approval suite fails); tsc,
vite build, frontend tests OK. Live (SOC): GET unmasked, 3 editable rows; nothing saved.

**Send Response Guide to IR — ticket flow, recipient preview, duplicate protection (2026-09-24, not committed):**
IrEmailService gains previewRecipient() (masked IR_TEAM address + source settings/server/none + email channel
configured) and idempotent send: idempotencyKey (uuid, one per confirmation dialog) = delivery eventId; key claimed
synchronously in an in-process in-flight set (race found by test and fixed), a key already SENT returns that result
(duplicate:true, nothing re-sent, no new audit), PENDING/in-flight → 409 DUPLICATE_IN_PROGRESS, FAILED may be
retried. Guide accepts responseId (GET ?responseId=, POST body): must belong to the incident (else 404
RESPONSE_NOT_FOUND); guide then uses the ticket's own recommendation + step (even if superseded) and the email adds
"Response ticket" + "VIGIX response ticket: /tickets/<id>" alongside the incident link. Previews return
{email, recipient}. Frontend: SendToIrModal shows "IR Team <masked> (source)", blocks Send with a message when no IR
email / no channel, sends one idempotency key per dialog, success panel (sentAt, status, recipient) with only Close;
Ticket detail passes its responseId. Tests: IrEmail.test.ts 21/21 (+ticket scoping, invalid/foreign ticket, DB
recipient over .env, .env fallback, missing recipient, next-send uses new Settings value, duplicate SENT, concurrent
double click, retry after failure); relevant suites 33/33; full backend 348 pass (only empty Approval suite fails);
tsc clean; frontend `npm test` 7/7; vite build OK. Live (no email by the assistant): ticket 738060ff preview → rec #1
step, ticket ref, recipient s***@gmail.com (settings); foreign ticket 404; invalid key 400. Observed user activity:
SOC account set IR_TEAM recipient at 21:31:04Z and sent the INC-298F2678 response guide at 21:37:31Z → SENT
21:37:35Z, delivery + RESPONSE_GUIDE_SENT_TO_IR audit recorded (real end-to-end success).

**ATK-01 alert (2026-09-24, user generated the lab activity; assistant did read-only verify + single ingest):** Wazuh
5763 (level 10, T1110) alert 1790201416.855231, 2026-09-23T22:10:16.529Z, agent 001 vigix-lab-ubuntu, srcip
172.31.250.50, dstuser labuser, index wazuh-alerts-4.x-2026.09.23, doc 1fhR0KABpdZJhjcc0RNE (burst 22:09:46–22:10:24Z:
9×5760, 9×5503, 1×5551, 1×5763). Sent once via unmodified custom-vigix.py → backend HTTP 201 in ~7 s, but the script
only treats 202 as success, so it logged "rejected"/exit 4 (script↔webhook status mismatch — not fixed). Not resent.
VIGIX: alert 80cd512f-f297-4ca4-9b28-0b0cf98b831f (1 copy), incident ec795586-df7e-4f05-ba7c-8e4f547a06a4
(investigating, medium, cycle 1), investigation 7a87d3c1… ACTIVE, evidence WAZUH_ALERT, IOCs IPV4 172.31.250.50 +
USERNAME labuser (ALERT) + aggregated DOMAIN vigix-lab-ubuntu / IPV4 172.19.0.5 (known issue), AI pipeline SUCCESS
(runs automatically on ingest). No recommendation/plan/verification; notification_deliveries unchanged (1).

**ATK-02 alert (2026-09-24, user generated the activity; assistant verified + ingested once):** Wazuh 5763 (level 10)
alert 1790201730.867859, 2026-09-23T22:15:30.498Z, agent 001 vigix-lab-ubuntu, srcip 172.31.250.50 (port 42464, user
labuser), index wazuh-alerts-4.x-2026.09.23, doc 7PhW0KABpdZJhjccmxPT; burst 22:15:00–22:15:38Z = 20 events (9×5760,
9×5503, 1×5551, 1×5763). custom-vigix.py → HTTP 201 logged as "rejected"/exit 4 (known 201 vs 202 issue), not resent.
VIGIX alert ee8c4972-9461-48ff-878a-090f04156098 (1 copy), incident 5eacdd32-7496-4365-a31f-0198d8227cde (investigating,
cycle 1), investigation c29802d2… ACTIVE; AI pipeline SUCCESS; no rec/plan/verification; deliveries unchanged.
Note: VIGIX opened a separate incident (not grouped with ATK-01 ec795586), same srcip/rule/host 5 min apart.

**Attack dataset — scenario labels + Alert Inbox search/filter (2026-09-24, not committed):** attack activity is
generated by the user only (assistant does read-only verification + single ingest). New VIGIX-layer metadata: table
alert_scenario_tags (migration 20260924130000_alert_scenario_tags, hand-written/additive, verified by read-only
migrate diff, pg_dump backups/soar_platform_before_alert_scenario_tags_20260924T062424Z.dump; 111 alerts / 110
incidents intact). Backend: domain/alert/attackScenarios.ts (catalog ATK-01..10: attackType, caseName, description),
PrismaAlertScenarioRepository, SetAlertScenarioUseCase (audited ALERT_SCENARIO_TAGGED/CLEARED, raw payload never
changed), routes GET /api/v1/alerts/scenarios + PUT /api/v1/alerts/:id/scenario (requireRole SOC; mounted before the
alert router); inbox items + alert view carry `scenario`; inbox filters attackType / scenario (id or case name) /
agent; search also matches scenario id/type/case. Frontend: Alert Inbox search "Search attack or scenario...", Attack
type / Case (from backend catalog) / Agent filters, scenario badge + rule id per row; Alert Detail "Test scenario"
label with SOC selector. Tests: AlertScenario.test.ts 7/7 (+ inbox suite 14/14 together); full backend 354 pass (only
empty Approval suite fails); frontend build + tests 7/7. Browser check blocked: stored SOC session expired
2026-09-23T22:58Z (no sign-in by the assistant); observed that an expired session shows "Could not load the dashboard"
instead of returning to sign-in. No alert labelled yet.
Current-config support (read-only): SSH supported (5760/5763, 5710/5712, 5503/5551). SQLi: no web server/access log
on the endpoint → UNSUPPORTED. Sudo: rules 5401/5402/5403/5405 exist but sudo is not installed → UNSUPPORTED as-is.
Cron: cron daemon not running; FIM only /etc,/usr/bin,/usr/sbin,/bin,/sbin,/boot every 43200 s (no realtime);
/var/spool/cron not monitored → no timely alert (a /etc/cron.d change would only surface as FIM 554/550 at the next
12 h scan) → UNSUPPORTED for this test. Download/execute: no auditd/command monitoring, /tmp not in FIM → UNSUPPORTED.
Existing ingested alerts: ATK-01 fits (80cd512f, single account labuser); the earlier "ATK-02" alert ee8c4972 is also
single-account (labuser) so it does NOT match the new ATK-02 definition (multiple accounts).

**ATK-02 (Brute Force + Multiple Accounts) — 2026-09-24:** 1st multi-account burst 06:54:06–06:54:24Z (13 events,
users labuser/testuser/admin/root/guest, 1 attempt each) → no aggregate rule (6×5710, 5×5503, 2×5760 < 8) → nothing
ingested. 2nd burst 07:04:08–07:04:34Z: 27 events (17×5710 over admin/guest/testuser 6 each, 8×5503, 1×5551, 1×5712).
Genuine 5712 "sshd: brute force … Non existent user" level 10, alert 1790233459.12882, 07:04:19.626Z, agent 001,
srcip 172.31.250.50, srcuser testuser, previous_output covers admin/guest/testuser, index wazuh-alerts-4.x-2026.09.24,
doc 2vg60qABpdZJhjccxBQR. Ingested once via custom-vigix.py → HTTP 201 (script "rejected"/exit 4, not resent):
VIGIX alert d5ca329c-c6a2-43aa-adf5-a6ca333110fe (1 copy) BUT pipelineDispatched=false, incidentId=null — AI
orchestrator (:8000) was not running (dev servers had been stopped by the app; only backend+frontend restarted), so NO
incident was created. Not labelled: SOC browser session expired 2026-09-23T22:58Z. Pending user: sign in, Create
Incident from the alert (existing SOC action) or decide otherwise, then label ATK-02 on Alert Detail.

**TASK 11 — Real Run / Re-run AI Analysis (2026-09-24, not committed):** reuses the existing pipeline
(orchestrator POST /pipeline/run) — no second AI pipeline. Orchestrator (additive): RunPipelineRequest.analysis_only
(default false → ingestion unchanged); when true the run persists the analysis and returns before the decision
callback (n8n) and notification_orchestrator. persist_agent_results now inserts threat_intel_iocs / mitre_mappings
only if the incident doesn't already have that (type,value) / technique (no-op on a first run) → re-runs don't
duplicate IOCs/MITRE (risk_scores/decisions/agent_executions/agent_results remain per-run history).
Backend: IAiAnalysisRunnerPort + LangGraphOrchestratorAdapter.runAnalysis (same /pipeline/run, analysis_only, 180 s
timeout; network/timeout → AI_UNAVAILABLE, non-2xx → AI_FAILED); RunIncidentAiAnalysisUseCase (incident exists; has
alertId; that alert is the primary alert of exactly this incident — else ALERT_OWNED_BY_OTHER_INCIDENT, so the
pipeline can never open/attach to another incident; in-process per-incident lock claimed before any await + DB check
for a RUNNING agent_execution < 15 min → ANALYSIS_IN_PROGRESS; after success investigations.syncIncident (same as
ingestion) and returns fresh analysis; pipeline answering with another incident id → AI_FAILED; audit AI_ANALYSIS_RUN
{trigger manual, outcome SUCCESS/PARTIAL_SUCCESS/FAILED, rerun, graphRunId, riskScore, error} for every attempt);
PrismaAiAnalysisRunGuard; route POST /api/v1/incidents/:incidentId/ai-analysis/run (requireRole SOC, IR_TEAM; 404 /
422 / 409 / 503 / 502). Never changes incident status, never creates alerts/incidents, never executes/notifies.
Frontend: Incident Detail → AI Analysis tab: "Run AI Analysis" / "Re-run AI Analysis" / "Analyzing..." (session.
canRunAiAnalysis) replacing the misleading "Retry / refresh"; separate "Reload" (read only); running/success/error
banners; success reloads the whole incident. utils/aiAnalysis.ts (+ test). Tests: backend RunIncidentAiAnalysis.test.ts
16/16, full backend 370 pass (only empty Approval suite fails), tsc clean; orchestrator tests/api 25/25 (+3
analysis_only); frontend npm test 12/12, vite build OK. Ops note: uvicorn --reload stalled after the edit (old worker
kept serving without analysis_only) → orchestrator restarted via preview; live schema confirmed. No AI run executed
by the assistant (no SOC session; would also call the real LLM).

**First-time "Generate Recommendation" UI (2026-09-24, frontend only, not committed):** Incident Detail →
Recommendation tab: when no recommendation exists, a "Generate Recommendation" button (SOC / IR_TEAM / admin via
utils/recommendation.ts canGenerateRecommendation, mirroring requireRole("SOC","IR_TEAM"); MANAGER sees a note) calls
the EXISTING POST /api/recommendations/generate (workflowApi.regenerate → GenerateRecommendationUseCase, backend
validation unchanged). Generate and Regenerate share one handler/state (runGenerate): "Generating..." + spinner,
disabled while running, clicks while running ignored (no second call), disabled for resolved/escalated incidents
(same rule as Regenerate); success → toast + full incident reload (recommendation, steps, Regenerate button); failure
→ backend error inline + toast, incident unchanged, retry allowed. Files: utils/recommendation.ts (+ .test.ts),
views/incidents/IncidentDetailView.vue. Tests: frontend npm test 17/17 (+5), vite build OK, backend
RecommendationGeneration 60/60 (backend unchanged). No real generation run by the assistant.

**Re-hunt IOC fix — REHUNT_QUERY_FAILED on ticket 738060ff (2026-09-24, not committed):** cause (read-only): incident
298f2678 carried AI-aggregated IOCs DOMAIN:vigix-lab-ubuntu (Wazuh predecoder.hostname/agent.name) and
IPV4:172.19.0.5 (agent.ip); no domain field exists in wazuh-alerts-4.x-*, so the adapter failed the whole re-hunt
(audit REHUNT_FAILED 09:29:16Z; no verification recorded). Fix: (1) RunRehuntVerification excludes IOC values equal to
the alert's own agent.name / agent.ip (case-insensitive, from rawPayload, nothing hard-coded, IOC rows untouched) and
stores them as excludedIocs (beforeState.criteria + afterState). (2) WazuhRehuntAdapter.prepareQuery: a category
whose configured fields are ALL absent from _field_caps is skipped (WeakMap per query → rehunt() returns
skippedIocTypes / searchedIocs / skippedIocs with reason "No searchable <TYPE> field in current Wazuh index"); a field
that exists but is non keyword/ip/constant_keyword, unsearchable or has non_searchable_indices → QUERY_FAILED; every
category skipped → INSUFFICIENT_CRITERIA; timeout/shard/partial rules unchanged. Evidence lists kept in
verification.afterState (JSON, no schema change); Ticket Detail shows Searched / Skipped (not searched) / Excluded.
(3) Orchestrator ioc_extractor: endpoint identity (agent.name, agent.ip, manager.name, predecoder.hostname) is metadata —
nested agent/manager/predecoder/decoder sections are not read as structured IOC fields and any extracted value equal to
an identity value is dropped (also regex hits from flattened text). Tests: backend 380 pass (+ adapter D–I, use case
A–C; old "missing mapping" test now expects INSUFFICIENT_CRITERIA for no-field, QUERY_FAILED for wrong type), tsc
clean; orchestrator 133 pass (+5 extractor, fixtures' expected IOCs still recovered); frontend 29/29, build OK.
Orchestrator restarted (reload stalls); backend auto-restarted. No re-hunt / verification run; existing IOC records
unchanged (still 4 on 298f2678 — excluded only at hunt time). New incidents no longer get agent-identity IOCs.

**Phase 2 / P1 — async ingest + DB-backed AI job queue (2026-09-24, verified):**
Queue lives on `agent_executions` (no Redis): new columns alert_id, trigger (INGEST/MANUAL/RETRY), attempt, queued_at,
next_attempt_at + index (status,next_attempt_at); unique index verifications(response_id). Migration
20260924170000_ai_job_queue_and_verification_unique (additive, applied with migrate deploy; pg_dump first:
backups/soar_platform_before_ai_job_queue_20260924T135119Z.dump). Alerts unique (source, external id) index NOT added:
13 duplicate groups exist (mock replays, tenant ...0001) — awaiting user decision; idempotency is enforced in code.
Ingest (webhook + AlertController) → 202: idempotent alert → backend opens the incident (createWithAlerts, actor
vigix-ingest, audit INCIDENT_CREATED origin SIEM_INGEST) → job QUEUED. Backend worker (AiAnalysisWorker, in-process,
single-flight, SKIP LOCKED claim) → RUNNING → existing runAnalysis with execution_id → orchestrator uses the row's
incident (never opens one when execution_id is given) → SUCCESS/PARTIAL_SUCCESS/FAILED → investigation sync → audit.
Retry: max 3 attempts, backoff 30 s·2^(n-1), each retry a new row; stale RUNNING (15 min) → FAILED STALE_RUNNING + retry;
DEFERRED while another run holds the incident; SUPERSEDED retry; INCIDENT_MISMATCH never retried.
Orchestrator callback now only audits AI_DECISION_RECORDED — never triggers n8n (auto_response disabled).
Tests: backend 398/398 (only pre-existing empty Approval.integration suite fails), orchestrator 135/135, frontend 29/29,
tsc + vue-tsc + vite build clean. E2E: genuine Wazuh 5551 alert 1790233470.19580 sent ONCE via unmodified
custom-vigix.py → 202 in 1.27 s (exit 0) → incident 0cb9041c… (open) + job 330e73d1… QUEUED → claimed 0.5 s later →
SUCCESS 108 s (risk 21 low, T1110, IOC 172.31.250.50, evidence, timeline, 10 agent_results). Approvals/notifications/
response plans/recommendations unchanged; no orchestrator callback. Not resent (idempotency covered by unit tests).
Gaps: alerts unique index (user decision), scripts/e2e-mock-attacks.ts still uses the old ingest contract, manual Run AI
still direct (not via queue, guard counts QUEUED), no job-status API/UI yet, ATK-02 alert d5ca329c has no incident.

**Security Role & Risk Policy revision (2026-09-24, verified):** Policy stays the only engine (PolicyEvaluator); new
result fields approvalChain (ordered union SOC->IR_TEAM->MANAGER), executorRole (default IR_TEAM), autoCreateIncident
(INTAKE, false wins). Migration 20260924230000_role_risk_policy_approval_chain (additive; pg_dump first:
backups/soar_platform_before_role_risk_policy_20260924T152430Z.dump): approvals.step_order (default 1 — existing 8
approvals = 1-step chains), alerts.triage_disposition/triage_note/triaged_by/triaged_at, and 7 new policy rows (no
existing row edited/deleted): RULE-P07 HIGH sev -> IR, P08 risk 50-74 -> IR, P09 CRITICAL sev -> IR>MANAGER, P10 risk
>=75 -> IR>MANAGER, P11/P12 IR before the MANAGER of P04/P05, RULE-I01 LOW alert -> SOC triage (no incident/AI).
Approval chain: step 1 pending, later steps waiting; STEP_NOT_ACTIVE (Manager can't approve before IR, not even admin);
approve -> next step activated (APPROVAL_STEP_ACTIVATED) / last -> READY_FOR_EXECUTION; reject -> REJECTED + rest
cancelled; more evidence -> ticket MORE_EVIDENCE_REQUESTED + incident investigating (same cycle, timeline, audit).
StartResponse requires every step approved. Ticket assignedRole = executor (IR_TEAM); responsibleRole = owner.
Manual PATCH status can't set resolved (RESOLVE_REQUIRES_VERIFICATION); status changes audited. LOW alert triage
POST /api/v1/alerts/:id/triage (SOC) FALSE_POSITIVE/INFORMATIONAL -> closed, MONITOR -> monitoring + SEND/SKIP email
(EMAIL_SENT/EMAIL_SKIPPED via IrEmailService, one per case). POST /incidents/:id/notification-decision (SOC),
/incidents/:id/risk-validation (SOC/IR, audit-only RISK_VALIDATED). Manual Create Incident queues a MANUAL AI job.
New audits: ALERT_ROUTED_TO_TRIAGE, ALERT_TRIAGED, INCIDENT_ASSIGNED (after each AI job), APPROVAL_APPROVED/REJECTED/
MORE_EVIDENCE_REQUESTED, APPROVAL_STEP_ACTIVATED, INCIDENT_RETURNED_TO_INVESTIGATION, INCIDENT_STATUS_CHANGED,
REHUNT_STARTED, INCIDENT_RESOLVED, INCIDENT_ESCALATED, EMAIL_SENT/SKIPPED/SEND_FAILED, RISK_VALIDATED.
Tests: backend 427/427 (only pre-existing empty Approval.integration fails), frontend 32/32 + vue-tsc + build.
Live: policy matrix evaluated against DB rules = as designed; genuine LOW Wazuh 5503 alert 1790233454.10730 sent once
-> 202, alert stored, NO incident/AI job, ALERT_ROUTED_TO_TRIAGE (RULE-I01). No new genuine MEDIUM+ alert available,
so the P1 MEDIUM+ path was not re-run live (unit-tested; intake returns autoCreate=true for MEDIUM/HIGH/CRITICAL live).

**Role workspaces / Incident 360 / Command Center (2026-09-25, not committed, no schema change):**
Backend (additive, read-only unless noted): `application/work` (WorkQueues pure rules + WorkQueries) +
`WorkReadRepository.prisma.ts`; routes `GET /api/v1/work/tickets?queue=my-work|awaiting-my-approval|awaiting-approval|ready|
in-progress|awaiting-rehunt|completed|failed|escalated|all` (My Work = tickets I started + unclaimed READY tickets of my
executor role — backend assignment, never email), `GET /api/v1/work/approvals?scope=mine|all&status=` (mine+pending = only
the ACTIVE step of my role; admin never), `GET /api/v1/work/incidents` (risk, Policy responsible role from
INCIDENT_ASSIGNED, active approval step, response status, AI job), `GET /api/v1/incidents/:id/audit` (audit_logs of the
incident + its alerts/recommendations/tickets/approvals/verifications + timeline, credential keys stripped),
`GET /api/v1/incidents/:id/ai-jobs`. Dashboard summary + aiJobs, triage, approvals by role/status, verificationDetail,
riskDistribution, recommendationReady, kpi (investigation time, time-to-decision, workload, automation success),
systemHealth (Backend, PostgreSQL, AI Orchestrator, AI Worker, Wazuh Indexer, Qdrant, Notification, Wazuh Manager =
UNKNOWN: no API client). Inbox `triage=pending|monitoring|triaged` filter. Behaviour changes: DecideApproval refuses admin
(ADMIN_NOT_APPROVER, 403) and audits every denied attempt (APPROVAL_DECISION_DENIED) — the old test asserting admin may
decide was rewritten to the new rule; manual `POST /api/incidents/:id/verifications` returns 409
RESOLVE_REQUIRES_VERIFICATION when it would yield RESOLVED (RESOLVED only via re-hunt). Email: IrEmailService takes an
optional recipientRole (default IR_TEAM, same delivery/idempotency/audit); NotificationRole + ADMIN (ADMIN_EMAIL);
`GET|POST /api/v1/incidents/:id/context-email` (content by SENDER role: SOC investigation / IR response / Manager approval /
admin notice; recipient role only, address from Settings/.env; EMAIL_SENT / EMAIL_SEND_FAILED audited).
Frontend: role sidebar (utils/workspace.ts), /triage, /approvals, /verification, Incidents presets (?view=critical|
escalated|investigation|recommendation), Response Tickets on backend queues, Incident 360 lifecycle + branches, Policy &
Approval chain, AI jobs, Audit timeline, Email tab, Command Center dashboard. Tests: backend 460 pass (only the empty
Approval.integration suite fails, pre-existing), AI 135, frontend 39 + vue-tsc + build. Live: routes mounted (401
unauthenticated), SQL read models verified against the dev DB; signed-in UI walk-through NOT done (needs a user sign-in).

**Severity is the primary classification — Risk Score retired from decisions (2026-09-25, not committed):** pg_dump
backups/soar_platform_before_severity_primary_20260924T183518Z.dump; migration 20260925010000_severity_primary_retire_risk_score
(additive: risk_scores.score + decisions.risk_threshold_used DROP NOT NULL; RULE-R01..R04, RULE-P08, RULE-P10 set
enabled=false — rows kept for history). Policy input = incident severity (incidents.priority, analyst-validated) via
domain/incident/severity.ts; PolicyEvaluationInput/ConditionFieldName/result have no riskScore/riskLevel; PolicyMatcher never
matches a `riskScore` condition (RETIRED_CONDITION_FIELDS); /api/policies/evaluate still accepts a legacy riskScore but
ignores it; CreatePolicy rejects riskScore conditions; seed RISK_SCORE_RETIRED_CODES disables (never deletes). Live DB:
LOW/MEDIUM -> SOC no approval; HIGH -> IR_TEAM, approval IR_TEAM; CRITICAL -> IR_TEAM, IR_TEAM -> MANAGER; risk 10/50/90
identical. Human Severity Validation: POST /api/v1/incidents/:id/severity-validation {severity, note} (SOC/IR_TEAM) —
confirm/correct, SEVERITY_VALIDATED audit + timeline, re-runs Policy assignment, SEVERITY_LOCKED while a ticket is
PENDING_APPROVAL/IN_PROGRESS; replaces the retired /risk-validation (404). getLatestRiskScore -> getAiSeveritySuggestion
(advisory). AI: ML node outputs only severity_prediction/confidence (no risk_score in state, DB, API, callback; failure
no longer defaults to "low"); decision agent / selector (high_severity signal, catalog updated) / classification / LLM
analyst / validation use severity. Dashboard severityDistribution replaces riskDistribution; UI shows Severity + AI
suggestion + Severity Validation panel (no risk score anywhere). Tests: backend 471 pass (only empty Approval suite fails),
AI 147 pass, frontend 40 pass + vue-tsc + build; lint script absent in all workspaces.

## 45.11 AUTOMATIC ALERT CORRELATION — 2026-10-05 (§45.7 issue 2)

A HIGH / CRITICAL alert that Policy INTAKE would open an incident for first looks for an OPEN incident
(`open` / `investigating`) of the same tenant holding the same activity; if one exists the alert JOINS it instead
of opening a second incident. No schema change, no new table.

* Rules (pure, `domain/alert/alertCorrelation.ts`, facts from the payloads only, no AI):
  SHARED_IOC — same public IP / domain / URL / file hash on any host within 7 days, or the same file / process
  path or private IP on the SAME host within 24 h (values < 7 chars, the agents' own IPs and OS paths such as
  `C:\Windows\…`, `/usr/bin/…` never count; ACTIVE IOCs the incident records itself count too);
  SAME_SOURCE_IP — same public `data.srcip` within 24 h; SAME_HOST_TECHNIQUE / SAME_HOST_RULE — same agent and a
  shared MITRE technique / the same rule within 24 h. Same host alone never correlates. Several matches → most
  shared IOCs, most reasons, newest incident; never merges two existing incidents (that stays Set Group).
* Flow: `IngestAlertFromSiemUseCase` → `PrismaIncidentCorrelationReader.openCandidates` (SQL pre-filter, searches
  Windows paths in their JSON-escaped form) → `absorbIntoIncident` (the Set Group write: `incident_alerts`, alert
  escalated/TRIAGED, timeline `alert_added` "correlated … automatically (reasons: IOCs)") → `syncIncident`
  (WAZUH_ALERT evidence + IOCs in Investigation #1, so recommendations and EVERY re-hunt include them) → audit
  `ALERT_CORRELATED_TO_INCIDENT` {reasons, sharedIocs}. No new AI job. Webhook/API output gains `correlation`.
* Failure-safe: lookup error, or the incident closed meanwhile (MergeBlockedError) → a new incident as before.
  MEDIUM alerts (Alert Inbox) are never auto-correlated; resolved / dismissed / escalated incidents never absorb.
* ATK-04: the C2 alert's process image IS the flagged file (SHARED_IOC, same host) → joins; round 3 (C2-only
  traffic) now MATCHES → NOT_RESOLVED ×3 → escalated (proven on Postgres with MockRehuntAdapter in
  `test/AlertCorrelation.postgres.test.ts`). Fixture cross-check: only ATK-01~02, 04~10, 05~06, 07~08 would
  correlate if open at the same time (same host+rule / same C2 / same attacker IP).
* E2E runner: related alerts must correlate (PASS, no GAP); a primary alert must open its own incident — an open
  incident left by an aborted run in the same tenant now FAILs that check. Not re-run live (needs LLM).
* Not done: two related alerts arriving concurrently can still open two incidents (no lock); a more severe joining
  alert does not raise the incident priority; the AI analysis is not re-run for the joined alert (§45.7 issue 1).
