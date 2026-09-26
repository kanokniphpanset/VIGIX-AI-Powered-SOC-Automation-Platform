# AI-Driven SOAR Automation Platform
### Enterprise Architecture & Project Structure Specification

**Classification:** Production-grade reference architecture, suitable for academic thesis / capstone submission
**Architecture style:** Clean Architecture + Domain-Driven Design (DDD) + Multi-Agent AI Orchestration
**Position:** The AI-Driven SOAR Automation Platform is **not** a SIEM. It is a SOAR layer that consumes alerts from external SIEMs (Wazuh, Splunk, Microsoft Defender, ELK) via REST/Webhook, enriches them with a multi-agent AI pipeline, and drives automated/human-approved response through n8n.

---

## 0. System Context (C4 Level 1)

```
 ┌────────────┐   REST/Webhook   ┌──────────────────────────────────────────────────┐
 │  Wazuh     │ ───────────────▶ │                                                    │
 │  Splunk    │                  │        AI-DRIVEN SOAR AUTOMATION PLATFORM          │
 │  Defender  │                  │                                                    │
 │  ELK       │ ───────────────▶ │  Backend API ─▶ AI Orchestrator ─▶ n8n             │
 └────────────┘                  │       │                              │            │
                                  │       ▼                              ▼            │
                                  │   PostgreSQL   Qdrant   XGBoost   Teams/           │
                                  │                                  Email/            │
                                  │                                  Ticketing         │
                                  └──────────────────────────────────────────────────┘
                                                     ▲
                                              Analyst Dashboard
                                              (Vue 3 SPA)
```

Three cooperating runtime services form the platform:

| Service | Language/Framework | Responsibility |
|---|---|---|
| **soar-backend** | Node.js + Express + TypeScript + **Prisma ORM** | Clean Architecture core: alert ingestion, domain logic, persistence (PostgreSQL via Prisma), API, auth, orchestration trigger |
| **soar-ai-orchestrator** | Python + LangGraph + FastAPI | Multi-agent AI pipeline (9 agents), state graph, memory, RAG, LLM, ML |
| **soar-frontend** | Vue 3 + Vite + TypeScript | Analyst/SOC console, executive dashboards, approval workflows |
| **n8n** (external, self-hosted) | Workflow engine | Playbook execution, notifications, ticketing, third-party integrations |

They communicate over REST/gRPC + webhooks and are independently deployable and independently scalable — a prerequisite for the "easy to replace LLM / vector DB / TI platform" requirement.

---

## 1. Complete Project Folder Structure

The AI-Driven SOAR Automation Platform is organized as a **polyglot monorepo** (Turborepo/Nx-style for JS/TS packages, Poetry/uv workspace for Python), so shared contracts (OpenAPI schemas, event schemas) stay versioned together while each runtime deploys independently.

```
soar-platform/
├── apps/
│   ├── backend/                          # Node.js + Express + TS — Clean Architecture / DDD
│   │   ├── src/
│   │   │   ├── domain/
│   │   │   ├── application/
│   │   │   ├── infrastructure/
│   │   │   ├── presentation/
│   │   │   ├── shared/
│   │   │   └── main.ts
│   │   ├── prisma/                        # schema.prisma + migrations/ (Prisma CLI convention)
│   │   ├── test/
│   │   ├── Dockerfile
│   │   ├── package.json
│   │   └── tsconfig.json
│   │
│   ├── ai-orchestrator/                  # Python + LangGraph — Multi-Agent AI Engine
│   │   ├── src/
│   │   │   ├── agents/
│   │   │   ├── graph/
│   │   │   ├── llm/
│   │   │   ├── embeddings/
│   │   │   ├── vectorstore/
│   │   │   ├── ml_models/
│   │   │   ├── memory/
│   │   │   ├── tools/
│   │   │   ├── api/
│   │   │   ├── config/
│   │   │   └── main.py
│   │   ├── tests/
│   │   ├── Dockerfile
│   │   ├── pyproject.toml
│   │   └── requirements.txt
│   │
│   └── frontend/                         # Vue 3 + Vite — SOC Console
│       ├── src/
│       │   ├── app/
│       │   ├── modules/
│       │   ├── shared/
│       │   ├── assets/
│       │   └── main.ts
│       ├── public/
│       ├── Dockerfile
│       ├── package.json
│       └── vite.config.ts
│
├── automation/
│   └── n8n/
│       ├── workflows/                    # exported .json workflow definitions
│       │   ├── playbook-runner.json
│       │   ├── teams-notification.json
│       │   ├── email-notification.json
│       │   ├── ticket-creation.json
│       │   ├── edr-isolate-host.json
│       │   └── firewall-block-ip.json
│       ├── custom-nodes/                 # custom n8n community nodes (TS)
│       │   ├── VigixWebhookTrigger/
│       │   └── VigixCallback/
│       ├── credentials/                  # credential templates (no secrets)
│       └── README.md
│
├── packages/                             # shared, versioned, cross-app code
│   ├── shared-types/                     # TS types generated from OpenAPI + domain contracts
│   ├── shared-schemas/                   # JSON Schema / Zod schemas shared FE↔BE
│   ├── shared-utils/                     # pure utility functions (date, hashing, etc.)
│   ├── eslint-config/
│   └── ui-kit/                           # shared Vue design-system components
│
├── infra/
│   ├── docker/
│   │   ├── docker-compose.yml            # local dev: postgres, qdrant, n8n, redis, all apps
│   │   ├── docker-compose.prod.yml
│   │   └── nginx/
│   ├── k8s/
│   │   ├── base/                         # kustomize base manifests
│   │   ├── overlays/
│   │   │   ├── dev/
│   │   │   ├── staging/
│   │   │   └── prod/
│   │   └── helm/soar-chart/
│   ├── terraform/
│   │   ├── modules/
│   │   └── environments/
│   └── monitoring/
│       ├── prometheus/
│       ├── grafana/dashboards/
│       └── otel-collector/
│
├── docs/
│   ├── architecture/                     # ADRs, diagrams (C4, ERD, sequence)
│   ├── api/                              # OpenAPI specs
│   ├── thesis/                           # academic write-up artifacts
│   └── runbooks/
│
├── scripts/                              # dev/CI helper scripts (seed db, generate types, etc.)
├── .github/workflows/                    # CI/CD pipelines
├── .env.example
├── turbo.json / nx.json
├── package.json                          # workspace root
└── README.md
```

---

## 2 & 3. Folder & File Responsibility

### 2.1 Backend (`apps/backend/src`) — Clean Architecture, 4 Rings

The dependency rule is enforced strictly: **domain → knows nothing** · **application → depends on domain only** · **infrastructure → depends on application + domain** · **presentation → depends on application only**. Arrows always point inward.

```
src/
├── domain/                               # RING 1 — Enterprise Business Rules (zero external deps)
│   ├── alert/
│   │   ├── entities/Alert.entity.ts              # Alert aggregate root
│   │   ├── value-objects/AlertSeverity.vo.ts      # enum-like immutable VO
│   │   ├── value-objects/AlertSource.vo.ts        # Wazuh|Splunk|Defender|ELK
│   │   ├── events/AlertReceived.event.ts
│   │   ├── repositories/IAlertRepository.ts       # port — interface only
│   │   └── errors/InvalidAlertError.ts
│   ├── incident/
│   │   ├── entities/Incident.entity.ts
│   │   ├── entities/IncidentTimeline.entity.ts
│   │   ├── value-objects/IncidentStatus.vo.ts
│   │   ├── services/IncidentEscalationPolicy.service.ts   # pure domain service
│   │   └── repositories/IIncidentRepository.ts
│   ├── agent-execution/
│   │   ├── entities/AgentExecution.entity.ts
│   │   ├── entities/AgentResult.entity.ts
│   │   └── repositories/IAgentExecutionRepository.ts
│   ├── threat-intel/
│   │   ├── entities/IOC.entity.ts
│   │   ├── value-objects/IOCType.vo.ts            # ip|domain|hash|url
│   │   └── repositories/IThreatIntelRepository.ts
│   ├── mitre/
│   │   ├── entities/MitreTechnique.entity.ts
│   │   └── repositories/IMitreRepository.ts
│   ├── playbook/
│   │   ├── entities/Playbook.entity.ts
│   │   ├── entities/PlaybookExecution.entity.ts
│   │   └── repositories/IPlaybookRepository.ts
│   ├── risk-assessment/
│   │   ├── entities/RiskScore.entity.ts
│   │   └── value-objects/ConfidenceLevel.vo.ts
│   ├── decision/
│   │   ├── entities/Decision.entity.ts
│   │   ├── entities/ApprovalRequest.entity.ts
│   │   └── services/PolicyEngine.service.ts       # pure risk-threshold rules
│   ├── analytics/
│   │   └── entities/KpiMetric.entity.ts           # MTTD, MTTR, ROI, automation rate
│   ├── feedback/
│   │   └── entities/AnalystFeedback.entity.ts
│   ├── identity/
│   │   ├── entities/User.entity.ts
│   │   ├── entities/Tenant.entity.ts               # multi-tenancy root
│   │   └── value-objects/Role.vo.ts
│   └── shared-kernel/
│       ├── AggregateRoot.ts
│       ├── Entity.ts
│       ├── ValueObject.ts
│       └── DomainEvent.ts
│
├── application/                          # RING 2 — Application / Use-Case Business Rules
│   ├── alert/
│   │   ├── use-cases/IngestAlertFromSiem.usecase.ts
│   │   ├── use-cases/TriggerAiAnalysis.usecase.ts
│   │   ├── dto/AlertIngestion.dto.ts
│   │   └── mappers/Alert.mapper.ts
│   ├── incident/
│   │   ├── use-cases/CreateIncidentFromAlert.usecase.ts
│   │   ├── use-cases/UpdateIncidentStatus.usecase.ts
│   │   └── use-cases/GetIncidentTimeline.usecase.ts
│   ├── agent-orchestration/
│   │   ├── use-cases/DispatchAgentPipeline.usecase.ts   # calls orchestrator port
│   │   ├── use-cases/ReceiveAgentResult.usecase.ts      # callback handler
│   │   └── ports/IAiOrchestratorPort.ts                 # interface -> swappable engine
│   ├── decision/
│   │   ├── use-cases/EvaluatePolicy.usecase.ts
│   │   ├── use-cases/RequestHumanApproval.usecase.ts
│   │   └── use-cases/ApproveOrRejectDecision.usecase.ts
│   ├── automation/
│   │   ├── use-cases/ExecutePlaybook.usecase.ts
│   │   └── ports/IWorkflowEnginePort.ts                 # interface -> n8n adapter
│   ├── analytics/
│   │   └── use-cases/ComputeExecutiveKpis.usecase.ts
│   ├── feedback/
│   │   └── use-cases/SubmitAnalystFeedback.usecase.ts
│   ├── identity/
│   │   ├── use-cases/AuthenticateUser.usecase.ts
│   │   └── use-cases/AuthorizeAction.usecase.ts
│   └── shared/
│       ├── ports/INotificationPort.ts
│       ├── ports/IEventBusPort.ts
│       └── validators/ (zod/class-validator schemas)
│
├── infrastructure/                       # RING 3 — Frameworks & Drivers (adapters implement ports)
│   ├── database/
│   │   ├── postgres/
│   │   │   ├── client.ts                                    # PrismaClient singleton (DI-injected)
│   │   │   ├── repositories/AlertRepository.prisma.ts        # implements IAlertRepository
│   │   │   ├── repositories/IncidentRepository.prisma.ts
│   │   │   └── mappers/                                      # Prisma model ↔ domain entity mappers
│   │   └── connection.ts
│   │       # NOTE: schema.prisma + migrations/ live at apps/backend/prisma/ (Prisma CLI root convention),
│   │       # not inside src/ — Prisma requires the schema at a fixed, tool-discoverable path.
│   ├── ai/
│   │   ├── LangGraphOrchestratorAdapter.ts               # implements IAiOrchestratorPort (HTTP client)
│   │   └── dto/OrchestratorRequest.dto.ts
│   ├── external-services/
│   │   ├── siem/
│   │   │   ├── WazuhAdapter.ts
│   │   │   ├── SplunkAdapter.ts
│   │   │   ├── DefenderAdapter.ts
│   │   │   ├── ElkAdapter.ts
│   │   │   └── ISiemAdapter.ts                           # common interface
│   │   ├── threat-intel/
│   │   │   ├── MispAdapter.ts
│   │   │   ├── VirusTotalAdapter.ts
│   │   │   └── OtxAdapter.ts
│   │   └── notification/
│   │       ├── TeamsNotificationAdapter.ts
│   │       └── EmailNotificationAdapter.ts
│   ├── automation/
│   │   └── N8nWorkflowEngineAdapter.ts                   # implements IWorkflowEnginePort
│   ├── messaging/
│   │   ├── EventBus.ts                                   # in-proc pub/sub (or Kafka/Redis Streams later)
│   │   └── WebhookDispatcher.ts
│   ├── security/
│   │   ├── JwtTokenService.ts
│   │   ├── PasswordHasher.ts
│   │   └── RbacGuard.ts
│   ├── cache/
│   │   └── RedisCacheAdapter.ts
│   ├── config/
│   │   ├── env.config.ts
│   │   └── container.ts                                  # DI container wiring (tsyringe/inversify)
│   └── logging/
│       └── Logger.ts                                     # structured JSON logger
│
├── presentation/                         # RING 4 — Interface Adapters (HTTP boundary)
│   ├── http/
│   │   ├── controllers/
│   │   │   ├── AlertController.ts
│   │   │   ├── IncidentController.ts
│   │   │   ├── DecisionController.ts
│   │   │   ├── PlaybookController.ts
│   │   │   ├── AnalyticsController.ts
│   │   │   └── FeedbackController.ts
│   │   ├── routes/
│   │   │   ├── alert.routes.ts
│   │   │   ├── incident.routes.ts
│   │   │   ├── decision.routes.ts
│   │   │   ├── webhook.routes.ts                         # inbound SIEM webhooks
│   │   │   └── index.ts
│   │   ├── middlewares/
│   │   │   ├── auth.middleware.ts
│   │   │   ├── error-handler.middleware.ts
│   │   │   ├── request-validation.middleware.ts
│   │   │   └── rate-limit.middleware.ts
│   │   └── webhooks/
│   │       ├── siem-inbound.webhook.ts
│   │       └── orchestrator-callback.webhook.ts          # AI result callback
│   └── websocket/
│       └── RealtimeGateway.ts                             # live alert/incident push to FE
│
├── shared/                               # cross-cutting kernel (no business rules)
│   ├── exceptions/AppException.ts
│   ├── result/Result.ts                                   # Result<T, E> pattern
│   └── di/tokens.ts
│
└── main.ts                               # composition root: builds container, starts server
```

**Naming discipline in this ring model:** a file's folder tells you which ring it lives in; a class name never leaks its ring (`AlertRepository.pg.ts` implements `IAlertRepository`, so the domain never imports Postgres).

### 2.2 AI Orchestrator (`apps/ai-orchestrator/src`) — LangGraph Multi-Agent Engine

```
src/
├── agents/
│   ├── threat_intel_agent/
│   │   ├── agent.py                      # LangGraph node function
│   │   ├── prompts.py
│   │   └── clients/ (misp_client.py, vt_client.py, otx_client.py)
│   ├── mitre_agent/
│   │   ├── agent.py
│   │   └── attack_matrix.py              # local ATT&CK STIX bundle loader
│   ├── rag_agent/
│   │   ├── agent.py
│   │   └── retriever.py                  # Qdrant similarity search wrapper
│   ├── ml_risk_agent/
│   │   ├── agent.py
│   │   ├── model/xgboost_risk_model.pkl
│   │   └── feature_engineering.py
│   ├── llm_analyst_agent/
│   │   ├── agent.py
│   │   ├── prompts/summary.jinja
│   │   ├── prompts/recommendation.jinja
│   │   └── prompts/report.jinja
│   ├── validation_agent/
│   │   ├── agent.py
│   │   └── rules.py                      # cross-check heuristics
│   ├── decision_agent/
│   │   ├── agent.py
│   │   └── policy_rules.py               # risk-threshold + human-in-loop gate
│   ├── business_analytics_agent/
│   │   ├── agent.py
│   │   └── kpi_calculators.py            # MTTD/MTTR/ROI formulas
│   └── feedback_agent/
│       ├── agent.py
│       └── retrain_trigger.py            # optional async retrain job dispatch
│
├── graph/
│   ├── state.py                          # TypedDict / Pydantic AgentState schema
│   ├── build_graph.py                    # StateGraph definition, nodes + edges
│   ├── router.py                         # conditional-edge routing logic
│   └── checkpointer.py                   # LangGraph persistence (Postgres checkpointer)
│
├── llm/
│   ├── provider_interface.py             # ILlmProvider — abstract base
│   ├── llama_provider.py                 # Llama 3.1 8B Instruct (vLLM/Ollama backend)
│   └── prompt_registry.py
│
├── embeddings/
│   ├── provider_interface.py             # IEmbeddingProvider
│   └── bge_embedding_provider.py         # BAAI/bge-small-en-v1.5
│
├── vectorstore/
│   ├── provider_interface.py             # IVectorStore — abstract base
│   └── qdrant_provider.py                # implements IVectorStore
│
├── ml_models/
│   ├── provider_interface.py             # IRiskModel
│   └── xgboost_provider.py
│
├── memory/
│   ├── short_term_memory.py              # per-run scratchpad (graph state)
│   └── long_term_memory.py               # cross-run memory (Postgres + Qdrant)
│
├── tools/
│   ├── ioc_extraction_tool.py
│   └── mitre_lookup_tool.py
│
├── api/
│   ├── main.py                           # FastAPI app
│   ├── routes/run_pipeline.py            # POST /pipeline/run
│   ├── routes/health.py
│   └── schemas.py                        # request/response Pydantic models
│
├── config/
│   ├── settings.py                       # pydantic-settings, env-driven
│   └── logging_config.py
│
└── main.py                               # entrypoint: uvicorn app
```

### 2.3 Frontend (`apps/frontend/src`) — Feature-Sliced Vue 3

```
src/
├── app/
│   ├── router/index.ts
│   ├── store/ (Pinia root)
│   └── App.vue
├── modules/
│   ├── alerts/
│   │   ├── components/ (AlertTable.vue, AlertDetailDrawer.vue)
│   │   ├── composables/useAlerts.ts
│   │   ├── stores/alerts.store.ts
│   │   ├── services/alerts.api.ts
│   │   └── views/AlertsView.vue
│   ├── incidents/
│   │   ├── components/ (IncidentTimeline.vue, MitreMatrixView.vue)
│   │   ├── stores/incidents.store.ts
│   │   └── views/IncidentDetailView.vue
│   ├── decisions/
│   │   ├── components/ApprovalCard.vue
│   │   └── views/ApprovalQueueView.vue
│   ├── playbooks/
│   │   └── views/PlaybookLibraryView.vue
│   ├── analytics/
│   │   ├── components/ (KpiCard.vue, MttdMttrChart.vue, RoiChart.vue)
│   │   └── views/ExecutiveDashboardView.vue
│   └── settings/
│       └── views/IntegrationsView.vue    # SIEM/TI credentials management
├── shared/
│   ├── ui-kit/ (Button.vue, Modal.vue, Badge.vue …)
│   ├── composables/ (useWebSocket.ts, useAuth.ts)
│   └── utils/
├── assets/
└── main.ts
```

---

## 4. Naming Conventions

| Scope | Convention | Example |
|---|---|---|
| TypeScript files (classes) | `PascalCase.suffix.ts` | `Alert.entity.ts`, `AlertRepository.pg.ts` |
| TS interfaces (ports) | `I` prefix | `IAlertRepository`, `IAiOrchestratorPort` |
| TS use-cases | `Verb+Noun.usecase.ts` | `IngestAlertFromSiem.usecase.ts` |
| Vue components/files | `PascalCase.vue` | `AlertDetailDrawer.vue` |
| Vue composables | `useXxx.ts` | `useAlerts.ts` |
| Pinia stores | `xxx.store.ts`, camelCase state | `incidents.store.ts` |
| Python modules/files | `snake_case.py` | `xgboost_provider.py` |
| Python classes | `PascalCase` | `class ThreatIntelAgent` |
| REST endpoints | plural kebab-case nouns | `/api/v1/incidents`, `/api/v1/threat-intel/iocs` |
| Postgres tables | `snake_case`, plural | `agent_executions`, `risk_scores` |
| Postgres columns | `snake_case` | `created_at`, `risk_score_value` |
| Qdrant collections | `snake_case` singular-domain | `playbook_embeddings`, `incident_embeddings` |
| Env variables | `UPPER_SNAKE_CASE` | `QDRANT_URL`, `LLM_PROVIDER` |
| Git branches | `type/short-desc` | `feat/mitre-agent`, `fix/webhook-auth` |
| Docker services | kebab-case | `soar-backend`, `ai-orchestrator` |
| Domain events | `PastTense.event.ts` | `AlertReceived.event.ts`, `DecisionApproved.event.ts` |

---

## 5. Module Dependency Rules

```
        presentation ──▶ application ──▶ domain
        infrastructure ────────────────▶ domain
        infrastructure ──▶ application (implements ports declared there)

              domain            → depends on NOTHING (pure TS/Python, no framework imports)
              application       → depends on domain only, defines PORTS (interfaces) for everything external
              infrastructure    → implements ports; free to import ORMs, SDKs, HTTP clients
              presentation      → depends on application use-cases only, never touches infrastructure directly
```

**Inter-service dependency (macro level):**

```
frontend  ──HTTP/WS──▶ backend
backend   ──HTTP──────▶ ai-orchestrator   (via IAiOrchestratorPort / LangGraphOrchestratorAdapter)
backend   ──HTTP──────▶ n8n               (via IWorkflowEnginePort / N8nWorkflowEngineAdapter)
ai-orchestrator ──────▶ Qdrant, PostgreSQL (checkpointer), Llama runtime, XGBoost model
n8n       ──HTTP──────▶ Teams, Email/SMTP, Ticketing, Firewall/EDR APIs
n8n       ──callback──▶ backend (orchestrator-callback.webhook.ts) — reports execution result
```

Because `backend` only ever talks to the orchestrator and to n8n through **ports**, either can be replaced (e.g. swap n8n for Temporal, or LangGraph for a different agent framework) by writing a new adapter — zero change to domain or application code. Same pattern makes the **LLM**, **vector database**, and **threat-intel provider** swappable purely inside `ai-orchestrator`'s `llm/`, `vectorstore/`, and `agents/threat_intel_agent/clients/` folders, each behind a small `provider_interface.py`.

---

## 6. Agent Interaction Model

```
                                   ┌─────────────────────┐
                                   │   Alert Ingested     │
                                   │ (backend → POST      │
                                   │  /pipeline/run)       │
                                   └──────────┬───────────┘
                                              │
                                              ▼
                                   ┌─────────────────────┐
                                   │     START node        │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │ ThreatIntelAgent      │
                                   │ (MISP/VT/OTX)         │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │   MitreAgent           │
                                   │ (ATT&CK mapping)      │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │    RagAgent            │
                                   │ (Qdrant retrieval)    │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │    MlRiskAgent        │
                                   │ (XGBoost risk score)  │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │   LlmAnalystAgent     │
                                   │ (Llama 3.1 summary,   │
                                   │  explanation, report) │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │   ValidationAgent     │
                                   │ (cross-checks TI,     │
                                   │  MITRE, RAG, LLM)     │
                                   └──────────┬───────────┘
                                     pass │        │ fail → loop back
                                          ▼        └──────────────┐
                                   ┌─────────────────────┐        │
                                   │    DecisionAgent      │◀──────┘
                                   │ (policy engine,       │
                                   │  risk threshold)      │
                                   └──────────┬───────────┘
                              risk < T │             │ risk ≥ T
                                       ▼             ▼
                          ┌────────────────┐  ┌──────────────────────┐
                          │  Auto-Response  │  │ Human Approval Queue  │
                          │ (n8n playbook)  │  │ (backend → frontend)  │
                          └────────┬────────┘  └───────────┬───────────┘
                                   └───────────┬────────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │ BusinessAnalyticsAgent│
                                   │ (MTTD/MTTR/ROI/KPI)   │
                                   └──────────┬───────────┘
                                              ▼
                                   ┌─────────────────────┐
                                   │    FeedbackAgent      │
                                   │ (analyst feedback →   │
                                   │  playbook/KB/retrain) │
                                   └──────────┬───────────┘
                                              ▼
                                          END node
```

Key interaction rules:
- **Sequential enrichment chain**: ThreatIntelAgent → MitreAgent → RagAgent run as ordered LangGraph nodes, not a parallel fan-out — RagAgent's query builder reads MitreAgent's technique matches and ThreatIntelAgent's IOC-derived malware family/threat categories out of `AgentState`, so it must run strictly after both have written their output.
- **Sequential dependency**: MlRiskAgent needs enrichment context (IOC reputation, MITRE techniques, similar past incidents) as features, so it must run after RagAgent.
- **Feedback edge**: ValidationAgent can route back to any upstream agent (conditional edge) if confidence is below threshold, up to a max retry count stored in state.
- **Human-in-the-loop**: DecisionAgent is a conditional edge — LangGraph interrupts the graph (`interrupt_before`) and persists a checkpoint when human approval is required; the graph resumes once the analyst responds via the frontend, which calls back into the backend, which resumes the orchestrator run.

---

## 7. LangGraph Workflow (State Graph Definition)

**Shared state schema** (`graph/state.py`):

```python
class AgentState(TypedDict):
    alert_id: str
    tenant_id: str
    raw_alert: dict
    siem_source: Literal["wazuh", "splunk", "defender", "elk"]
    iocs: list[dict]                    # ThreatIntelAgent output
    mitre_techniques: list[dict]        # MitreAgent output
    rag_matches: list[dict]             # RagAgent output (playbooks/SOPs/similar incidents)
    risk_score: float | None            # MlRiskAgent output
    severity_prediction: str | None
    confidence_score: float | None
    llm_summary: str | None             # LlmAnalystAgent output
    llm_recommendation: str | None
    validation_report: dict | None      # ValidationAgent output
    decision: Literal["auto_response","human_approval","dismiss"] | None
    approval_status: Literal["pending","approved","rejected"] | None
    kpi_snapshot: dict | None           # BusinessAnalyticsAgent output
    feedback: dict | None               # FeedbackAgent output
    retry_count: int
    trace: list[str]                    # execution trace for audit/thesis analysis
```

**Graph wiring** (`graph/build_graph.py`, conceptual):

```python
graph = StateGraph(AgentState)

graph.add_node("threat_intel", threat_intel_agent.run)
graph.add_node("mitre", mitre_agent.run)
graph.add_node("rag", rag_agent.run)
graph.add_node("ml_risk", ml_risk_agent.run)
graph.add_node("llm_analyst", llm_analyst_agent.run)
graph.add_node("validation", validation_agent.run)
graph.add_node("decision", decision_agent.run)
graph.add_node("business_analytics", business_analytics_agent.run)
graph.add_node("feedback", feedback_agent.run)

graph.set_entry_point("threat_intel")
graph.add_edge("threat_intel", "mitre")
graph.add_edge("mitre", "rag")
# Sequential, not a parallel fan-out: RagAgent reads MitreAgent's/
# ThreatIntelAgent's output out of AgentState, so it must run after both.

graph.add_edge("rag", "ml_risk")
graph.add_edge("ml_risk", "llm_analyst")
graph.add_edge("llm_analyst", "validation")

graph.add_conditional_edges(
    "validation",
    lambda s: "retry" if s["validation_report"]["failed"] and s["retry_count"] < 2 else "proceed",
    {"retry": "threat_intel", "proceed": "decision"},
)

graph.add_conditional_edges(
    "decision",
    lambda s: s["decision"],
    {"auto_response": "business_analytics",
     "human_approval": "business_analytics",   # graph interrupts here via interrupt_before
     "dismiss": "business_analytics"},
)

graph.add_edge("business_analytics", "feedback")
graph.add_edge("feedback", END)

app = graph.compile(checkpointer=PostgresCheckpointer(...), interrupt_before=["decision"])
```

**Execution modes:**
- **Synchronous** (low-severity, fast agents) — backend awaits the full run for near-real-time UI feedback.
- **Asynchronous with checkpoint resume** (human approval required) — LangGraph persists state to Postgres via the checkpointer; the run resumes from the exact node once an analyst approves/rejects in the frontend.
- **Parallel node execution** is native to LangGraph's `StateGraph` (nodes without a dependency edge between them execute concurrently in the same superstep) but is not used for ThreatIntelAgent/MitreAgent/RagAgent — they're wired as a sequential chain because RagAgent has a real data dependency on the other two's output.

---

## 8. Database Structure

### 8.1 PostgreSQL — Operational / Relational Store

```
tenants(id, name, plan, created_at)
users(id, tenant_id FK, email, password_hash, role, created_at)

alerts(
  id, tenant_id FK, external_alert_id, siem_source, raw_payload JSONB,
  severity, status, received_at, created_at
)

incidents(
  id, tenant_id FK, alert_id FK, title, status, priority,
  opened_at, closed_at, mttd_seconds, mttr_seconds
)

incident_timeline(id, incident_id FK, event_type, description, actor, occurred_at)

agent_executions(
  id, incident_id FK, graph_run_id, status, started_at, completed_at, trace JSONB
)

agent_results(
  id, agent_execution_id FK, agent_name, output JSONB, confidence, created_at
)

threat_intel_iocs(
  id, incident_id FK, ioc_type, ioc_value, source, reputation_score, raw_response JSONB
)

mitre_mappings(id, incident_id FK, technique_id, tactic, confidence)

playbooks(id, tenant_id FK, name, description, trigger_conditions JSONB, n8n_workflow_id)

playbook_executions(
  id, playbook_id FK, incident_id FK, status, started_at, completed_at, result JSONB
)

risk_scores(id, incident_id FK, score, severity_prediction, confidence_score, model_version)

decisions(
  id, incident_id FK, decision_type, risk_threshold_used, requires_approval, created_at
)

approvals(
  id, decision_id FK, requested_to (user_id FK), status, decided_at, comment
)

kpi_metrics(
  id, tenant_id FK, period_start, period_end, mttd_avg, mttr_avg,
  automation_rate, analyst_time_saved_hours, cost_saving_usd
)

analyst_feedback(
  id, incident_id FK, user_id FK, rating, comment, playbook_suggested_change, created_at
)

audit_logs(id, tenant_id FK, actor, action, entity, entity_id, metadata JSONB, created_at)
```

Indexes: `alerts(tenant_id, received_at)`, `incidents(tenant_id, status)`, `agent_results(agent_execution_id)`, partial index on `approvals(status='pending')` for the approval queue.

### 8.2 Qdrant — Vector Store (swappable behind `IVectorStore`)

| Collection | Embedding model | Payload | Purpose |
|---|---|---|---|
| `playbook_embeddings` | bge-small-en-v1.5 (384-d) | `playbook_id, name, tags` | RagAgent playbook retrieval |
| `sop_embeddings` | bge-small-en-v1.5 | `sop_id, category` | SOP retrieval |
| `incident_embeddings` | bge-small-en-v1.5 | `incident_id, mitre_techniques, severity` | similar-incident retrieval |

---

## 9. API Structure (Backend REST, `/api/v1`)

```
POST   /webhooks/siem/:source              # inbound alert ingestion (Wazuh|Splunk|Defender|ELK)
POST   /webhooks/orchestrator/callback     # AI orchestrator result callback

GET    /alerts                             # list/filter alerts
GET    /alerts/:id
POST   /alerts/:id/analyze                 # manually trigger AI pipeline

GET    /incidents
GET    /incidents/:id
GET    /incidents/:id/timeline
PATCH  /incidents/:id/status

GET    /incidents/:id/threat-intel
GET    /incidents/:id/mitre-mapping
GET    /incidents/:id/risk-score
GET    /incidents/:id/llm-report

GET    /decisions/pending                  # approval queue
POST   /decisions/:id/approve
POST   /decisions/:id/reject

GET    /playbooks
POST   /playbooks
POST   /playbooks/:id/execute

GET    /analytics/kpi                      # MTTD, MTTR, ROI, automation rate
GET    /analytics/executive-dashboard

POST   /feedback

POST   /auth/login
POST   /auth/refresh
GET    /users/me
```

The **ai-orchestrator** exposes its own internal FastAPI surface, called only by `backend`, never by the frontend:

```
POST /pipeline/run          # start a new LangGraph run
POST /pipeline/resume       # resume an interrupted run (human approval decision)
GET  /pipeline/:run_id      # run status / partial state
GET  /health
```

All external endpoints are versioned (`/api/v1`), authenticated via JWT + RBAC (`RbacGuard`), and validated at the presentation boundary using shared Zod/Pydantic schemas generated from `packages/shared-schemas`.

---

## 10. Future Scalability

| Concern | Strategy |
|---|---|
| **Agent throughput** | Move orchestrator invocation from sync HTTP to an async queue (Kafka/RabbitMQ/Redis Streams); backend publishes `AlertReceived`, orchestrator workers consume and scale horizontally |
| **Multi-tenancy** | `tenant_id` already threaded through every table and the graph state; can graduate to schema-per-tenant or DB-per-tenant for large customers |
| **LLM swap** | `ILlmProvider` abstraction — replace Llama 3.1 8B with a larger local model, or a hosted API, by adding a new provider module, no agent code changes |
| **Vector DB swap** | `IVectorStore` abstraction — Qdrant can be replaced with pgvector, Weaviate, or Milvus behind the same interface |
| **Threat-intel swap** | Each TI source is an isolated client behind `ThreatIntelAgent`; add/remove sources (Recorded Future, Shodan, etc.) without touching the agent's public contract |
| **Horizontal scaling** | Stateless backend/orchestrator pods behind a load balancer; PostgreSQL read replicas for analytics queries; Qdrant sharding for large embedding sets |
| **Workflow engine swap** | `IWorkflowEnginePort` isolates n8n; could migrate to Temporal or Camunda later with a new adapter only |
| **Observability** | OpenTelemetry tracing across backend → orchestrator → n8n; Prometheus + Grafana dashboards; LangGraph trace persisted per run for auditability and thesis evaluation data |
| **ML retraining** | FeedbackAgent can enqueue a retrain job (separate `ml-training` service, out of critical path) consuming analyst feedback + closed-incident outcomes to periodically refresh the XGBoost model |
| **Security hardening** | Secrets in a vault (HashiCorp Vault/AWS Secrets Manager), mTLS between internal services, signed webhook payloads from SIEMs, per-tenant API keys |
| **Deployment target** | Docker Compose for dev/thesis demo → Kubernetes (Helm chart in `infra/k8s`) for production, with Terraform-managed cloud infra |

---

## Summary

The AI-Driven SOAR Automation Platform cleanly separates **what the system does** (domain/application) from **how it does it** (infrastructure/presentation) in the backend, isolates the **AI reasoning pipeline** as an independently scalable LangGraph service, and treats **n8n** purely as a pluggable execution engine for response actions. Every external dependency — SIEM, threat-intel feed, LLM, vector database, workflow engine — sits behind a narrow interface (port), which is the architectural property that makes the platform both enterprise-defensible and thesis-defensible: you can justify every module boundary by pointing to the specific interface it implements and the specific requirement (SOLID, DDD, replaceability) it satisfies.
