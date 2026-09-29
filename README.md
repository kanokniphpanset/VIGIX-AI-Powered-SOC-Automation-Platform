# AI-Driven SOAR Automation Platform

Enterprise SOAR automation layer that ingests alerts from external SIEMs (Wazuh, Splunk,
Microsoft Defender, ELK), runs them through a multi-agent AI pipeline (LangGraph), and
drives automated/human-approved response through n8n.

This repo now includes a working **Threat Intelligence module** (backend REST API +
dashboard page) that analyzes a single IOC — IP, domain, URL, email, or hash — against
VirusTotal, AbuseIPDB, and a **self-hosted MISP instance**, and returns an aggregated,
explainable threat score. See [Threat Intelligence module](#threat-intelligence-module)
below for how it works and how to run it.

It also ships a **MitreAgent dashboard** for browsing the full MITRE ATT&CK Enterprise
technique catalog (697 techniques, synced from MITRE's own published data) as a heatmap
matrix. See [MitreAgent module](#mitreagent-module) below.

Finally, it includes a **Knowledge Base + RAG Agent**: a Markdown-based Incident Response
Knowledge Base (playbooks, SOPs, runbooks, threat reports, MITRE techniques) that gets
chunked, embedded into Qdrant, and semantically retrieved by `RagAgent` — one of the 9
AI agents in the LangGraph pipeline — to ground `LlmAnalystAgent`'s output in real
institutional knowledge instead of the model's own unaided judgment. See
[Knowledge Base & RAG Agent module](#knowledge-base--rag-agent-module) below.

---

## 0. Prerequisites (install these first)

| Tool | Version | Check with |
|---|---|---|
| Node.js | 20.x LTS | `node -v` |
| npm | 10.x | `npm -v` |
| Python | 3.11+ | `python3 --version` |
| Docker Desktop | latest | `docker -v` |
| Docker Compose | v2 (bundled with Docker Desktop) | `docker compose version` |
| Git | any recent | `git --version` |

Docker Desktop must be **running** before you continue (it starts PostgreSQL, Qdrant, n8n,
and Redis for you — you don't install those individually).

---

## 1. Clone the repository

```bash
git clone https://github.com/your-org/soar-platform.git
cd soar-platform
```

---

## 2. Configure environment variables

Copy the example env file and fill in the values (defaults work fine for local/demo use).

```bash
cp .env.example .env
```

Open `.env` and confirm at minimum:

```env
# Database
DATABASE_URL="postgresql://soar:soar_password@localhost:5432/soar_platform"

# Vector DB
QDRANT_URL="http://localhost:6333"

# AI Orchestrator
AI_ORCHESTRATOR_URL="http://localhost:8000"
LLM_PROVIDER="llama-3.1-8b-instruct"
EMBEDDING_MODEL="BAAI/bge-small-en-v1.5"

# n8n
N8N_URL="http://localhost:5678"
N8N_API_KEY="changeme"

# Auth
JWT_SECRET="replace-with-a-long-random-string"

# App
BACKEND_PORT=4000
FRONTEND_PORT=5173

# Threat Intelligence module (backend) — all optional. Any provider left
# unconfigured just reports as "DISABLED" in results instead of failing.
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
MISP_URL="https://localhost:8443"        # self-hosted, see Step 3
MISP_API_KEY=                            # fetched after MISP's first boot, see Step 3
MISP_VERIFY_TLS=false                    # self-hosted MISP uses a self-signed cert
```

> The real per-provider `.env` (retry counts, timeouts, MISP TLS/base-URL settings) lives
> in `apps/backend/.env` — see [Step 6](#6-start-the-backend-api) and
> `apps/backend/.env.example` for the full list.

---

## 3. Start infrastructure services (Postgres, Qdrant, n8n, Redis, MISP)

This uses the Docker Compose file in `infra/docker/`.

```bash
docker compose -f infra/docker/docker-compose.yml up -d
```

Verify everything is healthy:

```bash
docker compose -f infra/docker/docker-compose.yml ps
```

You should see `postgres`, `qdrant`, `n8n`, `redis`, `misp-db`, `misp-redis`,
`misp-modules`, and `misp-core` all with status `Up (healthy)` (`misp-modules` has no
healthcheck, `Up` is enough).

- Qdrant dashboard: http://localhost:6333/dashboard
- n8n editor: http://localhost:5678
- MISP web UI: https://localhost:8443 (self-signed cert — accept the browser warning; login `admin@admin.test` / `admin`)

### MISP first boot (one-time)

MISP is **self-hosted**, not an external API — the compose file runs the official
[MISP-docker](https://github.com/MISP/misp-docker) images (`misp-core`, `misp-db`,
`misp-redis`, `misp-modules`). First boot runs MISP's own DB migration and GPG key
generation, which takes several minutes:

```bash
docker compose -f infra/docker/docker-compose.yml logs -f misp-core
```

Wait until `docker compose -f infra/docker/docker-compose.yml ps` shows `misp-core` as
`healthy`, then fetch the automation API key (MISP runs with "advanced authkeys" enabled,
so the key **cannot** be pre-set — it must be generated and captured after boot):

```bash
docker compose -f infra/docker/docker-compose.yml exec misp-core \
  /var/www/MISP/app/Console/cake User change_authkey 1
```

Copy the printed key into `MISP_API_KEY` in both `apps/backend/.env` and
`apps/ai-orchestrator/.env`. Re-run this command any time to rotate the key (it
invalidates the previous one).

> All MISP credentials in `infra/docker/docker-compose.yml` (`ADMIN_PASSWORD`,
> `MYSQL_PASSWORD`, `GPG_PASSPHRASE`) are local-dev defaults — change every one of them
> before running this anywhere but your own machine.

---

## 4. Install dependencies (root workspace)

From the repo root (this installs backend + frontend + shared packages in one pass,
since it's a monorepo):

```bash
npm install
```

For the Python AI orchestrator, use a virtual environment:

```bash
cd apps/ai-orchestrator
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd ../..
```

---

## 5. Set up the database (Prisma)

> **Important (monorepo gotcha):** Prisma's CLI only reads a `.env` file located in the
> **same package folder as `schema.prisma`** — that's `apps/backend/`, not the repo root.
> Even though you created `.env` at the repo root in Step 2, you also need one inside
> `apps/backend/`.

```bash
cd apps/backend
cp .env.example .env      # backend-local env file, required by Prisma CLI
```

Run this from `apps/backend`:

```bash
npx prisma generate          # generates the Prisma client
npx prisma migrate dev       # creates tables from schema.prisma
```

If you see `Error: Environment variable not found: DATABASE_URL`, it means the
`apps/backend/.env` file above is missing — Prisma cannot see the root `.env`.

If you see a database connection error instead, Docker's Postgres container likely isn't
running yet — go back to Step 3 and confirm `docker compose ... ps` shows `soar-postgres`
as `Up (healthy)`.

### Run the seed script

The seed script populates demo data: a default tenant, an admin user, MITRE ATT&CK
reference data, and a couple of sample alerts/incidents so the dashboard isn't empty on
first login.

```bash
npm run seed
```

This runs `prisma/seed.ts` under the hood (wired via the `"prisma": { "seed": ... }`
entry in `apps/backend/package.json`). If you ever want to run it directly without the
npm alias:

```bash
npx prisma db seed
```

To wipe and reseed from scratch:

```bash
npx prisma migrate reset
```

(`migrate reset` drops the DB, reapplies migrations, and re-runs the seed automatically.)

```bash
cd ../..    # back to repo root
```

---

## 6. Start the backend API

```bash
cd apps/backend
npm run dev
```

Backend should now be running at **http://localhost:4000**. Confirm with:

```bash
curl http://localhost:4000/api/v1/health
```

### Orchestration worker (Phase 4)

The webhook above only validates, persists, and enqueues — it never runs the
AI pipeline itself (see Step 10). A separate worker process consumes the
`vigix-ai-orchestration` queue and actually dispatches each job to the AI
orchestrator (Step 7). Without this running, enqueued jobs just sit
`QUEUED` forever. In another terminal:

```bash
cd apps/backend
npm run worker:dev
```

Concurrency (how many jobs this process handles at once) is controlled by
`AI_WORKER_CONCURRENCY` in `apps/backend/.env` (default 3) — see
`src/worker.ts` for the full retry/backoff/idempotency picture.

---

## Threat Intelligence module

A self-contained feature inside `apps/backend` for looking up a **single indicator on
demand** — separate from the AI orchestrator's own per-alert `ThreatIntelAgent` (Step 7),
which enriches every IOC found in an incoming alert automatically. This module is for an
analyst (or the dashboard) asking "what do we know about *this one* IP/domain/hash right
now?"

### How it works

```
POST /api/threat-intelligence/analyze  { "ioc": "185.220.101.1" }
        │
        ▼
1. Detect & validate the IOC's type (IPv4/IPv6/domain/URL/email/MD5/SHA1/SHA256)
        │
        ▼
2. Query every configured provider in parallel — each one never throws, it
   always reports a status (SUCCESS, DISABLED, FAILED, TIMEOUT, RATE_LIMITED, ...):
     • VirusTotal   — /ip_addresses, /domains, /urls, /files
     • AbuseIPDB    — /check (IPv4/IPv6 only)
     • MISP         — Attribute Search + Event Search (self-hosted, all types)
        │
        ▼
3. Aggregate every provider's independent result into one explainable verdict:
   additive threat score (0-100), risk level, and a human-readable summary +
   line-by-line score breakdown. A provider with no API key configured just
   shows "DISABLED" — it never blocks the other providers or fails the request.
        │
        ▼
4. Return the full report: verdict, threat score, confidence, every provider's
   raw result, categories/malware family/threat actors, and the summary.
```

A provider left unconfigured (no API key) never breaks the request — it just reports
`DISABLED` and the aggregate verdict is based on whichever providers *did* respond. If
**no** provider could be reached at all, the verdict is `UNKNOWN` — deliberately never
the same as `CLEAN` (`CLEAN` means providers actually checked and found nothing).

### Try it

```bash
curl -X POST http://localhost:4000/api/threat-intelligence/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.1"}'
```

Or open the dashboard page — see [Step 8](#8-start-the-frontend-dashboard) — and use the
**Threat Intel** nav item.

Interactive API docs (Swagger UI): **http://localhost:4000/api-docs**

### Configuration

Set these in `apps/backend/.env` (see `apps/backend/.env.example` for the full list
including timeouts/retries):

| Var | Required for |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal lookups (get a free key at virustotal.com) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB lookups (get a free key at abuseipdb.com) |
| `MISP_URL`, `MISP_API_KEY` | Self-hosted MISP — see [Step 3](#3-start-infrastructure-services-postgres-qdrant-n8n-redis-misp) for how to boot MISP and fetch the key |
| `MISP_VERIFY_TLS=false` | Required for the self-hosted instance's self-signed cert |

None of these are required to run the module — with all three unset, `/analyze` still
responds `200 OK` with every provider `DISABLED` and verdict `UNKNOWN`.

### Architecture note

Clean Architecture, same as the rest of `apps/backend`: `domain/threat-intel/` holds the
IOC processing pipeline and the scoring service (pure logic, no I/O);
`infrastructure/external-services/threat-intel/{virustotal,abuseipdb,misp}/` holds one
adapter per provider (the only place that knows about axios/HTTP); the frontend
(`apps/frontend/src/modules/threat-intel/`) contains **no business logic** — it only
calls the API and renders whatever comes back.

---

## MitreAgent module

A read-only browsing/coverage dashboard for the MITRE ATT&CK Enterprise matrix, backed by
the same technique knowledge base MitreAgent's rule engine uses internally to map alert
behavior onto ATT&CK techniques (`apps/backend/data/mitre/techniques/*.json`). This module
only exposes the catalog for browsing — it does not run alert-to-technique mapping over
HTTP; that happens inside the AI orchestrator's pipeline (see [Step 7](#7-start-the-ai-orchestrator-langgraph-service)).

### How it works

```
GET /api/v1/mitre/techniques
        │
        ▼
Reads every apps/backend/data/mitre/techniques/<id>.json file, validates each against
the schema, and returns the full catalog: technique ID, name, description, tactics,
platforms, data sources, detection guidance, and references.
```

Try it:

```bash
curl http://localhost:4000/api/v1/mitre/techniques
```

Or open the dashboard — **Mitre Agent** in the sidebar
(`http://localhost:5173/mitre-agent`). The matrix columns and technique names are real,
live data from that endpoint. Detection counts, the 14-day trend chart, and the
recent-alerts feed are clearly marked **sample data** in the UI — there's no live
detections pipeline wired up yet, so those numbers are illustrative placeholders, not
telemetry.

### Refreshing the ATT&CK catalog from MITRE

The shipped catalog (697 techniques) was generated from MITRE's official STIX2 export —
attack.mitre.org itself has no REST API, but MITRE publishes the full matrix as a STIX2
bundle on GitHub (`mitre-attack/attack-stix-data`). To re-sync and pick up MITRE's latest
matrix:

```bash
cd apps/backend
npm run mitre:sync
```

This downloads the current Enterprise ATT&CK bundle (~50MB) and regenerates every file
under `data/mitre/techniques/`. To process an already-downloaded bundle instead of
re-downloading:

```bash
npm run mitre:sync -- /path/to/enterprise-attack.json
```

Restart the backend afterward so it picks up the refreshed files (the in-memory catalog
cache otherwise only refreshes on its own TTL).

---

## Knowledge Base & RAG Agent module

A Retrieval-Augmented Generation layer: Markdown knowledge documents live in
`apps/backend/data/knowledge/`, get parsed, chunked, and embedded into Qdrant, and are
retrieved by `RagAgent` (Python, `apps/ai-orchestrator`) during the alert pipeline to give
`LlmAnalystAgent` real evidence — retrieved playbook steps, MITRE technique context,
threat-actor profiles — instead of reasoning from nothing.

### Document categories

```
apps/backend/data/knowledge/
├── playbooks/        Incident Response Playbooks (PLAYBOOK) — 8 shipped:
│                      ransomware, phishing, credential access/brute force,
│                      malware infection, command and control, data
│                      exfiltration, insider threat, privilege escalation
├── sop/               Standard Operating Procedures (SOP)
├── runbooks/          Step-by-step operational runbooks (RUNBOOK)
├── detection/         Detection-rule documentation (DETECTION_RULE)
├── threat-reports/    Threat actor / malware family profiles (THREAT_REPORT)
└── lessons-learned/   Post-incident retrospectives (LESSONS_LEARNED)
```

Every document is Markdown with a YAML front-matter block (`title`, `documentType`,
`incidentTypes`, `mitreTechniques`, `malwareFamilies`, `tags`, `severity`, `version`,
`createdDate`, `updatedDate`, ...). The parser (`MarkdownFrontmatterParser.ts`) is
intentionally minimal — it supports single-line `key: value` and single-line
`key: [a, b, c]` flat arrays only, **not** multi-line YAML block lists (`key:\n  - item`).
Keep every list field on one line when adding or editing a document.

### How it works

```
Markdown files (apps/backend/data/knowledge/**/*.md)
        │  npm run knowledge:ingest
        ▼
KnowledgeDocument rows in Postgres (embeddingStatus: PENDING)
        │  npm run knowledge:embed
        ▼
Chunked (1000 chars, 200 overlap) → embedded (BAAI/bge-small-en-v1.5, via the AI
orchestrator's /embeddings endpoint) → stored in Qdrant
        │
        ▼
RagAgent (LangGraph pipeline, runs after ThreatIntelAgent + MitreAgent so it has real
alert context) builds a semantic query → vector search → re-rank → filter → hands
structured evidence + a context block to LlmAnalystAgent
```

### Ingesting and embedding the knowledge base

Run from `apps/backend`, in this order, any time you add or edit a document:

```bash
npm run knowledge:ingest          # Markdown -> KnowledgeDocument rows (Postgres)
npm run knowledge:embed           # chunk + embed pending/stale documents -> Qdrant
```

Also available: `npm run mitre:knowledge:ingest` (MITRE technique catalog → knowledge
documents) and `npm run misp:knowledge:ingest` (self-hosted MISP events → knowledge
documents, incremental).

`knowledge:embed` requires the **AI orchestrator running** (it calls its `/embeddings`
endpoint) and **Qdrant reachable** — start both before running it (see
[Step 7](#7-start-the-ai-orchestrator-langgraph-service)). A document that fails to embed
is marked `FAILED` and is excluded from future `knowledge:embed` runs until an operator
resets it back to `PENDING` — see [Troubleshooting](#troubleshooting) if you hit this.

### Viewing RAG Agent output

Open the dashboard — **RAG Agent** in the sidebar (`http://localhost:5173/rag-agent`) —
to see the retrieval pipeline, retrieved documents with relevance scores, the exact
context text handed to `LlmAnalystAgent`, and source references for a given incident.

> **Status:** the dashboard currently shows clearly-labeled **mock data** — the backend
> doesn't yet expose `GET /api/v1/rag-agent/executions/latest`. Real `RagAgent` output is
> already persisted per-incident in the `agent_results` table (`agent_name = 'rag'`);
> wiring that endpoint is the next step to make the dashboard live.

---

## 7. Start the AI orchestrator (LangGraph service)

In a new terminal:

```bash
cd apps/ai-orchestrator
cp .env.example .env      # same monorepo gotcha as Prisma — this must live in apps/ai-orchestrator/
source .venv/bin/activate      # Windows: .venv\Scripts\activate
uvicorn src.main:app --reload --port 8000
```

> **Windows, without `--reload`** (e.g. running the built app, or any other
> single-process `uvicorn` invocation): use `python scripts/run_dev_server.py`
> instead. `--reload` happens to work around a real bug — psycopg's async
> pool (the Phase 4 Postgres checkpointer) cannot run under asyncio's default
> ProactorEventLoop on Windows, and uvicorn only switches to the compatible
> SelectorEventLoop in its `--reload`/multi-worker subprocess mode, not in
> plain single-process mode. The Docker image is unaffected (Linux has no
> ProactorEventLoop).

Confirm it's up:

```bash
curl http://localhost:8000/health
```

The first request that reaches `RagAgent` will download the `BAAI/bge-small-en-v1.5`
embedding model (~130MB) from Hugging Face — this needs internet access once, then it's
cached under `~/.cache/huggingface`.

`RagAgent` only retrieves what's actually in Qdrant — with an empty knowledge base it
degrades gracefully to no evidence rather than fabricating any, but you want real results.
Run `npm run knowledge:ingest` and `npm run knowledge:embed` from `apps/backend` once this
service is up — see [Knowledge Base & RAG Agent
module](#knowledge-base--rag-agent-module) above for the full walkthrough.

**Optional but recommended — run Llama 3.1 locally via Ollama** so `LlmAnalystAgent`
produces real model output instead of its rule-based fallback:

```bash
# https://ollama.com/download
ollama pull llama3.1:8b-instruct-q4_K_M
ollama serve
```

Without Ollama running, the pipeline still completes — `LlmAnalystAgent` just falls back
to a deterministic template summary instead of calling the LLM.

**Optional — threat intel enrichment.** `ThreatIntelAgent` calls MISP / VirusTotal /
AlienVault OTX only if you set their API keys in `apps/ai-orchestrator/.env`
(`VIRUSTOTAL_API_KEY`, `OTX_API_KEY`, `MISP_URL` + `MISP_API_KEY`). Without keys, the
agent still extracts IOCs from the alert text, it just skips reputation lookups.

### Trigger the pipeline manually (before wiring a real SIEM)

```bash
curl -X POST http://localhost:8000/pipeline/run \
  -H "Content-Type: application/json" \
  -d '{"alert_id": "<an alert id from GET /api/v1/alerts>", "tenant_id": "00000000-0000-0000-0000-000000000001"}'
```

This runs all 9 agents end-to-end and writes results into `incidents`,
`threat_intel_iocs`, `mitre_mappings`, `risk_scores`, `decisions`, and `agent_results`.

---

## 8. Start the frontend dashboard

In another new terminal:

```bash
cd apps/frontend
npm run dev
```

Vite will print a local URL — by default:

**http://localhost:5173**

Open that in your browser. Log in with the seeded admin account:

```
Email:    admin@soar-platform.local
Password: ChangeMe123!
```

> Change this password immediately after first login — it's a seed default, not meant for
> production use.

The sidebar has five pages: **Alerts**, **Incidents**, **Threat Intel**, **Mitre Agent**,
and **RAG Agent**. Threat Intel is the lookup page from the [Threat Intelligence
module](#threat-intelligence-module) section above (`http://localhost:5173/threat-intelligence`);
Mitre Agent is the ATT&CK coverage dashboard from the [MitreAgent
module](#mitreagent-module) section (`http://localhost:5173/mitre-agent`); RAG Agent is
the retrieval-pipeline dashboard from the [Knowledge Base & RAG Agent
module](#knowledge-base--rag-agent-module) section (`http://localhost:5173/rag-agent`,
currently mock data — see that section). All pages only call the backend API; no analysis
logic runs in the browser.

---

## 9. (Optional) Import n8n workflows

The playbook workflow definitions live in `automation/n8n/workflows/`. Import them into
the running n8n instance:

1. Open http://localhost:5678
2. Go to **Workflows → Import from File**
3. Select each `.json` file in `automation/n8n/workflows/`
4. Activate the workflows you want live (e.g. `teams-notification.json`,
   `ticket-creation.json`)

Set `TEAMS_WEBHOOK_URL`, `TICKETING_API_URL`, `BACKEND_URL`, and `FRONTEND_URL` under
n8n's **Settings → Variables** before activating — the workflows reference them via
`$env`.

> **Status:** these workflows are importable and independently runnable, but the backend
> doesn't call them automatically yet — `N8nWorkflowEngineAdapter.ts` exists
> (`infrastructure/automation/`) but isn't wired into the pipeline's decision-handling
> flow. That's the next integration step.

## 10. Send a test alert through the full pipeline

The workflow is **Wazuh alert → Alert Inbox → SOC triage → Create Incident → AI analysis → Recommendation →
Response Ticket → IR decision (Manager approval or justified self-decision) → Start response → Re-hunt → Verification**.
Ingestion never opens an incident on its own — every alert (LOW, MEDIUM, HIGH or CRITICAL) waits in the Alert Inbox
until the SOC decides.

**1. Send a Wazuh-format alert** (the webhook stores it and returns `202` immediately):

```bash
curl -X POST http://localhost:4000/api/v1/webhooks/siem/wazuh   -H "Content-Type: application/json"   -d '{
    "timestamp": "2026-08-09T10:15:23.145+0700",
    "rule": { "level": 12, "description": "Suspicious PowerShell execution detected", "id": "100201", "mitre": { "id": ["T1059.001"], "tactic": ["Execution"] } },
    "agent": { "id": "003", "name": "WKS-TEST-01", "ip": "10.0.5.22" },
    "full_log": "powershell.exe -enc JABzAD0A... connecting to 185.220.101.5"
  }'
```

Response:

```json
{ "alertId": "...", "status": "received", "incidentId": null, "aiJob": null, "duplicate": false, "triageRequired": true }
```

**2. SOC triage** — sign in as `soc@soar-platform.local`, open **Alert Inbox → Awaiting triage** and either:

- mark it **False positive** (a reason is required), **Informational** or **Monitor** — no incident, audited; or
- **Create Incident** (choose the final incident severity; mixed-severity groups must be chosen explicitly). This opens
  the incident, queues the AI analysis (run by the [orchestration worker](#orchestration-worker-phase-4) from Step 6)
  and puts a *New incident* entry in the notification bell.

**3. Incident → Recommendation → IR.** On the incident, review Evidence / AI Analysis, generate the Recommendation, use
**Create response ticket** on a step, then **Email** the IR team. The IR team sees the ticket under **Response Tickets**
(the SOC follows progress read-only in the incident **Overview**).

**4. IR decision on the ticket.** If Policy requires approval, the ticket waits for the Policy approval chain. If it
does not, IR either presses **Request Manager approval** (reason required) or writes a **justification** and presses
**Start response** (audited as `IR_DECISION_WITHOUT_MANAGER`). Manager approval sends IR the full response process by
email and in the bell.

**5. Respond and verify.** IR presses **Start response**, performs the instructions, **Mark eradicated**, then
**Re-hunt**: VIGIX queries Wazuh again (or the mock provider when `REHUNT_PROVIDER=mock`). `NO_MATCH` → RESOLVED;
`MATCH` → NOT_RESOLVED and a new investigation cycle with the new evidence (earlier evidence is kept). After 3 rounds
without resolution the incident is **ESCALATED**. Only the IR team can start, complete or re-hunt — not SOC, Manager
or admin.

Check what arrived at any point:

```bash
curl http://localhost:4000/api/v1/incidents -H "Authorization: Bearer <token>"
```

---

## 11. Deploy ขึ้นเว็บ (Production: Linux server + Docker + Nginx + HTTPS)

Step 1-10 ด้านบนเป็นการรันแบบ **local dev** ส่วนนี้คือขั้นตอน deploy ขึ้น server จริงให้เข้าผ่าน
`https://your-domain.com` ได้ โครงสร้างหลัง deploy:

```
Browser ──HTTPS──> Nginx (:443, บน host)
                     ├─ /        → ไฟล์ static ของ dashboard (build จาก apps/ → /var/www/soar)
                     └─ /api/*   → soar-backend (container, 127.0.0.1:4000)
                                     ├─> soar-ai-orchestrator (container, 127.0.0.1:8000)
                                     └─> Postgres / Qdrant / Redis / n8n (docker compose)
```

Frontend เรียก API ด้วย path แบบ relative (`/api/...`) อยู่แล้ว ตอน dev ส่วนนี้ส่งต่อผ่าน proxy
ของ Vite ส่วนบน production ให้ Nginx ส่ง `/api` ต่อไปที่ backend แทน เพราะอยู่ domain เดียวกัน
จึงไม่ต้องตั้ง CORS และไม่ต้องใส่ URL ของ API ตอน build

> ทุกคำสั่งในส่วนนี้รัน **บน server** (Ubuntu 22.04/24.04) ยกเว้นที่เขียนไว้ว่า "บนเครื่อง dev"
> ให้แทน `your-domain.com`, `user@SERVER_IP` และรหัสผ่านทั้งหมดด้วยค่าจริง

### 11.1 สิ่งที่ต้องมีก่อน

- VPS/Cloud VM ที่เป็น Ubuntu, RAM **8 GB ขึ้นไป** ถ้าจะรัน MISP/Wazuh ด้วย
  (ถ้ารันแค่ Postgres/Qdrant/Redis/n8n ใช้ 4 GB ได้)
- Domain ที่ตั้ง DNS **A record** ชี้ไปที่ IP ของ server แล้ว
- Firewall/Security group ของ cloud provider เปิดแค่พอร์ต **22, 80, 443**

### 11.2 ติดตั้ง Docker, Node.js 20, Nginx และ Certbot

```bash
sudo apt update && sudo apt install -y ca-certificates curl git nginx certbot python3-certbot-nginx
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

เปิด firewall บน host (บล็อก 4000/8000 จากภายนอก เพราะ backend/orchestrator ใช้ `--network host`):

```bash
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw enable
```

### 11.3 Clone โค้ดและคัดลอกไฟล์ migration

```bash
sudo mkdir -p /opt/soar-platform && sudo chown $USER:$USER /opt/soar-platform
git clone https://github.com/your-org/soar-platform.git /opt/soar-platform
cd /opt/soar-platform
```

`.gitignore` ตัดไฟล์ `apps/backend/prisma/migrations/**/migration.sql` ออก ไฟล์ SQL เหล่านี้จึงไม่ได้มากับ
`git clone` ต้องคัดลอกจากเครื่อง dev ขึ้นไปเอง (**รันบนเครื่อง dev** ที่ root ของ repo):

```bash
scp -r apps/backend/prisma/migrations user@SERVER_IP:/opt/soar-platform/apps/backend/prisma/
```

### 11.4 ตั้งค่า infra (Postgres ฯลฯ) ให้ปลอดภัยก่อนรันครั้งแรก

1. **เปลี่ยนรหัสผ่าน Postgres** ใน `infra/docker/docker-compose.yml` (`POSTGRES_PASSWORD: soar_password`)
   ให้เสร็จ **ก่อน** `up` ครั้งแรก เพราะ Postgres อ่านค่านี้แค่ตอนสร้าง volume ครั้งแรกเท่านั้น
   ถ้าจะใช้ MISP ให้เปลี่ยน `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD`, `ADMIN_PASSWORD`, `GPG_PASSPHRASE`
   และ `BASE_URL` ด้วย
2. **อย่าเปิดพอร์ตฐานข้อมูลออก internet**: compose file publish พอร์ต 5432/6333/6379/5678/8880/8443
   ไว้บน `0.0.0.0` และ **Docker ข้ามกฎของ ufw** จึงต้องผูกพอร์ตไว้ที่ localhost:

   ```bash
   sed -i -E 's/- "([0-9]+:[0-9]+)"/- "127.0.0.1:\1"/' infra/docker/docker-compose.yml
   grep -n '127.0.0.1:' infra/docker/docker-compose.yml
   ```

3. เริ่ม infra ที่จำเป็น (`firewall-test-target` เป็น container ไว้ทดสอบเท่านั้น **ห้ามรันบน production**):

   ```bash
   docker compose -f infra/docker/docker-compose.yml up -d postgres qdrant redis n8n
   # (ถ้าใช้) MISP — boot ครั้งแรกใช้เวลาหลายนาที ดู Step 3 เรื่องการดึง API key
   docker compose -f infra/docker/docker-compose.yml up -d misp-db misp-redis misp-modules misp-core
   docker compose -f infra/docker/docker-compose.yml ps
   ```

   n8n และ MISP ไม่ได้เปิดออก internet แล้ว ถ้าต้องการเปิด UI ให้ใช้ SSH tunnel จากเครื่องตัวเอง:
   `ssh -L 5678:localhost:5678 -L 8443:localhost:8443 user@SERVER_IP` แล้วเปิด `http://localhost:5678`

### 11.5 สร้างไฟล์ `.env` ของแต่ละ app

```bash
cp apps/backend/.env.example apps/backend/.env
cp apps/ai-orchestrator/.env.example apps/ai-orchestrator/.env
openssl rand -hex 32      # ใช้ค่าที่ได้เป็น JWT_SECRET
nano apps/backend/.env
nano apps/ai-orchestrator/.env
```

ค่าที่ **ต้อง** แก้ใน `apps/backend/.env`:

| ตัวแปร | ค่าบน production |
|---|---|
| `DATABASE_URL` | `postgresql://soar:<รหัสใหม่จาก 11.4>@localhost:5432/soar_platform` |
| `JWT_SECRET` | ค่าจาก `openssl rand -hex 32` |
| `VIGIX_BASE_URL` | `https://your-domain.com` (ใช้สร้างลิงก์ในอีเมล/แจ้งเตือน) |
| `AI_ORCHESTRATOR_URL` | `http://localhost:8000` |
| `RECOMMENDATION_AGENT` | `llm` ถ้าต้องการใช้ AI จริง (`fake` = ค่าตายตัวไว้ demo) |
| `REHUNT_PROVIDER` | ลบ `mock` ออก / ตั้ง `wazuh` เมื่อเชื่อม Wazuh Indexer จริง |
| `EMAIL_*`, `DISCORD_WEBHOOK_URL`, `TELEGRAM_*`, `*_API_KEY` | ค่าจริง (ถ้าใช้) |

ใน `apps/ai-orchestrator/.env` ให้แก้ `DATABASE_URL` (รหัสใหม่เหมือนกัน) และ `LLM_BASE_URL`/`LLM_MODEL`/`LLM_API_KEY`
ให้ชี้ไป LLM ที่ใช้จริง (Ollama บน server เดียวกันใช้ `http://localhost:11434/v1` ได้เลยเพราะใช้ `--network host`)

`docker run --env-file` **ไม่ตัดเครื่องหมายคำพูด** (`KEY="value"` จะได้ค่าที่มี `"` ติดมาด้วย)
จึงต้องลบเครื่องหมายคำพูดออกจากทั้งสองไฟล์ก่อน (dotenv ยังอ่านไฟล์แบบไม่มีเครื่องหมายคำพูดได้ตามปกติ):

```bash
sed -i -E 's/^([A-Za-z_][A-Za-z0-9_]*)="(.*)"$/\1=\2/' apps/backend/.env apps/ai-orchestrator/.env
```

### 11.6 ติดตั้ง dependencies และ migrate database

```bash
cd /opt/soar-platform
npm ci
cd apps/backend
npx prisma generate
npx prisma migrate deploy
```

ใช้ `migrate deploy` เท่านั้น **ห้ามใช้ `migrate dev`** บน server: `migrate dev` เป็นคำสั่งสำหรับ dev
ซึ่งอาจ prompt ถามและใช้ shadow database

ถ้าเป็น database ใหม่ที่ยังว่าง ต้องมี user ไว้ login ก่อน โดย `npm run seed` จะสร้าง
`admin@soar-platform.local` / `ChangeMe123!` พร้อมข้อมูล demo (**รันครั้งเดียว แล้วเปลี่ยนรหัสทันที**)
อีกทางหนึ่งคือย้ายข้อมูลจากเครื่อง dev ด้วย `pg_dump` (**บนเครื่อง dev**) แล้ว restore บน server:

```bash
docker exec soar-postgres pg_dump -U soar -Fc soar_platform > soar_platform.dump
scp soar_platform.dump user@SERVER_IP:/tmp/
```

```bash
docker exec -i soar-postgres pg_restore -U soar -d soar_platform --clean --if-exists < /tmp/soar_platform.dump
```

### 11.7 Build และรัน backend + AI orchestrator (Docker)

`Dockerfile` ของทั้งสอง app ใช้ `COPY . .` แต่ยังไม่มี `.dockerignore` จึงต้องสร้างก่อน ไม่อย่างนั้น
`.env` (รหัสผ่าน/API key) และ `node_modules`/`.venv` ของ host จะถูก copy เข้าไปใน image:

```bash
cd /opt/soar-platform
printf "node_modules\ndist\n.env\n" > apps/backend/.dockerignore
printf ".venv\n__pycache__\n.env\n" > apps/ai-orchestrator/.dockerignore

docker build -t soar-backend:latest apps/backend
docker build -t soar-ai-orchestrator:latest apps/ai-orchestrator

docker run -d --name soar-ai-orchestrator --restart unless-stopped --network host \
  --env-file apps/ai-orchestrator/.env soar-ai-orchestrator:latest

docker run -d --name soar-backend --restart unless-stopped --network host \
  --env-file apps/backend/.env soar-backend:latest
```

AI analysis worker รันอยู่ใน process เดียวกับ backend แล้ว ไม่ต้องเปิด container แยก
(ถ้าต้องการปิด worker ให้ตั้ง `AI_WORKER_ENABLED=false`)

ตรวจสอบ:

```bash
curl http://localhost:4000/api/v1/health
curl http://localhost:8000/health
docker logs -f soar-backend
```

### 11.8 Build frontend (dashboard)

```bash
cd /opt/soar-platform
npm run build --workspace=apps
sudo mkdir -p /var/www/soar
sudo rsync -a --delete apps/dist/ /var/www/soar/
```

### 11.9 ตั้งค่า Nginx และ HTTPS

```bash
sudo tee /etc/nginx/sites-available/soar > /dev/null <<'EOF'
server {
    listen 80;
    server_name your-domain.com;

    root /var/www/soar;
    index index.html;
    client_max_body_size 20m;

    # API → backend (container, --network host)
    location /api/ {
        proxy_pass http://127.0.0.1:4000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;   # AI analysis อาจใช้เวลานาน
    }

    # Vue Router (history mode) — ทุก path ที่ไม่ใช่ไฟล์ให้ส่ง index.html
    location / {
        try_files $uri $uri/ /index.html;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/soar /etc/nginx/sites-enabled/soar
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl reload nginx

# ขอใบรับรอง HTTPS (Let's Encrypt) — certbot จะแก้ config ให้ redirect 80 → 443 อัตโนมัติ
sudo certbot --nginx -d your-domain.com
```

เปิด **https://your-domain.com** แล้ว login ได้เลย ตรวจ API ผ่าน domain ได้ด้วย:

```bash
curl https://your-domain.com/api/v1/health
```

ถ้า SIEM (Wazuh) ส่ง alert มาจากภายนอก ให้ชี้ webhook ไปที่
`https://your-domain.com/api/v1/webhooks/siem/wazuh`

### 11.10 อัปเดตเวอร์ชันใหม่ (redeploy)

```bash
cd /opt/soar-platform
git pull
# ถ้ามี migration ใหม่: scp โฟลเดอร์ migrations จากเครื่อง dev อีกครั้ง (ดู 11.3)

# backup DB ก่อน migrate ทุกครั้ง
mkdir -p backups
docker exec soar-postgres pg_dump -U soar -Fc soar_platform > backups/soar_$(date +%F_%H%M).dump

npm ci
(cd apps/backend && npx prisma migrate deploy)

docker build -t soar-backend:latest apps/backend
docker rm -f soar-backend
docker run -d --name soar-backend --restart unless-stopped --network host \
  --env-file apps/backend/.env soar-backend:latest

# ถ้า ai-orchestrator เปลี่ยนด้วย
docker build -t soar-ai-orchestrator:latest apps/ai-orchestrator
docker rm -f soar-ai-orchestrator
docker run -d --name soar-ai-orchestrator --restart unless-stopped --network host \
  --env-file apps/ai-orchestrator/.env soar-ai-orchestrator:latest

npm run build --workspace=apps
sudo rsync -a --delete apps/dist/ /var/www/soar/
```

### 11.11 Checklist ก่อนเปิดใช้งานจริง

- [ ] เปลี่ยนรหัส `admin@soar-platform.local` (seed default `ChangeMe123!`) และ user demo อื่นๆ
- [ ] `JWT_SECRET` เป็นค่าสุ่มยาว และรหัสผ่าน Postgres/MISP ไม่ใช่ค่า default ใน compose file
- [ ] `docker compose ps` แสดงพอร์ตเป็น `127.0.0.1:...` ทั้งหมด (ไม่มี `0.0.0.0`)
- [ ] `ufw status` เปิดแค่ 22/80/443 และ `curl http://SERVER_IP:4000` จากภายนอกต้องเข้าไม่ได้
- [ ] `REHUNT_PROVIDER` ไม่ใช่ `mock` และ `RECOMMENDATION_AGENT` ตั้งตามที่ต้องการ
- [ ] ตั้ง cron backup DB (เช่นคำสั่ง `pg_dump` ใน 11.10 ทุกวัน) และทดสอบ restore อย่างน้อยหนึ่งครั้ง
- [ ] backend ยังใช้ `app.use(cors())` แบบเปิดทุก origin ซึ่งไม่เป็นปัญหาเมื่อเข้าผ่าน Nginx domain เดียว
      แต่ถ้าจะเปิด API ให้ origin อื่นเรียก ควรจำกัด origin ก่อน

---

## Quick reference — daily startup order

Once everything is installed and seeded once, this is all you need each time you come back:

```bash
docker compose -f infra/docker/docker-compose.yml up -d   # infra (postgres, qdrant, n8n, redis, MISP)
cd apps/backend && npm run dev                              # terminal 1 — HTTP API (webhook, dashboard, etc.)
cd apps/backend && npm run worker:dev                        # terminal 2 — orchestration worker (Phase 4)
cd apps/ai-orchestrator && source .venv/bin/activate && uvicorn src.main:app --reload --port 8000   # terminal 3
cd apps/frontend && npm run dev                              # terminal 4
```

Then open **http://localhost:5173** (dashboard) or **http://localhost:4000/api-docs**
(Threat Intelligence API docs). MISP only needs its first-boot setup once — see
[Step 3](#3-start-infrastructure-services-postgres-qdrant-n8n-redis-misp) — after that,
`docker compose up -d` just starts the existing container again.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Error: P1001: Can't reach database server` | Docker isn't running, or Postgres container isn't up yet — run `docker compose ... ps` and wait a few seconds after `up -d` |
| `npm run seed` fails with "no such table" | You skipped `npx prisma migrate dev` — run it before seeding |
| Frontend loads but shows no data | Seed didn't run, or backend isn't reachable — check `apps/frontend/.env` points `VITE_API_URL` at `http://localhost:4000` |
| n8n webhooks not firing | Workflow isn't activated in the n8n editor — toggle it on (top-right switch) |
| Port already in use | Something else is using 4000/5173/8000/5678/5432/6333/8443 — stop it or change the port in `.env` |
| Threat Intel providers all show `DISABLED` | Expected if no API keys are set in `apps/backend/.env` — not a bug. Set `VIRUSTOTAL_API_KEY`/`ABUSEIPDB_API_KEY`/`MISP_API_KEY` to enable them |
| MISP: `403 Authentication failed` even with a key set | Check `docker compose logs misp-core \| grep -i redis` for `"Redis is not reachable."` — if present, `ENABLE_REDIS_EMPTY_PASSWORD` isn't taking effect; confirm it's set in `infra/docker/docker-compose.yml`'s `misp-core` service and recreate the container |
| MISP: key stops working after a restart | The compose file doesn't set a fixed key (MISP's "advanced authkeys" mode won't honor one reliably) — regenerate with the `cake User change_authkey 1` command from Step 3 and update `.env` |
| Backend `/analyze` errors with a self-signed-cert TLS error for MISP | `MISP_VERIFY_TLS` isn't set to `false` in `apps/backend/.env` |
| Mitre Agent dashboard shows "Cataloged techniques: 0" or an error banner | Backend isn't reachable, or `apps/backend/data/mitre/techniques/` is empty/missing — re-run `npm run mitre:sync` from `apps/backend` (see [MitreAgent module](#mitreagent-module)) |
| `knowledge:ingest` fails with `malformed frontmatter line (expected "key: value")` | A list field (`incidentTypes`, `mitreTechniques`, `tags`, ...) is written as a multi-line YAML block list (`key:\n  - item`) — the parser only supports single-line flow style. Rewrite it as `key: [item1, item2]` on one line |
| `knowledge:embed` fails with `Cannot copy out of meta tensor; no data!` | PyTorch/`transformers`/`accelerate` version mismatch in the AI orchestrator's Python environment. Run `pip install -U torch transformers accelerate sentence-transformers` and **fully restart** the `uvicorn` process (not just retry the request) |
| `knowledge:embed` reports `documents processed: 0` right after a failed run | The failed documents were marked `embeddingStatus: FAILED` and are excluded from the pending queue by design. Reset them once the underlying issue above is fixed: `UPDATE knowledge_documents SET embedding_status = 'PENDING' WHERE embedding_status = 'FAILED';` |
| RAG Agent dashboard shows a "Mock data" banner | Expected — `GET /api/v1/rag-agent/executions/latest` isn't implemented yet. See [Knowledge Base & RAG Agent module](#knowledge-base--rag-agent-module) |

---

## Stopping everything

```bash
docker compose -f infra/docker/docker-compose.yml down
```

Add `-v` to also wipe the Postgres/Qdrant/**MISP** volumes (full reset):

```bash
docker compose -f infra/docker/docker-compose.yml down -v
```

> With `-v`, MISP loses all its data (including any seeded events/attributes and the API
> key) — the first-boot setup in [Step 3](#3-start-infrastructure-services-postgres-qdrant-n8n-redis-misp)
> runs again next time you `up -d`.
# VIGIX-AI-Powered-SOC-Automation-Platform
