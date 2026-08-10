# AI-Driven SOAR Automation Platform

Enterprise SOAR automation layer that ingests alerts from external SIEMs (Wazuh, Splunk,
Microsoft Defender, ELK), runs them through a multi-agent AI pipeline (LangGraph), and
drives automated/human-approved response through n8n.

> **Status note:** This README describes the setup flow for the project as designed in
> `docs/architecture/`. If your repo currently only contains the architecture docs and not
> yet the actual `apps/backend`, `apps/ai-orchestrator`, `apps/frontend` code, **Step 0**
> below (scaffolding) must be done first — every command after that assumes those files exist.

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
```

---

## 3. Start infrastructure services (Postgres, Qdrant, n8n, Redis)

This uses the Docker Compose file in `infra/docker/`.

```bash
docker compose -f infra/docker/docker-compose.yml up -d
```

Verify everything is healthy:

```bash
docker compose -f infra/docker/docker-compose.yml ps
```

You should see `postgres`, `qdrant`, `n8n`, and `redis` all with status `Up (healthy)`.

- Qdrant dashboard: http://localhost:6333/dashboard
- n8n editor: http://localhost:5678

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

---

## 7. Start the AI orchestrator (LangGraph service)

In a new terminal:

```bash
cd apps/ai-orchestrator
cp .env.example .env      # same monorepo gotcha as Prisma — this must live in apps/ai-orchestrator/
source .venv/bin/activate      # Windows: .venv\Scripts\activate
uvicorn src.main:app --reload --port 8000
```

Confirm it's up:

```bash
curl http://localhost:8000/health
```

The first request that reaches `RagAgent` will download the `BAAI/bge-small-en-v1.5`
embedding model (~130MB) from Hugging Face — this needs internet access once, then it's
cached under `~/.cache/huggingface`.

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

Simulate what Wazuh would send, end to end (ingestion → AI pipeline → incident):

```bash
curl -X POST http://localhost:4000/api/v1/webhooks/siem/wazuh \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-08-09T10:15:23.145+0700",
    "rule": { "level": 12, "description": "Suspicious PowerShell execution detected", "id": "100201" },
    "agent": { "id": "003", "name": "WKS-TEST-01", "ip": "10.0.5.22" },
    "full_log": "powershell.exe -enc JABzAD0A... connecting to 185.220.101.5"
  }'
```

This should: save the alert, create an incident, run all 9 AI agents (MitreAgent will
match "powershell" to T1059; ThreatIntelAgent will extract the IP `185.220.101.5` as an
IOC), and return the decision. Check the result:

```bash
curl http://localhost:4000/api/v1/incidents
```

---

## Quick reference — daily startup order

Once everything is installed and seeded once, this is all you need each time you come back:

```bash
docker compose -f infra/docker/docker-compose.yml up -d   # infra
cd apps/backend && npm run dev                              # terminal 1
cd apps/ai-orchestrator && source .venv/bin/activate && uvicorn src.main:app --reload --port 8000   # terminal 2
cd apps/frontend && npm run dev                              # terminal 3
```

Then open **http://localhost:5173**.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `Error: P1001: Can't reach database server` | Docker isn't running, or Postgres container isn't up yet — run `docker compose ... ps` and wait a few seconds after `up -d` |
| `npm run seed` fails with "no such table" | You skipped `npx prisma migrate dev` — run it before seeding |
| Frontend loads but shows no data | Seed didn't run, or backend isn't reachable — check `apps/frontend/.env` points `VITE_API_URL` at `http://localhost:4000` |
| n8n webhooks not firing | Workflow isn't activated in the n8n editor — toggle it on (top-right switch) |
| Port already in use | Something else is using 4000/5173/8000/5678/5432/6333 — stop it or change the port in `.env` |

---

## Stopping everything

```bash
docker compose -f infra/docker/docker-compose.yml down
```

Add `-v` to also wipe the Postgres/Qdrant volumes (full reset):

```bash
docker compose -f infra/docker/docker-compose.yml down -v
```
