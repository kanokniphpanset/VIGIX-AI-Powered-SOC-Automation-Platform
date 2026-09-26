# Knowledge

**Status: placeholder only (Phase 3). Not populated, no loader.**

The real Incident Response Knowledge Base (playbooks, SOPs, runbooks,
detection-rule docs, threat reports, lessons-learned — 13 Markdown files)
already lives at `apps/backend/data/knowledge/**/*.md`, gets ingested into
Postgres (`KnowledgeDocument` rows) and embedded into Qdrant via the
existing Knowledge Base module (see this repo's root README, "Knowledge
Base & RAG Agent module" section). It is already file-based and
git-versioned — exactly this resource system's goal — just under
`apps/backend/data/` rather than repo-root `resources/`.

Consolidating it into this folder is a later decision (it would mean
updating the ingestion pipeline's configured source directory), not an
urgent gap — the content is not hardcoded in source code today.
