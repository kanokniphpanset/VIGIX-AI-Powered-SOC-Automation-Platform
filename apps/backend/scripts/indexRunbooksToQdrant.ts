/**
 * indexRunbooksToQdrant.ts — one-off/on-demand indexing script: reads every
 * Runbook row from Postgres, embeds a searchable text built from its
 * name/trigger/objective/procedure/verificationCriteria (via the AI
 * orchestrator's existing POST /embeddings/ endpoint), and upserts each
 * into Qdrant.
 *
 * Deliberately does NOT introduce a KnowledgeDocument model or a Markdown
 * ingestion pipeline (scope decision — see conversation record: Postgres
 * Runbook is the source of truth for this phase, not a new document
 * corpus). Safe to re-run any time a Runbook changes — upsert by the
 * Runbook's own id, never accumulates duplicates.
 *
 * Run with: npm run runbooks:index   (from apps/backend)
 * Requires: Postgres reachable, Qdrant reachable, ai-orchestrator running
 * (for the embedding call).
 */
import { PrismaClient } from "@prisma/client";
import { QdrantProvider } from "../src/infrastructure/vectorstore/QdrantProvider";

const prisma = new PrismaClient();

const AI_ORCHESTRATOR_URL = process.env.AI_ORCHESTRATOR_URL ?? "http://localhost:8000";
const QDRANT_URL = process.env.QDRANT_URL ?? "http://localhost:6333";
const COLLECTION = "knowledge_embeddings";
const EMBEDDING_VECTOR_SIZE = 384; // BAAI/bge-small-en-v1.5

/** RB-BRUTEFORCE-001 -> "BRUTE_FORCE", RB-NETWORK-001 -> "NETWORK_ATTACK", etc.
 * Never guesses beyond this fixed map — an unrecognized code segment is left
 * as-is rather than invented into a plausible-looking category. */
const CODE_SEGMENT_TO_INCIDENT_TYPE: Record<string, string> = {
  BRUTEFORCE: "BRUTE_FORCE",
  MALWARE: "MALWARE",
  RANSOMWARE: "RANSOMWARE",
  PHISHING: "PHISHING",
  NETWORK: "NETWORK_ATTACK",
};

function deriveIncidentType(code: string): string {
  const match = code.match(/^RB-([A-Z]+)-\d+$/);
  const segment = match?.[1] ?? "";
  return CODE_SEGMENT_TO_INCIDENT_TYPE[segment] ?? segment;
}

function buildSearchableContent(runbook: {
  name: string;
  trigger: string | null;
  objective: string | null;
  procedure: unknown;
  verificationCriteria: unknown;
}): string {
  const asStringArray = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
  const lines = [
    `Runbook: ${runbook.name}`,
    runbook.trigger ? `Trigger: ${runbook.trigger}` : null,
    runbook.objective ? `Objective: ${runbook.objective}` : null,
    "Procedure:",
    ...asStringArray(runbook.procedure).map((step, i) => `${i + 1}. ${step}`),
    "Verification:",
    ...asStringArray(runbook.verificationCriteria),
  ].filter((line): line is string => line !== null);
  return lines.join("\n");
}

async function embed(text: string): Promise<number[]> {
  const res = await fetch(`${AI_ORCHESTRATOR_URL}/embeddings/`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(`Embedding request failed: HTTP ${res.status} ${await res.text()}`);
  }
  const data = (await res.json()) as { embedding: number[]; dimension: number };
  if (data.dimension !== EMBEDDING_VECTOR_SIZE) {
    throw new Error(`Unexpected embedding dimension ${data.dimension}, expected ${EMBEDDING_VECTOR_SIZE}`);
  }
  return data.embedding;
}

async function main() {
  console.log(`Indexing Runbooks into Qdrant collection "${COLLECTION}"...`);

  const runbooks = await prisma.runbook.findMany({ where: { status: "ACTIVE" } });
  if (runbooks.length === 0) {
    console.log("No ACTIVE runbooks found — nothing to index.");
    return;
  }

  const qdrant = new QdrantProvider(QDRANT_URL, EMBEDDING_VECTOR_SIZE);

  for (const runbook of runbooks) {
    const content = buildSearchableContent(runbook);
    const vector = await embed(content);
    const incidentType = deriveIncidentType(runbook.code);

    await qdrant.upsert(COLLECTION, runbook.id, vector, {
      content,
      title: runbook.name,
      documentId: runbook.code,
      chunkId: null,
      metadata: {
        sourceType: "PLAYBOOK", // matches RagAgent.retrieve_playbooks()'s hard filter
        documentType: "RUNBOOK",
        runbookCode: runbook.code,
        incidentTypes: [incidentType],
        phase: "containment",
        sourceProvider: "INTERNAL",
        mitreTechniques: [], // honest: Runbook has no MITRE mapping data today
        tenantId: runbook.tenantId,
      },
    });

    console.log(`  Indexed ${runbook.code} (${runbook.name}) -> point ${runbook.id}`);
  }

  console.log(`Done. Indexed ${runbooks.length} runbook(s).`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
