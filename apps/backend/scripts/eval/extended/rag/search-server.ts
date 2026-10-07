/**
 * search-server.ts — MINIMAL stand-in for the backend used ONLY by the RAG evaluation. It mounts the REAL
 * KnowledgeSearchController / VectorSearchService / QdrantProvider (POST /api/v1/knowledge/search, no auth in the
 * product either) against the ISOLATED evaluation Qdrant, and nothing else: every other path (e.g. the MITRE endpoints
 * the orchestrator also asks the backend for) gets the socket destroyed, so those agents behave as in the earlier
 * evaluations where the backend was unreachable. Every search request is appended to ./search-requests.jsonl.
 * Usage: QDRANT_URL=http://127.0.0.1:6335 PORT=4100 npx ts-node --transpile-only scripts/eval/extended/rag/search-server.ts
 */
import express from "express";
import * as fs from "node:fs";
import * as path from "node:path";
import { QdrantProvider } from "../../../../src/infrastructure/vectorstore/QdrantProvider";
import { VectorSearchService } from "../../../../src/application/knowledge/services/VectorSearchService";
import { KnowledgeSearchController } from "../../../../src/presentation/http/controllers/KnowledgeSearchController";

const QDRANT_URL = process.env.QDRANT_URL ?? "";
const PORT = Number(process.env.PORT ?? 4100);
if (!/:6335\b/.test(QDRANT_URL) && process.env.ALLOW_OTHER_QDRANT !== "1") throw new Error(`refusing to start: QDRANT_URL=${QDRANT_URL} is not the isolated evaluation Qdrant (:6335)`);
const LOG = path.join(__dirname, "..", "..", "..", "..", "..", "..", "results", "extended-evaluation", "logs", "rag-search-requests.jsonl");
fs.mkdirSync(path.dirname(LOG), { recursive: true });

const controller = new KnowledgeSearchController(new VectorSearchService(new QdrantProvider(QDRANT_URL, 384), "knowledge_embeddings"));
const app = express();
app.use(express.json({ limit: "2mb" }));
app.get("/health", (_q, r) => { r.json({ status: "ok", service: "vigix-rag-eval-search", qdrant: QDRANT_URL }); });
app.post("/api/v1/knowledge/search", (req, res, next) => {
  const b = req.body ?? {};
  fs.appendFileSync(LOG, JSON.stringify({ at: new Date().toISOString(), topK: b.topK, filters: b.filters ?? null, minScore: b.minScore ?? null, embeddingDim: Array.isArray(b.embedding) ? b.embedding.length : null }) + "\n");
  controller.search(req, res).catch(next);
});
app.use((req) => { req.socket.destroy(); });
app.use((err: Error, _q: express.Request, res: express.Response, _n: express.NextFunction) => { console.error("search error:", err.message); res.status(503).json({ error: "VECTOR_SEARCH_FAILED", message: err.message }); });
app.listen(PORT, "127.0.0.1", () => console.log(`rag-eval search server on http://127.0.0.1:${PORT} -> ${QDRANT_URL}`));
