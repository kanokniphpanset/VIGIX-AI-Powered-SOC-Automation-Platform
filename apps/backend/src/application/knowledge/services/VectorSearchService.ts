import { QdrantProvider, QdrantFilter } from "../../../infrastructure/vectorstore/QdrantProvider";

export interface VectorSearchResultItem {
  id: string;
  score: number;
  content: string;
  title: string | null;
  documentId: string | null;
  chunkId: string | null;
  metadata: Record<string, unknown>;
}

/**
 * VectorSearchService — the ONE place that turns a caller-supplied
 * embedding into ranked Qdrant results. Referenced by name in
 * apps/ai-orchestrator/src/agents/rag_agent/vector_search_client.py's own
 * docstring and this repo's root README ("Knowledge Base & RAG Agent
 * module") — audit confirmed neither this class nor the collection it
 * reads ever actually existed in this repo before now.
 *
 * Does NOT embed anything itself — RagAgent (Python) embeds its own query
 * in-process (BgeEmbeddingProvider) before calling this over HTTP; this
 * service only searches Qdrant with the vector it's given. Does not decide
 * relevance thresholds or re-ranking either (RagAgent's reranker.py/
 * config.py own that) — `minScore` here is a raw Qdrant score_threshold
 * passthrough, not a business decision.
 */
export class VectorSearchService {
  constructor(
    private readonly qdrant: QdrantProvider,
    private readonly collection: string
  ) {}

  async search(input: {
    embedding: number[];
    topK: number;
    minScore?: number;
    filters?: Record<string, (string | boolean)[]>;
  }): Promise<VectorSearchResultItem[]> {
    const qdrantFilter = this.buildFilter(input.filters);

    const rows = await this.qdrant.search(this.collection, input.embedding, input.topK, qdrantFilter, input.minScore);

    return rows.map((row) => {
      const payload = row.payload ?? {};
      return {
        id: String(row.id),
        score: row.score,
        content: typeof payload.content === "string" ? payload.content : "",
        title: typeof payload.title === "string" ? payload.title : null,
        documentId: typeof payload.documentId === "string" ? payload.documentId : null,
        chunkId: typeof payload.chunkId === "string" ? payload.chunkId : null,
        metadata: (payload.metadata as Record<string, unknown>) ?? {},
      };
    });
  }

  /** Qdrant's own filter DSL — buildFilter() referenced by name in
   * knowledge_base_client.py's comment ("QdrantVectorSearchService.ts").
   * Every key becomes a match-any clause; an empty/absent filters object
   * means no filtering at all (never a 0-result trap). */
  private buildFilter(filters?: Record<string, (string | boolean)[]>): QdrantFilter | undefined {
    if (!filters || Object.keys(filters).length === 0) return undefined;
    const must = Object.entries(filters)
      .filter(([, values]) => values.length > 0)
      .map(([key, values]) => ({ key: `metadata.${key}`, match: { any: values } }));
    return must.length > 0 ? { must } : undefined;
  }
}
