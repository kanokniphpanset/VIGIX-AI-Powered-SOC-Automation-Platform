import { QdrantClient } from "@qdrant/js-client-rest";

export interface VectorSearchResultRow {
  id: string | number;
  score: number;
  payload: Record<string, unknown> | null;
}

export interface QdrantFilter {
  must: { key: string; match: { any: (string | boolean)[] } }[];
}

/**
 * QdrantProvider — Node-side counterpart to apps/ai-orchestrator's
 * src/vectorstore/qdrant_provider.py (that Python class is never called by
 * anything today — confirmed by audit — so this is a NEW, separate
 * implementation for the Node backend, not a port of dead code). Thin
 * wrapper: nothing here decides what to index or how to rank results —
 * see VectorSearchService.ts for that.
 */
export class QdrantProvider {
  private readonly client: QdrantClient;

  constructor(url: string, private readonly vectorSize = 384) {
    this.client = new QdrantClient({ url, checkCompatibility: false });
  }

  async ensureCollection(collection: string): Promise<void> {
    const exists = await this.client.collectionExists(collection);
    if (!exists.exists) {
      await this.client.createCollection(collection, {
        vectors: { size: this.vectorSize, distance: "Cosine" },
      });
    }
  }

  async search(
    collection: string,
    vector: number[],
    limit: number,
    filter?: QdrantFilter,
    scoreThreshold?: number
  ): Promise<VectorSearchResultRow[]> {
    try {
      const result = await this.client.query(collection, {
        query: vector,
        limit,
        with_payload: true,
        filter,
        score_threshold: scoreThreshold,
      });
      return result.points.map((p) => ({ id: p.id, score: p.score, payload: (p.payload as Record<string, unknown>) ?? null }));
    } catch {
      // Collection doesn't exist yet (nothing indexed) — return no matches
      // rather than throwing, mirroring qdrant_provider.py's own
      // "degrade, don't crash" precedent for this exact situation.
      return [];
    }
  }

  async upsert(collection: string, pointId: string, vector: number[], payload: Record<string, unknown>): Promise<void> {
    await this.ensureCollection(collection);
    await this.client.upsert(collection, {
      points: [{ id: pointId, vector, payload }],
    });
  }
}
