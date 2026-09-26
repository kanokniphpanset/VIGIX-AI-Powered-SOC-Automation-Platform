import { z } from "zod";

/**
 * vectorSearchSchema — validates POST /api/v1/knowledge/search's body.
 * Shape matches apps/ai-orchestrator/src/agents/rag_agent/vector_search_client.py's
 * request exactly ({embedding, topK, minScore?, filters?}) — that Python
 * client is the only real caller this endpoint has today, so the contract
 * is theirs to define, not invented here.
 */
export const vectorSearchSchema = z
  .object({
    embedding: z.array(z.number()).min(1),
    topK: z.number().int().positive().max(50),
    minScore: z.number().min(0).max(1).optional(),
    filters: z.record(z.array(z.union([z.string(), z.boolean()]))).optional(),
  })
  .strict();

export type VectorSearchDto = z.infer<typeof vectorSearchSchema>;
