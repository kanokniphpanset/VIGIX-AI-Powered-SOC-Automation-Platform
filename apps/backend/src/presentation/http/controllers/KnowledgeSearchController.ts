import { Request, Response } from "express";
import { VectorSearchService } from "../../../application/knowledge/services/VectorSearchService";
import { vectorSearchSchema } from "../../../application/knowledge/dto/VectorSearchDto";
import { validateBody } from "../validators/validateBody";

/**
 * KnowledgeSearchController — serves POST /api/v1/knowledge/search, the
 * endpoint apps/ai-orchestrator's RagAgent (via vector_search_client.py)
 * has always expected to exist but, per audit, never actually did in this
 * repo. No authentication gate: this is the one surface an internal
 * service-to-service caller (the AI orchestrator) hits, analogous to
 * PolicyEvaluationController's own "AI/LLM callers only ever hit
 * /evaluate" precedent — it is read-only and cannot mutate anything.
 */
export class KnowledgeSearchController {
  constructor(private readonly vectorSearchService: VectorSearchService) {}

  search = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(vectorSearchSchema, req, res);
    if (!body) return;

    const results = await this.vectorSearchService.search(body);
    res.json({ results });
  };
}
