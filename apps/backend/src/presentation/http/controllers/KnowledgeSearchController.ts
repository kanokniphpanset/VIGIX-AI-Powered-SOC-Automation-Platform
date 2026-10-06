import { Request, Response } from "express";
import { VectorSearchService } from "../../../application/knowledge/services/VectorSearchService";
import { vectorSearchSchema } from "../../../application/knowledge/dto/VectorSearchDto";
import { validateBody } from "../validators/validateBody";
import { authenticatedTenant } from "../middlewares/auth.middleware";

/**
 * KnowledgeSearchController — serves POST /api/v1/knowledge/search, the
 * read-only endpoint used by human callers and the orchestrator RagAgent.
 * The route authenticates humans or scoped services; tenant filtering is
 * always derived here from the authenticated principal.
 */
export class KnowledgeSearchController {
  constructor(private readonly vectorSearchService: VectorSearchService) {}

  search = async (req: Request, res: Response): Promise<void> => {
    const body = validateBody(vectorSearchSchema, req, res);
    if (!body) return;

    const results = await this.vectorSearchService.search({ ...body, filters: { ...body.filters, tenantId: [authenticatedTenant(req)] } });
    res.json({ results });
  };
}
