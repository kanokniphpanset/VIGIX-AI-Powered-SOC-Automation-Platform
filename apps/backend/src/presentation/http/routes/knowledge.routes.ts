import { Router } from "express";
import { KnowledgeSearchController } from "../controllers/KnowledgeSearchController";
import { authenticateScopedRead } from "../middlewares/auth.middleware";

/** Mounted at /api/v1/knowledge (see main.ts). */
export function buildKnowledgeRoutes(controller: KnowledgeSearchController): Router {
  const router = Router();
  router.post("/search", authenticateScopedRead("knowledge:search"), controller.search);
  return router;
}
