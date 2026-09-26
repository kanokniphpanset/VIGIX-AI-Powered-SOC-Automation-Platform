import { Router } from "express";
import { MitreController } from "../controllers/MitreController";

/** Mounted at /api/v1/mitre. Read-only reference catalog. */
export function buildMitreRoutes(controller: MitreController): Router {
  const router = Router();
  router.get("/techniques", controller.listTechniques);
  return router;
}
