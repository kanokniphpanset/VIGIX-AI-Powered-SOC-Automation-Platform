import { Router } from "express";
import { IncidentController } from "../controllers/IncidentController";

export function buildIncidentRoutes(controller: IncidentController): Router {
  const router = Router();

  router.get("/", controller.list);
  router.get("/:id", controller.getById);
  router.get("/:id/timeline", controller.getTimeline);
  router.patch("/:id/status", controller.updateStatus);

  return router;
}
