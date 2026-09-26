import { Router } from "express";
import { AlertController } from "../controllers/AlertController";
import { authenticate } from "../middlewares/auth.middleware";

/** Mounted at /api/v1/alerts. RBAC foundation: read access requires any authenticated user. */
export function buildAlertRoutes(controller: AlertController): Router {
  const router = Router();

  router.get("/", authenticate, controller.list);
  // Alert Inbox read models — must be registered before "/:id".
  router.get("/inbox", authenticate, controller.inbox);
  router.get("/:id/view", authenticate, controller.view);

  router.post("/ingest", authenticate, controller.ingest);

  router.get("/:id", authenticate, controller.getById);

  return router;
}
