import { Router } from "express";
import { InAppNotificationController } from "../controllers/InAppNotificationController";
import { authenticate } from "../middlewares/auth.middleware";

/** Mounted at /api/v1/notifications — the header bell. Any signed-in role reads its own role's notifications. */
export function buildInAppNotificationRoutes(controller: InAppNotificationController): Router {
  const router = Router();
  router.get("/", authenticate, controller.list);
  router.post("/read", authenticate, controller.markRead);
  return router;
}
