import { Router } from "express";
import { DashboardController } from "../controllers/DashboardController";
import { authenticate } from "../middlewares/auth.middleware";

/** Mounted at /api/v1/dashboard. Read-only; any authenticated role. */
export function buildDashboardRoutes(controller: DashboardController): Router {
  const router = Router();
  router.get("/summary", authenticate, controller.summary);
  return router;
}
