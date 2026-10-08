import { Router } from "express";
import { AuthController } from "../controllers/AuthController";
import { authenticate } from "../middlewares/auth.middleware";
import { asyncHandler } from "../middlewares/async-handler.middleware";

/** Mounted at /api/auth (see main.ts). change-password / change-email: the signed-in human's own account only (service tokens -> 403). */
export function buildAuthRoutes(controller: AuthController): Router {
  const router = Router();
  router.post("/login", controller.login);
  router.post("/change-password", authenticate, asyncHandler(controller.changePassword));
  router.post("/change-email", authenticate, asyncHandler(controller.changeEmail));
  return router;
}
