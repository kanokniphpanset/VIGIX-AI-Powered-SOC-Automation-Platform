import { Router } from "express";
import { AuthController } from "../controllers/AuthController";

/** Mounted at /api/auth (see main.ts). */
export function buildAuthRoutes(controller: AuthController): Router {
  const router = Router();
  router.post("/login", controller.login);
  return router;
}
