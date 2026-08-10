import { Router } from "express";
import { AlertController } from "../controllers/AlertController";

export function buildAlertRoutes(controller: AlertController): Router {
  const router = Router();

  router.get("/", controller.list);
  router.get("/:id", controller.getById);

  return router;
}
