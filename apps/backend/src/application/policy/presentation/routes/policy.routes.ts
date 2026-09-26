import { Router } from "express";
import { IPolicyRepository } from "../../domain/repositories/IPolicyRepository";
import { PolicyController } from "../controllers/Policy.controller";
import { PolicyEvaluationController } from "../controllers/PolicyEvaluation.controller";
import { validateCreatePolicyBody, validateUpdatePolicyBody, validateEvaluatePolicyBody } from "../validators/Policy.validator";

/**
 * ASSUMPTION — Express Router. Wire this into the app with:
 *   app.use("/policies", buildPolicyRoutes(policyRepository));
 * where policyRepository is a PrismaPolicyRepository (or any other
 * IPolicyRepository implementation) constructed once at startup.
 */
export function buildPolicyRoutes(policyRepository: IPolicyRepository): Router {
  const router = Router();
  const policyController = new PolicyController(policyRepository);
  const evaluationController = new PolicyEvaluationController(policyRepository);

  router.get("/", policyController.list);
  router.get("/:id", policyController.get);
  router.post("/", validateCreatePolicyBody, policyController.create);
  router.patch("/:id", validateUpdatePolicyBody, policyController.update);
  router.post("/:id/enable", policyController.enable);
  router.post("/:id/disable", policyController.disable);

  router.post("/evaluate", validateEvaluatePolicyBody, evaluationController.evaluate);

  return router;
}
