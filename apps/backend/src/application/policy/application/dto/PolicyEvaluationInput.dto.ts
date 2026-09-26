import {
  PolicyEvaluationInput,
  SEVERITIES,
  ASSET_CRITICALITIES,
  ACTION_IMPACT_LEVELS,
  VERIFICATION_RESULTS,
} from "../../domain/entities/PolicyEvaluationTypes";

/**
 * PolicyEvaluationInputDto — validates the raw request body for
 * POST /policies/evaluate before it is handed to PolicyEvaluator.
 * PolicyEvaluationTypes.ts documents this file as the required validation
 * boundary: PolicyEvaluationInput itself is the already-validated shape,
 * so nothing downstream (PolicyMatcher, PolicyEvaluator) re-checks enums
 * or ranges.
 */
export class PolicyEvaluationInputDto {
  static validate(raw: Record<string, unknown>): PolicyEvaluationInput {
    const input: PolicyEvaluationInput = {};

    if (raw.severity !== undefined) {
      if (!SEVERITIES.includes(raw.severity as any)) {
        throw new Error(`severity must be one of ${SEVERITIES.join(", ")}`);
      }
      input.severity = raw.severity as PolicyEvaluationInput["severity"];
    }

    if (raw.riskScore !== undefined) {
      const score = Number(raw.riskScore);
      if (!Number.isFinite(score) || score < 0 || score > 100) {
        throw new Error("riskScore must be a number between 0 and 100");
      }
      input.riskScore = score;
    }

    if (raw.assetCriticality !== undefined) {
      if (!ASSET_CRITICALITIES.includes(raw.assetCriticality as any)) {
        throw new Error(`assetCriticality must be one of ${ASSET_CRITICALITIES.join(", ")}`);
      }
      input.assetCriticality = raw.assetCriticality as PolicyEvaluationInput["assetCriticality"];
    }

    if (raw.actionImpactLevel !== undefined) {
      if (!ACTION_IMPACT_LEVELS.includes(raw.actionImpactLevel as any)) {
        throw new Error(`actionImpactLevel must be one of ${ACTION_IMPACT_LEVELS.join(", ")}`);
      }
      input.actionImpactLevel = raw.actionImpactLevel as PolicyEvaluationInput["actionImpactLevel"];
    }

    if (raw.verificationResult !== undefined) {
      if (!VERIFICATION_RESULTS.includes(raw.verificationResult as any)) {
        throw new Error(`verificationResult must be one of ${VERIFICATION_RESULTS.join(", ")}`);
      }
      input.verificationResult = raw.verificationResult as PolicyEvaluationInput["verificationResult"];
    }

    if (raw.spreadDetected !== undefined) {
      if (typeof raw.spreadDetected !== "boolean") {
        throw new Error("spreadDetected must be a boolean");
      }
      input.spreadDetected = raw.spreadDetected;
    }

    if (raw.threatContained !== undefined) {
      if (typeof raw.threatContained !== "boolean") {
        throw new Error("threatContained must be a boolean");
      }
      input.threatContained = raw.threatContained;
    }

    if (Object.keys(input).length === 0) {
      throw new Error("evaluation input must include at least one field");
    }

    return input;
  }
}
