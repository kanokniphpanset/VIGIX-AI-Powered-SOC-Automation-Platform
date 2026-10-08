import { RecommendationContextContainmentProcedure } from "../dto/RecommendationContextDto";

/**
 * Reads the attack-specific containment procedure (apps/knowledge/playbooks/PB-STC-001/procedures/<ATTACK_TYPE>/)
 * for the RecommendationContext. The YAML procedure is the source of truth for objective, strategy, ordered steps,
 * decisions and verification; the DB Playbook stays the source of truth for identity and allowedActions.
 * Returns null when no procedure exists for the attack type.
 */
export interface IContainmentProcedureReader {
  read(attackType: string): RecommendationContextContainmentProcedure | null;
}
