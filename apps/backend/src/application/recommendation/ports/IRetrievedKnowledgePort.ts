import { RecommendationContextDto, RecommendationContextRetrievedKnowledge } from "../dto/RecommendationContextDto";

/**
 * Retrieves response knowledge (IR / Defense / analyst-approved case / threat intelligence) for an incident that no
 * attack-specific playbook covers. Optional: when no implementation is wired the context carries none, and an unknown
 * incident gets the investigation-only response.
 */
export interface IRetrievedKnowledgePort {
  retrieve(context: Pick<RecommendationContextDto, "incidentTitle" | "mitreMappings" | "evidence" | "iocs">): Promise<RecommendationContextRetrievedKnowledge[]>;
}
