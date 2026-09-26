import { Request, Response } from "express";
import { ListMitreTechniquesUseCase } from "../../../application/mitre/use-cases/ListMitreTechniques.usecase";

export class MitreController {
  constructor(private readonly listMitreTechniques: ListMitreTechniquesUseCase) {}

  /** Shape consumed by the AI orchestrator's MitreKnowledgeBaseClient.get_catalog(). */
  listTechniques = async (_req: Request, res: Response): Promise<void> => {
    const techniques = await this.listMitreTechniques.execute();
    res.json({
      techniques: techniques.map((t) => ({
        techniqueId: t.techniqueId,
        name: t.name,
        tactics: t.tactics,
        description: t.description ?? "",
        detection: "",
      })),
    });
  };
}
