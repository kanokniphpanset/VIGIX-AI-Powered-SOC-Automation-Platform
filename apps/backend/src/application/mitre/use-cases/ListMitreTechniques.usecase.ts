import { IMitreTechniqueRepository } from "../../../domain/mitre/repositories/IMitreTechniqueRepository";
import { MitreTechnique } from "../../../domain/mitre/entities/MitreTechnique.entity";

export class ListMitreTechniquesUseCase {
  constructor(private readonly mitreTechniqueRepository: IMitreTechniqueRepository) {}

  async execute(): Promise<MitreTechnique[]> {
    return this.mitreTechniqueRepository.findAll();
  }
}
