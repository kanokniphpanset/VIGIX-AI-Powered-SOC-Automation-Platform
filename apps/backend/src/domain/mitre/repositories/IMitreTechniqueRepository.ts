import { MitreTechnique } from "../entities/MitreTechnique.entity";

export interface IMitreTechniqueRepository {
  findAll(): Promise<MitreTechnique[]>;
}
