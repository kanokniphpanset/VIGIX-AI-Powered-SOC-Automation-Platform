import { PrismaClient } from "@prisma/client";
import { IMitreTechniqueRepository } from "../../../../domain/mitre/repositories/IMitreTechniqueRepository";
import { MitreTechnique } from "../../../../domain/mitre/entities/MitreTechnique.entity";

export class PrismaMitreTechniqueRepository implements IMitreTechniqueRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findAll(): Promise<MitreTechnique[]> {
    const rows = await this.prisma.mitreTechnique.findMany({ orderBy: { techniqueId: "asc" } });
    return rows.map((r) => ({
      techniqueId: r.techniqueId,
      name: r.name,
      // `tactic` is a single column; multi-tactic techniques are stored comma-separated.
      tactics: r.tactic.split(",").map((t) => t.trim()).filter(Boolean),
      description: r.description,
    }));
  }
}
