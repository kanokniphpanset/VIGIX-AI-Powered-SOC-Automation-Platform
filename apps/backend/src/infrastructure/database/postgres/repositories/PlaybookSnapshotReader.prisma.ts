import { PrismaClient } from "@prisma/client";
import { IPlaybookSnapshotReader } from "../../../../application/incident/use-cases/ResponseGuide.usecases";

export class PrismaPlaybookSnapshotReader implements IPlaybookSnapshotReader {
  constructor(private readonly prisma: PrismaClient) {}

  async findPlaybook(snapshotId: string): Promise<{ code: string; version: string } | null> {
    const row = await this.prisma.playbookSnapshot.findUnique({ where: { id: snapshotId }, select: { playbookCode: true, playbookVersion: true } });
    return row ? { code: row.playbookCode, version: row.playbookVersion } : null;
  }
}
