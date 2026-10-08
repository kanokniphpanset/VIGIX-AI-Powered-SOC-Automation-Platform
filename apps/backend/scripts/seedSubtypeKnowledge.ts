import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { seedSubtypeKnowledge } from "../prisma/seeds/subtype.seed";

/**
 * Adds the subtype-knowledge Action / Runbook catalog rows (additive upserts). Run it ONLY against the database you intend to change:
 *   DATABASE_URL=<target db> npx ts-node scripts/seedSubtypeKnowledge.ts --tenant <tenant-id>
 * Without --tenant the demo tenant id is used. It never touches alerts, incidents or recommendations.
 */
async function main() {
  const i = process.argv.indexOf("--tenant");
  const tenantId = i > 0 ? process.argv[i + 1] : "00000000-0000-0000-0000-000000000001";
  const prisma = new PrismaClient();
  try {
    console.log(`seeding subtype knowledge into ${(process.env.DATABASE_URL ?? "").replace(/:\/\/[^@]*@/, "://***@")} for tenant ${tenantId}`);
    console.log(await seedSubtypeKnowledge(prisma, tenantId));
  } finally {
    await prisma.$disconnect();
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
