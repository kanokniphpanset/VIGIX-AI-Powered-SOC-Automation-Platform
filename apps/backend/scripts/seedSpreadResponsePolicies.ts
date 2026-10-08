import { resolve } from "node:path";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import { SPREAD_POLICIES } from "../prisma/seeds/policy.seed";

dotenv.config({ path: resolve(__dirname, "../.env") });

/** Creates only missing spread policies; never rewrites existing policy rules or published playbooks. */
async function main() {
  const prisma = new PrismaClient();
  try {
    const tenants = await prisma.tenant.findMany({ select: { id: true } });
    const tenantId = process.argv.slice(2).find(arg => !arg.startsWith("--")) ?? (tenants.length === 1 ? tenants[0].id : undefined);
    if (!tenantId || !tenants.some(t => t.id === tenantId)) throw new Error("Supply an existing tenant ID; automatic selection requires exactly one tenant.");
    const apply = process.argv.includes("--apply");
    for (const seed of SPREAD_POLICIES) {
      const outcome = await prisma.$transaction(async tx => {
        const existing = await tx.policy.findUnique({ where: { code: seed.code }, select: { tenantId: true } });
        if (existing && existing.tenantId !== tenantId) throw new Error(`Policy code ${seed.code} is already in use by another tenant.`);
        if (existing) return "PRESERVED";
        if (!apply) return "WOULD_CREATE";
        const policy = await tx.policy.create({ data: {
          tenantId, code: seed.code, name: seed.name, description: seed.description, type: seed.type, precedence: seed.precedence,
          rules: { create: seed.rules.map(rule => ({ condition: rule.condition, result: rule.result })) },
        } });
        await tx.auditLog.create({ data: {
          tenantId, actor: "seed:spread-response", action: "policy.created", entity: "Policy", entityId: policy.id,
          metadata: { code: seed.code, source: "SPREAD_POLICIES", creationOnly: true },
        } });
        return "CREATED";
      });
      console.log(`${seed.code}: ${outcome}`);
    }
    if (!apply) console.log("Preview only. Add --apply to create the missing policies.");
  } finally { await prisma.$disconnect(); }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
