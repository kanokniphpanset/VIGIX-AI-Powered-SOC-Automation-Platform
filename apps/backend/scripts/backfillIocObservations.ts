/**
 * backfillIocObservations.ts - adds ioc_observations rows for IOCs that already exist, from the WAZUH_ALERT evidence they were
 * extracted for. DRY-RUN BY DEFAULT.
 *
 *   npx ts-node --transpile-only scripts/backfillIocObservations.ts                              # report only
 *   npx ts-node --transpile-only scripts/backfillIocObservations.ts --apply --confirm-database=<db name>
 *
 * Rules: it only INSERTS observations. It never creates, changes or deletes an IOC, evidence row or alert; an IOC the v2 extractor
 * would add but the investigation does not have is only counted ("missing IOC"). Existing observations are skipped, so re-running
 * is safe. --apply is refused unless --confirm-database matches the database in DATABASE_URL. Apply the migration
 * 20261008100000_ioc_observations first.
 */
import { PrismaClient } from "@prisma/client";
import { extractWazuhEvidenceV2 } from "../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { checkIocValue } from "../src/application/investigation/iocValidation";

const args = process.argv.slice(2);
const apply = args.includes("--apply");
const confirm = args.find((a) => a.startsWith("--confirm-database="))?.split("=")[1];
const dbName = new URL(process.env.DATABASE_URL ?? "postgresql://x/none").pathname.slice(1);

(async () => {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is not set");
  if (apply && confirm !== dbName) throw new Error(`--apply needs --confirm-database=${dbName} (the database in DATABASE_URL)`);
  const prisma = new PrismaClient();
  const stats = { evidence: 0, notWazuhOrUnreadable: 0, wouldCreate: 0, alreadyThere: 0, missingIoc: 0, invalidValue: 0 };
  const byRole: Record<string, number> = {};
  const byClass: Record<string, number> = {};
  try {
    const rows = await prisma.evidence.findMany({
      where: { type: "WAZUH_ALERT", alertId: { not: null } },
      select: { id: true, alertId: true, timestamp: true, investigationId: true, alert: { select: { id: true, externalAlertId: true, rawPayload: true, createdAt: true, siemSource: true } } },
    });
    for (const ev of rows) {
      stats.evidence++;
      const v2 = ev.alert && ev.alert.siemSource === "wazuh"
        ? extractWazuhEvidenceV2(ev.alert.rawPayload, { alertRowId: ev.alert.id, receivedAt: ev.alert.createdAt, externalAlertId: ev.alert.externalAlertId })
        : null;
      if (!v2 || v2.isFailure) { stats.notWazuhOrUnreadable++; continue; }
      for (const i of v2.value.iocs) {
        const checked = checkIocValue(i.type, i.value);
        if (!checked.ok) { stats.invalidValue++; continue; }
        const ioc = await prisma.threatIntelIoc.findFirst({ where: { investigationId: ev.investigationId, iocType: i.type, iocValue: checked.value }, select: { id: true } });
        if (!ioc) { stats.missingIoc++; continue; }
        const exists = await prisma.iocObservation.findFirst({ where: { iocId: ioc.id, alertId: ev.alertId, evidenceId: ev.id, sourcePath: i.sourcePath }, select: { id: true } });
        if (exists) { stats.alreadyThere++; continue; }
        stats.wouldCreate++;
        byRole[i.role] = (byRole[i.role] ?? 0) + 1;
        byClass[v2.value.provenance.class] = (byClass[v2.value.provenance.class] ?? 0) + 1;
        if (apply) {
          await prisma.iocObservation.create({
            data: { iocId: ioc.id, alertId: ev.alertId, evidenceId: ev.id, sourcePath: i.sourcePath, role: i.role, roleBasis: i.roleBasis, lastKnown: i.lastKnown, provenanceClass: v2.value.provenance.class, observedAt: ev.timestamp },
          });
        }
      }
    }
    console.log(JSON.stringify({ database: dbName, mode: apply ? "APPLY" : "DRY-RUN", ...stats, observationsToCreate: stats.wouldCreate, byRole, byProvenanceClass: byClass }, null, 2));
    if (!apply) console.log("Dry run: nothing was written.");
  } finally {
    await prisma.$disconnect();
  }
})().catch((e) => { console.error(e instanceof Error ? e.message : e); process.exit(1); });
