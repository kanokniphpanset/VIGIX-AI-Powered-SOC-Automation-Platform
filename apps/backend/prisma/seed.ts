/**
 * Seed script — populates demo data so the dashboard isn't empty on first login.
 * Run with: npm run seed   (wraps `prisma db seed`)
 */
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  console.log("Seeding AI-Driven SOAR Automation Platform demo data...");

  // 1. Tenant
  const tenant = await prisma.tenant.upsert({
    where: { id: "00000000-0000-0000-0000-000000000001" },
    update: {},
    create: {
      id: "00000000-0000-0000-0000-000000000001",
      name: "Demo SOC",
      plan: "standard",
    },
  });

  // 2. Admin user
  const passwordHash = await bcrypt.hash("ChangeMe123!", 10);
  const admin = await prisma.user.upsert({
    where: { email: "admin@soar-platform.local" },
    update: {},
    create: {
      tenantId: tenant.id,
      email: "admin@soar-platform.local",
      passwordHash,
      role: "admin",
    },
  });

  // 3. MITRE ATT&CK reference techniques (small sample set)
  const techniques = [
    { techniqueId: "T1566", name: "Phishing", tactic: "Initial Access" },
    { techniqueId: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    { techniqueId: "T1078", name: "Valid Accounts", tactic: "Defense Evasion" },
    { techniqueId: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
  ];
  for (const t of techniques) {
    await prisma.mitreTechnique.upsert({
      where: { techniqueId: t.techniqueId },
      update: {},
      create: t,
    });
  }

  // 4. Sample alert
  const alert = await prisma.alert.create({
    data: {
      tenantId: tenant.id,
      externalAlertId: "wazuh-demo-0001",
      siemSource: "wazuh",
      rawPayload: { rule: "Suspicious PowerShell execution", agent: "WKS-DEMO-01" },
      severity: "high",
      status: "received",
      receivedAt: new Date(),
    },
  });

  // 5. Sample incident derived from the alert
  const incident = await prisma.incident.create({
    data: {
      tenantId: tenant.id,
      alertId: alert.id,
      title: "Suspicious PowerShell execution on WKS-DEMO-01",
      status: "investigating",
      priority: "high",
    },
  });

  await prisma.incidentTimeline.create({
    data: {
      incidentId: incident.id,
      eventType: "created",
      description: "Incident created from Wazuh alert",
      actor: "system",
    },
  });

  console.log("Seed complete:");
  console.log(`  Tenant:  ${tenant.name} (${tenant.id})`);
  console.log(`  Admin:   ${admin.email} / ChangeMe123!`);
  console.log(`  Alert:   ${alert.externalAlertId}`);
  console.log(`  Incident: ${incident.title}`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
