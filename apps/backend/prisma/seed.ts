/**
 * Seed script — populates demo data so the dashboard isn't empty on first login.
 * Run with: npm run seed   (wraps `prisma db seed`)
 */
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import { seedPolicies } from "./seeds/policy.seed";
import { seedActions } from "./seeds/action.seed";
import { seedRunbooks } from "./seeds/runbook.seed";
import { seedPlaybooks } from "./seeds/playbook.seed";

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

  // 2b. RBAC demo users — VIGIX has exactly two operational roles, SOC and IR_TEAM: the same
  // ResponsibleRole vocabulary the Policy Engine outputs
  // (see domain/policy/entities/PolicyEvaluationTypes.ts), so a real login
  // can be gated against the same roles Policy assigns responsibility to.
  const rbacUsers = [
    { email: "soc@soar-platform.local", role: "SOC" },
    { email: "irteam@soar-platform.local", role: "IR_TEAM" },
  ];
  for (const u of rbacUsers) {
    await prisma.user.upsert({
      where: { email: u.email },
      update: {},
      create: { tenantId: tenant.id, email: u.email, passwordHash, role: u.role },
    });
  }

  // 3. MITRE ATT&CK reference techniques (small sample set)
  const techniques = [
    { techniqueId: "T1566", name: "Phishing", tactic: "Initial Access" },
    { techniqueId: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
    { techniqueId: "T1078", name: "Valid Accounts", tactic: "Defense Evasion, Persistence, Privilege Escalation, Initial Access" },
    { techniqueId: "T1486", name: "Data Encrypted for Impact", tactic: "Impact" },
    // Techniques exercised by the 10-case mock attack suite (resources/mock-attacks/)
    { techniqueId: "T1110", name: "Brute Force", tactic: "Credential Access" },
    { techniqueId: "T1110.001", name: "Password Guessing", tactic: "Credential Access" },
    { techniqueId: "T1204.002", name: "Malicious File", tactic: "Execution" },
    { techniqueId: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
    { techniqueId: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
    { techniqueId: "T1068", name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
    { techniqueId: "T1098", name: "Account Manipulation", tactic: "Persistence, Privilege Escalation" },
    { techniqueId: "T1059.001", name: "PowerShell", tactic: "Execution" },
    { techniqueId: "T1547.001", name: "Registry Run Keys / Startup Folder", tactic: "Persistence, Privilege Escalation" },
  ];
  for (const t of techniques) {
    await prisma.mitreTechnique.upsert({
      where: { techniqueId: t.techniqueId },
      update: { name: t.name, tactic: t.tactic },
      create: t,
    });
  }

  // 4. Sample alert — created once; re-running the seed reuses the existing one.
  let alert = await prisma.alert.findFirst({
    where: { tenantId: tenant.id, siemSource: "wazuh", externalAlertId: "wazuh-demo-0001" },
  });
  if (!alert) {
    alert = await prisma.alert.create({
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
  }

  // 5. Sample incident derived from the alert — created once, together with its timeline row.
  let incident = await prisma.incident.findFirst({
    where: { tenantId: tenant.id, alertId: alert.id },
  });
  if (!incident) {
    incident = await prisma.incident.create({
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
  }

  // 6. Policy module — POL-001..POL-017 (Priority/Assignment/Approval/
  // Verification/Escalation). Idempotent — see prisma/seeds/policy.seed.ts.
  await seedPolicies(prisma, tenant.id);

  // 7. Recommendation/Response workflow catalogs — Runbook (RB-*), Action
  // Action Catalog, Playbook (STC-001). Idempotent by code.
  await seedRunbooks(prisma, tenant.id);
  await seedActions(prisma, tenant.id);
  await seedPlaybooks(prisma, tenant.id);

  console.log("Seed complete:");
  console.log(`  Tenant:  ${tenant.name} (${tenant.id})`);
  console.log(`  Admin:   ${admin.email} / ChangeMe123!`);
  console.log(`  RBAC demo users (same password): ${rbacUsers.map((u) => `${u.email} [${u.role}]`).join(", ")}`);
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
