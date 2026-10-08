import { resolve } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";

dotenv.config({ path: resolve(__dirname, "../.env") });
// Load after dotenv: the signing module reads JWT_SECRET at import time.
const { signServiceToken } = require("../src/presentation/http/middlewares/auth.middleware");

async function main() {
  const prisma = new PrismaClient();
  try {
    const tenants = await prisma.tenant.findMany({ select: { id: true } });
    const tenantId = process.argv[2] ?? (tenants.length === 1 ? tenants[0].id : undefined);
    if (!tenantId || !tenants.some(t => t.id === tenantId)) {
      throw new Error("Supply an existing tenant ID; automatic selection requires exactly one tenant.");
    }
    const token = signServiceToken({ id: "service:ai-rag", tenantId, scopes: ["knowledge:search"], jobIds: [] });
    const path = resolve(__dirname, "../../ai-orchestrator/.env");
    const original = readFileSync(path, "utf8");
    const line = `BACKEND_SERVICE_TOKEN=${token}`;
    const updated = /^BACKEND_SERVICE_TOKEN=.*$/m.test(original)
      ? original.replace(/^BACKEND_SERVICE_TOKEN=.*$/m, line)
      : `${original.trimEnd()}\n${line}\n`;
    writeFileSync(path, updated);
    console.log("Configured a tenant-scoped knowledge:search token (expires in 1 hour). Restart the AI orchestrator to load it.");
  } finally {
    await prisma.$disconnect();
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
