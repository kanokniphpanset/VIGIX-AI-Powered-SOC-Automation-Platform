import { PrismaClient } from "@prisma/client";

/**
 * Single shared PrismaClient instance for the whole backend process.
 * Injected into repository implementations at the composition root (main.ts).
 */
export const prisma = new PrismaClient();
