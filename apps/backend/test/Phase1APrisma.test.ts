import { readFileSync } from "node:fs";
import path from "node:path";
import { Prisma } from "@prisma/client";

test("generated model contract matches approved storage and Incident fields without a DB", () => {
  const source = readFileSync(path.join(__dirname, "../prisma/schema.prisma"), "utf8");
  const generated = readFileSync(require.resolve(".prisma/client/schema.prisma"), "utf8");
  const normalize = (s: string) => s.replace(/\/\/[^\n]*/g, "").replace(/\s+/g, "");
  expect(normalize(generated)).toBe(normalize(source));
  const models = Prisma.dmmf.datamodel.models;
  const draft = models.find(m => m.name === "ResponseTicketDraft")!;
  expect(draft.dbName).toBe("response_ticket_drafts");
  expect(draft.fields.find(f => f.name === "responseId")?.isUnique).toBe(true);
  expect(draft.fields.find(f => f.name === "checked")?.isList).toBe(true);
  expect(models.find(m => m.name === "Tenant")?.fields.some(f => f.name === "responseTicketDrafts")).toBe(true);
  expect(models.find(m => m.name === "ResponsePlan")?.fields.some(f => f.name === "draft")).toBe(true);
  expect(models.find(m => m.name === "Incident")?.fields.map(f => f.name)).toEqual(expect.arrayContaining(["incidentType", "responseGuidance"]));
});
