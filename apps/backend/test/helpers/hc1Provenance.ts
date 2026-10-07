import { PrismaClient } from "@prisma/client";
import { randomUUID } from "node:crypto";
import { Playbook } from "../../src/domain/playbook/entities/Playbook.entity";
import { pinRevision } from "../../src/domain/playbook/PlaybookRevisionProvenance";
import { GenerationPlaybookCatalog } from "../../src/application/recommendation/ports/IGenerationPlaybookCatalogReader";

/** Explicit revision fixtures, never used by application code or to infer legacy provenance. */
export function fixtureCatalog(playbooks: Playbook[]): GenerationPlaybookCatalog {
  return {
    playbooks,
    pinSelected(code) {
      const p = playbooks.find(p => p.code === code)!;
      return pinRevision({ tenantId: p.tenantId, playbookId: p.id, revisionId: `fixture-revision-${p.id}`, version: p.version ?? "1.0",
        content: { code: p.code, name: p.name, description: p.description, version: p.version, playbookStatus: p.status,
          triggerConditions: p.triggerConditions, n8nWorkflowId: null, steps: p.steps.map(s => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })) } });
    },
  };
}

export async function publishedFixture(db: PrismaClient, tenantId: string, version = "1.0") {
  const code = `HC1-${randomUUID()}`;
  const content = { code, name: code, description: null, version, playbookStatus: "ACTIVE", n8nWorkflowId: null,
    triggerConditions: { scope: "INCIDENT", incidentType: code, mitreTechniques: ["T1110"], allowedActions: [] },
    steps: [{ stepOrder: 1, title: "Contain", description: null }] };
  return db.$transaction(async tx => {
    const playbook = await tx.playbook.create({ data: { tenantId, code, name: code, version, status: "ACTIVE", triggerConditions: content.triggerConditions, steps: { create: content.steps } } });
    const revision = await tx.playbookRevision.create({ data: { tenantId, playbookId: playbook.id, revisionNumber: 1, version, status: "PUBLISHED", content, createdBy: "hc1-human", publishedBy: "hc1-human", publishedAt: new Date() } });
    await tx.playbook.update({ where: { id: playbook.id }, data: { publishedRevisionId: revision.id } });
    return { code, playbook, revision, content, provenance: pinRevision({ tenantId, playbookId: playbook.id, revisionId: revision.id, version, content }) };
  });
}

/**
 * One playbook whose revisions carry the given versions, oldest first: the last one PUBLISHED (the pointer), every earlier
 * one SUPERSEDED with a publishedAt, as publish / rollback leave them. Returns the exact pinned provenance per version.
 */
export async function revisionHistoryFixture(db: PrismaClient, tenantId: string, versions: string[]) {
  const code = `HC1-${randomUUID()}`;
  const contentFor = (version: string) => ({ code, name: code, description: null, version, playbookStatus: "ACTIVE", n8nWorkflowId: null,
    triggerConditions: { scope: "INCIDENT", incidentType: code, mitreTechniques: ["T1110"], allowedActions: [] },
    steps: [{ stepOrder: 1, title: `Contain (${version})`, description: null }] });
  return db.$transaction(async tx => {
    const last = contentFor(versions[versions.length - 1]);
    const playbook = await tx.playbook.create({ data: { tenantId, code, name: code, version: last.version, status: "ACTIVE", triggerConditions: last.triggerConditions, steps: { create: last.steps } } });
    const provenance = new Map<string, ReturnType<typeof pinRevision>>();
    let publishedId = "";
    for (const [i, version] of versions.entries()) {
      const content = contentFor(version);
      const published = i === versions.length - 1;
      const revision = await tx.playbookRevision.create({ data: {
        tenantId, playbookId: playbook.id, revisionNumber: i + 1, version, status: published ? "PUBLISHED" : "SUPERSEDED", content,
        createdBy: "hc1-human", publishedBy: "hc1-human", publishedAt: new Date(Date.now() - (versions.length - i) * 1000) } });
      if (published) publishedId = revision.id;
      provenance.set(version, pinRevision({ tenantId, playbookId: playbook.id, revisionId: revision.id, version, content }));
    }
    await tx.playbook.update({ where: { id: playbook.id }, data: { publishedRevisionId: publishedId } });
    return { code, playbook, provenance };
  });
}
