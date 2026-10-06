import { PrismaClient } from "@prisma/client";
import { IGenerationPlaybookCatalogReader, GenerationPlaybookCatalog } from "../../../../application/recommendation/ports/IGenerationPlaybookCatalogReader";
import { canonicalRevisionContent, pinRevision, PlaybookProvenanceError } from "../../../../domain/playbook/PlaybookRevisionProvenance";
import { PlaybookMapper } from "../mappers/Playbook.mapper";

type Row = Parameters<typeof PlaybookMapper.toDomain>[0] & {
  revision: { id: string; tenantId: string; playbookId: string; version: string; status: string; publishedAt: string | null; content: unknown } | null;
};

/** Generation-only read; ordinary catalog readers and the selection algorithm are unchanged. */
export class PrismaGenerationPlaybookCatalogReader implements IGenerationPlaybookCatalogReader {
  constructor(private readonly prisma: PrismaClient) {}

  async read(tenantId: string): Promise<GenerationPlaybookCatalog> {
    // One PostgreSQL statement snapshot: never fetch the current pointer after reading selection content.
    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT p.id, p.tenant_id AS "tenantId", p.code, p.name, p.description, p.version, p.status,
        p.trigger_conditions AS "triggerConditions", p.n8n_workflow_id AS "n8nWorkflowId", p.published_revision_id AS "publishedRevisionId",
        COALESCE((SELECT jsonb_agg(jsonb_build_object('id', s.id, 'playbookId', s.playbook_id,
          'stepOrder', s.step_order, 'title', s.title, 'description', s.description))
          FROM playbook_steps s WHERE s.playbook_id = p.id), '[]'::jsonb) AS steps,
        CASE WHEN r.id IS NULL THEN NULL ELSE jsonb_build_object('id', r.id, 'tenantId', r.tenant_id,
          'playbookId', r.playbook_id, 'version', r.version, 'status', r.status, 'publishedAt', r.published_at, 'content', r.content) END AS revision
      FROM playbooks p LEFT JOIN playbook_revisions r
        ON r.id = p.published_revision_id AND r.tenant_id = p.tenant_id AND r.playbook_id = p.id
      WHERE p.tenant_id = ${tenantId}`;
    const playbooks = rows.map(PlaybookMapper.toDomain);
    return {
      playbooks,
      pinSelected(code) {
        const row = rows.find(p => p.code === code);
        const r = row?.revision;
        if (!row || !r) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_NOT_FOUND");
        if (row.tenantId !== tenantId || r.tenantId !== tenantId) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_TENANT_MISMATCH");
        const c = r.content as Record<string, unknown> | null;
        if (!c || typeof c !== "object" || Array.isArray(c)) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
        const steps = row.steps.map(s => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })).sort((a, b) => a.stepOrder - b.stepOrder);
        // Publication sorts the projection, but preserves the raw revision JSON (including its array order).
        if (!Array.isArray(c.steps) || c.steps.some(s => !s || typeof s !== "object" || !Number.isInteger(s.stepOrder)))
          throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
        const revisionSteps = c.steps.map(s => ({ stepOrder: s.stepOrder, title: s.title, description: s.description })).sort((a, b) => a.stepOrder - b.stepOrder);
        if (r.id !== row.publishedRevisionId || r.playbookId !== row.id || r.status !== "PUBLISHED" || !r.publishedAt ||
            r.version !== (row.version ?? "1.0") || c.code !== row.code || c.name !== row.name || c.description !== row.description ||
            c.version !== row.version || c.playbookStatus !== row.status || c.n8nWorkflowId !== row.n8nWorkflowId ||
            canonicalRevisionContent(c.triggerConditions) !== canonicalRevisionContent(row.triggerConditions) ||
            canonicalRevisionContent(revisionSteps) !== canonicalRevisionContent(steps))
          throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_MISMATCH");
        return pinRevision({ tenantId, playbookId: row.id, revisionId: r.id, version: r.version, content: r.content });
      },
    };
  }
}
