-- HC-1: additive provenance only. Existing rows retain NULL; no historical backfill.
ALTER TABLE "playbook_snapshots"
  ADD COLUMN "playbook_id" TEXT,
  ADD COLUMN "playbook_revision_id" TEXT,
  ADD COLUMN "content_hash" TEXT,
  ADD COLUMN "frozen_revision_content" JSONB;

ALTER TABLE "playbook_snapshots"
  ADD CONSTRAINT "playbook_snapshots_playbook_id_fkey"
    FOREIGN KEY ("playbook_id") REFERENCES "playbooks"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT "playbook_snapshots_playbook_revision_id_fkey"
    FOREIGN KEY ("playbook_revision_id") REFERENCES "playbook_revisions"("id") ON DELETE RESTRICT ON UPDATE RESTRICT,
  ADD CONSTRAINT "playbook_snapshots_provenance_complete"
    CHECK (("playbook_id" IS NULL AND "playbook_revision_id" IS NULL AND "content_hash" IS NULL AND "frozen_revision_content" IS NULL)
      OR ("playbook_id" IS NOT NULL AND "playbook_revision_id" IS NOT NULL AND "content_hash" IS NOT NULL
        AND "frozen_revision_content" IS NOT NULL AND jsonb_typeof("frozen_revision_content") = 'object'
        AND "content_hash" ~ '^sha256:canonical-json-v1:[0-9a-f]{64}$'));

-- Ownership and tuple equality are also verified in the generation transaction before INSERT.
CREATE INDEX "playbook_snapshots_tenant_id_playbook_revision_id_idx" ON "playbook_snapshots"("tenant_id", "playbook_revision_id");
CREATE INDEX "playbook_snapshots_playbook_id_idx" ON "playbook_snapshots"("playbook_id");
