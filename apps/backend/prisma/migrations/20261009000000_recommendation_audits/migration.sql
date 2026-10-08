-- Additive: internal audit of the subtype-knowledge evaluation behind a Recommendation. No existing table or column changes.
CREATE TABLE "recommendation_audits" (
    "id" TEXT NOT NULL,
    "tenant_id" TEXT NOT NULL,
    "incident_id" TEXT NOT NULL,
    "recommendation_id" TEXT,
    "investigation_number" INTEGER NOT NULL,
    "mode" TEXT NOT NULL,
    "knowledge_version" TEXT NOT NULL,
    "knowledge_status" TEXT NOT NULL,
    "audit" JSONB NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "recommendation_audits_pkey" PRIMARY KEY ("id")
);

CREATE INDEX "recommendation_audits_incident_id_idx" ON "recommendation_audits"("incident_id");
CREATE INDEX "recommendation_audits_recommendation_id_idx" ON "recommendation_audits"("recommendation_id");

ALTER TABLE "recommendation_audits" ADD CONSTRAINT "recommendation_audits_recommendation_id_fkey" FOREIGN KEY ("recommendation_id") REFERENCES "recommendations"("id") ON DELETE SET NULL ON UPDATE CASCADE;
