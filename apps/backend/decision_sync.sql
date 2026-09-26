-- AlterTable
ALTER TABLE "decisions" ADD COLUMN     "approval_requirement" JSONB,
ADD COLUMN     "approval_tier" TEXT,
ADD COLUMN     "asset_criticality" TEXT,
ADD COLUMN     "audit_trace" JSONB,
ADD COLUMN     "conditions" JSONB,
ADD COLUMN     "confidence" DOUBLE PRECISION,
ADD COLUMN     "correlation_id" TEXT,
ADD COLUMN     "evidence_summary" JSONB,
ADD COLUMN     "execution_id" TEXT,
ADD COLUMN     "execution_mode" TEXT,
ADD COLUMN     "expiration_time" TIMESTAMP(3),
ADD COLUMN     "policy_provenance" JSONB,
ADD COLUMN     "policy_registry_version" TEXT,
ADD COLUMN     "primary_asset_id" TEXT,
ADD COLUMN     "priority" TEXT,
ADD COLUMN     "reasons" JSONB,
ADD COLUMN     "recommended_actions" JSONB;

