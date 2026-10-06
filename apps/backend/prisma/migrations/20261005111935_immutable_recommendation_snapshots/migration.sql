-- DropIndex
DROP INDEX "playbook_snapshots_incident_id_investigation_number_key";

-- CreateIndex
CREATE INDEX "playbook_snapshots_incident_id_investigation_number_idx" ON "playbook_snapshots"("incident_id", "investigation_number");
