/**
 * Audit of human Playbook changes (Knowledge management). Implemented by the existing AuditLogger (audit_logs):
 * actor + timestamp are recorded for CREATE_PLAYBOOK, UPDATE_PLAYBOOK, ACTIVATE_PLAYBOOK, DEACTIVATE_PLAYBOOK and
 * DELETE_PLAYBOOK (with the reason and a full copy of the deleted playbook). Revision publication (Phase 1D) is audited on
 * the PlaybookRevision entity as PLAYBOOK_REVISION_CREATED / _UPDATED / _PUBLISHED / _SUPERSEDED / _ROLLED_BACK, in
 * the same transaction as the change.
 */
export type PlaybookAuditAction = "CREATE_PLAYBOOK" | "UPDATE_PLAYBOOK" | "ACTIVATE_PLAYBOOK" | "DEACTIVATE_PLAYBOOK" | "DELETE_PLAYBOOK";
export type PlaybookRevisionAuditAction =
  | "PLAYBOOK_REVISION_CREATED"
  | "PLAYBOOK_REVISION_UPDATED"
  | "PLAYBOOK_REVISION_PUBLISHED"
  | "PLAYBOOK_REVISION_SUPERSEDED"
  | "PLAYBOOK_REVISION_ROLLED_BACK";

export interface IPlaybookAuditRecorder {
  record(input: {
    tenantId: string;
    actor: string;
    action: PlaybookAuditAction | PlaybookRevisionAuditAction;
    entity: "Playbook" | "PlaybookRevision";
    entityId: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}
