/**
 * Audit of human Playbook changes (Knowledge management). Implemented by the existing AuditLogger (audit_logs):
 * actor + timestamp are recorded for CREATE_PLAYBOOK, UPDATE_PLAYBOOK, ACTIVATE_PLAYBOOK, DEACTIVATE_PLAYBOOK and
 * DELETE_PLAYBOOK (with the reason and a full copy of the deleted playbook).
 */
export type PlaybookAuditAction = "CREATE_PLAYBOOK" | "UPDATE_PLAYBOOK" | "ACTIVATE_PLAYBOOK" | "DEACTIVATE_PLAYBOOK" | "DELETE_PLAYBOOK";

export interface IPlaybookAuditRecorder {
  record(input: {
    tenantId: string;
    actor: string;
    action: PlaybookAuditAction;
    entity: "Playbook";
    entityId: string;
    metadata?: Record<string, unknown>;
  }): Promise<void>;
}
