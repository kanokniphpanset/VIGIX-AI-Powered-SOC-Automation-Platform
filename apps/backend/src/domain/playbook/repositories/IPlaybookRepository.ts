import { Playbook } from "../entities/Playbook.entity";

/**
 * A new playbook (Phase 1D): the playbooks row is created as status DRAFT with no published revision, together with
 * revision 1 (DRAFT) holding the exact definition. Nothing becomes selectable until that revision is reviewed,
 * approved and published (PublishPlaybookRevisionUseCase).
 */
export interface CreatePlaybookData {
  tenantId: string;
  code: string | null;
  name: string;
  description: string | null;
  version: string;
  /** The status the playbook takes when this revision is published (revision content.playbookStatus). */
  publishedStatus: "ACTIVE" | "DEPRECATED";
  steps: { stepOrder: number; title: string; description: string | null }[];
  /** triggerConditions.incidentType (applicable incident category); null/undefined = not set. */
  incidentType?: string | null;
  /** Author of revision 1 (four-eyes: may not approve or publish it). */
  createdBy: string;
}

export interface CreatedPlaybookRevision {
  id: string;
  revisionNumber: number;
  status: "DRAFT";
  version: string;
}

export interface UpdatePlaybookData {
  name?: string;
  description?: string | null;
  version?: string | null;
  status?: "ACTIVE" | "DEPRECATED" | null;
  /** Sets triggerConditions.incidentType (null removes it); every other triggerConditions key is kept as is. */
  incidentType?: string | null;
  /** Replaces the response steps (the process for FUTURE recommendations; past ones keep their own snapshot). */
  steps?: { stepOrder: number; title: string; description: string | null }[];
}

export interface IPlaybookRepository {
  findById(id: string, tenantId: string): Promise<Playbook | null>;
  findByCode(code: string, tenantId: string): Promise<Playbook | null>;
  findAll(tenantId: string): Promise<Playbook[]>;
  /** Creates the DRAFT playbook and its DRAFT revision 1 in one transaction. */
  createDraft(data: CreatePlaybookData): Promise<{ playbook: Playbook; revision: CreatedPlaybookRevision }>;
  update(id: string, tenantId: string, data: UpdatePlaybookData): Promise<Playbook>;
  /** Playbook executions that reference this playbook (a foreign key: such a playbook cannot be deleted). */
  countExecutions(id: string): Promise<number>;
  /** Removes the playbook, its steps and its DRAFT revisions (one transaction); never a published / superseded revision. */
  delete(id: string, tenantId: string): Promise<void>;
  /**
   * Revision lifecycle state (Phase 1D): the published revision pointer and how many revisions exist. A published
   * playbook is a projection of its revision and may only change through publish / rollback. `historyCount` counts the
   * revisions that are not plain never-published drafts (published, superseded, or legacy review states).
   */
  revisionState(id: string, tenantId: string): Promise<{ publishedRevisionId: string | null; revisionCount: number; historyCount: number } | null>;
}
