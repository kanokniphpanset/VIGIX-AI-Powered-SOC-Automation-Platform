/**
 * Playbook revision persistence for publish / rollback (Phase 1D). Every method must run inside the caller's
 * AtomicWorkflow transaction ("playbook" scope): lockPlaybook() is the first statement, assertPublicationConsistent()
 * the last one before COMMIT.
 */

export type PlaybookRevisionStatus = "DRAFT" | "IN_REVIEW" | "APPROVED" | "PUBLISHED" | "SUPERSEDED" | "REJECTED";

export interface PlaybookContentStep {
  stepOrder: number;
  title: string;
  description: string | null;
}

/** The immutable snapshot stored in playbook_revisions.content (the source of truth for that revision). */
export interface PlaybookContent {
  code: string | null;
  name: string;
  description: string | null;
  triggerConditions: Record<string, unknown>;
  n8nWorkflowId: string | null;
  playbookStatus: string | null;
  version: string | null;
  steps: PlaybookContentStep[];
}

/** The playbook row, read under FOR UPDATE. */
export interface LockedPlaybook {
  id: string;
  tenantId: string;
  code: string | null;
  publishedRevisionId: string | null;
}

export interface PlaybookRevisionRecord {
  id: string;
  tenantId: string;
  playbookId: string;
  revisionNumber: number;
  version: string;
  status: PlaybookRevisionStatus;
  content: unknown;
  createdBy: string;
  approvedBy: string | null;
  publishedBy: string | null;
  publishedAt: Date | null;
}

/** What the runtime read model (playbooks + playbook_steps) currently holds for one playbook. */
export interface PlaybookProjection {
  code: string | null;
  name: string;
  description: string | null;
  triggerConditions: unknown;
  n8nWorkflowId: string | null;
  status: string | null;
  version: string | null;
  steps: PlaybookContentStep[];
}

/** A revision as listed for a playbook's version history (Knowledge → Playbooks). */
export interface PlaybookRevisionSummary {
  id: string;
  revisionNumber: number;
  version: string;
  status: PlaybookRevisionStatus;
  content: unknown;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  publishedBy: string | null;
  publishedAt: Date | null;
}

export interface NewPlaybookRevision {
  tenantId: string;
  playbookId: string;
  revisionNumber: number;
  version: string;
  content: PlaybookContent;
  createdBy: string;
  proposalReason: string | null;
}

export interface IPlaybookRevisionRepository {
  /** SELECT … FROM playbooks WHERE id AND tenant_id FOR UPDATE — serializes publish / rollback per playbook (row lock only). */
  lockPlaybook(playbookId: string, tenantId: string): Promise<LockedPlaybook | null>;
  findRevision(revisionId: string, tenantId: string): Promise<PlaybookRevisionRecord | null>;
  /** All revisions of the playbook in the trusted tenant, oldest first. */
  listRevisions(playbookId: string, tenantId: string): Promise<PlaybookRevisionSummary[]>;
  /** A new DRAFT revision ("Create New Version"). */
  createDraftRevision(data: NewPlaybookRevision): Promise<PlaybookRevisionSummary>;
  /** Replaces a DRAFT revision's content / version; false when it is no longer a DRAFT (nothing written). */
  updateDraftContent(revisionId: string, version: string, content: PlaybookContent): Promise<boolean>;
  markSuperseded(revisionId: string): Promise<void>;
  markPublished(revisionId: string, publishedBy: string, publishedAt: Date): Promise<void>;
  setPublishedPointer(playbookId: string, revisionId: string): Promise<void>;
  /**
   * Writes the revision content into the runtime read model: playbooks fields + the full playbook_steps set. `status`
   * overrides content.playbookStatus — "DRAFT" keeps a never-published playbook's row out of selection while it mirrors
   * its draft.
   */
  projectContent(playbookId: string, version: string, content: PlaybookContent, status?: "DRAFT"): Promise<void>;
  readProjection(playbookId: string): Promise<PlaybookProjection>;
  /** SET CONSTRAINTS ALL IMMEDIATE: runs the deferred publication check now, so a violation reaches the caller. */
  assertPublicationConsistent(): Promise<void>;
}
