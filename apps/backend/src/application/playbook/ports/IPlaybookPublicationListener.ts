/**
 * Optional post-commit notification of a publish / rollback. Wire it through AtomicWorkflow.defer(listener, ["published"]),
 * so it runs only after the publication transaction committed; it must not change business state.
 */
export interface PlaybookPublishedEvent {
  tenantId: string;
  playbookId: string;
  revisionId: string;
  /** null for the first publish of a playbook created as a DRAFT. */
  previousRevisionId: string | null;
  version: string;
  kind: "PUBLISH" | "ROLLBACK";
  actor: string;
}

export interface IPlaybookPublicationListener {
  published(event: PlaybookPublishedEvent): Promise<void>;
}
