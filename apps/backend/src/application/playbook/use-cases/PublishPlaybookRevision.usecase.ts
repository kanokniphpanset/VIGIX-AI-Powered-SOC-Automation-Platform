import { IPlaybookRevisionRepository } from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";
import { IPlaybookPublicationListener } from "../ports/IPlaybookPublicationListener";
import { PlaybookPublication, PlaybookPublicationError, PlaybookPublicationInput, PlaybookPublicationResult } from "./PlaybookPublication";

/**
 * Publishes an APPROVED revision (Phase 1D): the current PUBLISHED revision becomes SUPERSEDED, the target becomes
 * PUBLISHED, the playbook pointer moves and the revision content is projected into playbooks / playbook_steps. Only a
 * human admin who is neither the revision's creator may publish, and the approver must differ from the creator.
 * Must be wrapped with AtomicWorkflow ("playbook" scope).
 */
export class PublishPlaybookRevisionUseCase {
  private readonly publication: PlaybookPublication;

  constructor(revisions: IPlaybookRevisionRepository, audit: IPlaybookAuditRecorder, listener?: IPlaybookPublicationListener) {
    this.publication = new PlaybookPublication(revisions, audit, listener);
  }

  execute(input: PlaybookPublicationInput): Promise<Result<PlaybookPublicationResult, PlaybookPublicationError>> {
    return this.publication.run("PUBLISH", input);
  }
}
