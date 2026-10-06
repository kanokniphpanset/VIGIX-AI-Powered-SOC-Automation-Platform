import { IPlaybookRevisionRepository } from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";
import { IPlaybookAuditRecorder } from "../ports/IPlaybookAuditRecorder";
import { IPlaybookPublicationListener } from "../ports/IPlaybookPublicationListener";
import { PlaybookPublication, PlaybookPublicationError, PlaybookPublicationInput, PlaybookPublicationResult } from "./PlaybookPublication";

/**
 * Re-publishes a previously published (SUPERSEDED) revision (Phase 1D). Its content, version, revision number and
 * creator are never changed; only status, publishedBy (the rolling-back admin) and publishedAt (now). Same transaction,
 * projection and audit rules as publish. Must be wrapped with AtomicWorkflow ("playbook" scope).
 */
export class RollbackPlaybookRevisionUseCase {
  private readonly publication: PlaybookPublication;

  constructor(revisions: IPlaybookRevisionRepository, audit: IPlaybookAuditRecorder, listener?: IPlaybookPublicationListener) {
    this.publication = new PlaybookPublication(revisions, audit, listener);
  }

  execute(input: PlaybookPublicationInput): Promise<Result<PlaybookPublicationResult, PlaybookPublicationError>> {
    return this.publication.run("ROLLBACK", input);
  }
}
