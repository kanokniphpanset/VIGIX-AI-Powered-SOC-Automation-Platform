import { IPlaybookRepository } from "../../../domain/playbook/repositories/IPlaybookRepository";
import { IPlaybookRevisionRepository, PlaybookRevisionSummary } from "../../../domain/playbook/repositories/IPlaybookRevisionRepository";
import { Result } from "../../../shared/result/Result";

/** A playbook's version history in the trusted tenant (oldest first), for the Knowledge page. Read-only. */
export class ListPlaybookRevisionsUseCase {
  constructor(private readonly playbooks: IPlaybookRepository, private readonly revisions: IPlaybookRevisionRepository) {}

  async execute(input: { tenantId: string; id: string }): Promise<Result<{ publishedRevisionId: string | null; items: PlaybookRevisionSummary[] }, "NOT_FOUND">> {
    const state = await this.playbooks.revisionState(input.id, input.tenantId);
    if (!state) return Result.fail("NOT_FOUND");
    return Result.ok({ publishedRevisionId: state.publishedRevisionId, items: await this.revisions.listRevisions(input.id, input.tenantId) });
  }
}
