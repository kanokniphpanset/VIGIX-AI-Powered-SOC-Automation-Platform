import { Playbook } from "../../../domain/playbook/entities/Playbook.entity";
import { PlaybookRevisionProvenance } from "../../../domain/playbook/PlaybookRevisionProvenance";

/** A catalog and its revision tuples from the same database statement, scoped to one generation. */
export interface GenerationPlaybookCatalog {
  readonly playbooks: Playbook[];
  pinSelected(code: string): PlaybookRevisionProvenance;
}
export interface IGenerationPlaybookCatalogReader {
  read(tenantId: string): Promise<GenerationPlaybookCatalog>;
}
