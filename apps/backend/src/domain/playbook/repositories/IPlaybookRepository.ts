import { Playbook } from "../entities/Playbook.entity";

export interface CreatePlaybookData {
  tenantId: string;
  code: string | null;
  name: string;
  description: string | null;
  version: string | null;
  status: "ACTIVE" | "DEPRECATED" | null;
  steps: { stepOrder: number; title: string; description: string | null }[];
  /** triggerConditions.incidentType (applicable incident category); null/undefined = not set. */
  incidentType?: string | null;
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
  create(data: CreatePlaybookData): Promise<Playbook>;
  update(id: string, tenantId: string, data: UpdatePlaybookData): Promise<Playbook>;
  /** Playbook executions that reference this playbook (a foreign key: such a playbook cannot be deleted). */
  countExecutions(id: string): Promise<number>;
  /** Removes the playbook and its steps (one transaction). */
  delete(id: string, tenantId: string): Promise<void>;
}
