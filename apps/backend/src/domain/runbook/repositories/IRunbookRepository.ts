import { Runbook } from "../entities/Runbook.entity";

export interface NewRunbookInput {
  tenantId: string;
  code: string;
  name: string;
  version: string;
  description: string | null;
  trigger: string | null;
  preconditions: string[];
  objective: string | null;
  procedure: string[];
  decisionPoints: string[];
  expectedResult: string | null;
  escalation: string | null;
  verificationCriteria: string[];
}

export interface UpdateRunbookInput {
  name?: string;
  version?: string;
  status?: "ACTIVE" | "DEPRECATED";
  description?: string | null;
  trigger?: string | null;
  preconditions?: string[];
  objective?: string | null;
  procedure?: string[];
  decisionPoints?: string[];
  expectedResult?: string | null;
  escalation?: string | null;
  verificationCriteria?: string[];
}

export interface IRunbookRepository {
  findById(id: string, tenantId: string): Promise<Runbook | null>;
  findByCode(code: string, tenantId: string): Promise<Runbook | null>;
  findByCodes(codes: string[], tenantId: string): Promise<Runbook[]>;
  findAll(tenantId: string): Promise<Runbook[]>;
  create(input: NewRunbookInput): Promise<Runbook>;
  update(id: string, tenantId: string, input: UpdateRunbookInput): Promise<Runbook>;
}
