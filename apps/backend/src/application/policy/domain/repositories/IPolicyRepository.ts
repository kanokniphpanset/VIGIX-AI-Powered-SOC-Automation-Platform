import { Policy } from "../entities/Policy.entity";
import { PolicyResultFragment } from "../entities/PolicyEvaluationTypes";
import { PolicyCondition } from "../entities/PolicyCondition";

export interface NewPolicyInput {
  tenantId: string;
  code: string;
  name: string;
  description: string | null;
  type: Policy["type"];
  precedence: number;
  rules: { condition: PolicyCondition; result: PolicyResultFragment }[];
}

export interface UpdatePolicyInput {
  name?: string;
  description?: string | null;
  precedence?: number;
  rules?: { condition: PolicyCondition; result: PolicyResultFragment }[];
}

/**
 * IPolicyRepository — port (interface) owned by the domain. The
 * infrastructure layer implements this (PrismaPolicyRepository.ts).
 * Application/domain code depends only on this interface, never on Prisma
 * directly — same convention as IIncidentRepository / IAlertRepository.
 */
export interface IPolicyRepository {
  findById(id: string, tenantId: string): Promise<Policy | null>;
  findByCode(code: string, tenantId: string): Promise<Policy | null>;
  findAll(tenantId: string): Promise<Policy[]>;
  /** Enabled policies (with only their enabled rules) — the only read the
   * evaluation endpoint is allowed to use. */
  findAllEnabled(tenantId: string): Promise<Policy[]>;
  create(input: NewPolicyInput): Promise<Policy>;
  update(id: string, tenantId: string, input: UpdatePolicyInput): Promise<Policy>;
  setEnabled(id: string, tenantId: string, enabled: boolean): Promise<Policy>;
}
