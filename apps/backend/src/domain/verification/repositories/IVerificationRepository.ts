import { Verification, VerificationResult } from "../entities/Verification.entity";

export interface CreateVerificationData {
  tenantId: string;
  incidentId: string;
  responseId: string | null;
  wazuhIndex: string | null;
  query: string | null;
  timeRangeStart: Date | null;
  timeRangeEnd: Date | null;
  matchingEvents: number | null;
  affectedHosts: string[];
  iocRecurrence: boolean;
  spreadDetected: boolean;
  threatContained: boolean;
  beforeState: Record<string, unknown> | null;
  afterState: Record<string, unknown> | null;
  result: VerificationResult;
  notes: string | null;
  verifiedBy: string;
}

export interface IVerificationRepository {
  findById(id: string, tenantId: string): Promise<Verification | null>;
  findAllByIncident(incidentId: string, tenantId: string): Promise<Verification[]>;
  /** Tenant-wide, newest first — used to compute "already verified" for the Response Operations Dashboard. */
  findAll(tenantId: string, limit?: number, offset?: number): Promise<Verification[]>;
  create(data: CreateVerificationData): Promise<Verification>;
}
