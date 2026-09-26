import { CreateEvidenceData, CreateIocData, EvidenceDetail, EvidenceRecord, InvestigationRecord, IocRecord } from "./Investigation.types";

/**
 * IInvestigationRepository — Investigation cycles plus the Evidence and IOCs that belong to them.
 * One aggregate port: an Evidence row and its IOC links are always written together.
 */
export interface IInvestigationRepository {
  /**
   * Idempotently makes the incident's investigation data consistent: a row for every cycle 1..N,
   * a WAZUH_ALERT evidence row per grouped alert in cycle #1, and cycle-less IOCs (written by the AI
   * orchestrator) assigned to cycle #1. Needed because the orchestrator creates incidents directly.
   */
  syncIncident(incidentId: string, tenantId: string): Promise<void>;

  listByIncident(incidentId: string, tenantId: string): Promise<InvestigationRecord[]>;
  findById(id: string, tenantId: string): Promise<InvestigationRecord | null>;

  listEvidence(investigationId: string): Promise<EvidenceRecord[]>;
  findEvidence(id: string, tenantId: string): Promise<EvidenceDetail | null>;
  createEvidence(data: CreateEvidenceData): Promise<EvidenceRecord>;

  listIocs(investigationId: string): Promise<IocRecord[]>;
  findIocsByIds(ids: string[], investigationId: string): Promise<IocRecord[]>;
  /** Throws DuplicateIocError when (investigation, type, value) already exists. */
  createIoc(data: CreateIocData): Promise<IocRecord>;
}
