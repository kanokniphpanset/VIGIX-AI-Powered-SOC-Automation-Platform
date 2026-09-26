import { IInvestigationRepository } from "../../../domain/investigation/IInvestigationRepository";
import { IIncidentRepository } from "../../../domain/incident/repositories/IIncidentRepository";
import { EvidenceDetail, EvidenceRecord, InvestigationRecord, IocRecord } from "../../../domain/investigation/Investigation.types";
import { Result } from "../../../shared/result/Result";

type In = { tenantId: string };

/** Read-only. Makes the incident's investigation data consistent first (see IInvestigationRepository.syncIncident). */
export class ListInvestigationsByIncidentUseCase {
  constructor(
    private readonly investigations: IInvestigationRepository,
    private readonly incidents: IIncidentRepository
  ) {}

  async execute(input: In & { incidentId: string }): Promise<Result<InvestigationRecord[], "INCIDENT_NOT_FOUND">> {
    const incident = await this.incidents.findById(input.incidentId, input.tenantId);
    if (!incident) return Result.fail("INCIDENT_NOT_FOUND");
    await this.investigations.syncIncident(input.incidentId, input.tenantId);
    return Result.ok(await this.investigations.listByIncident(input.incidentId, input.tenantId));
  }
}

export class GetInvestigationUseCase {
  constructor(private readonly investigations: IInvestigationRepository) {}

  async execute(input: In & { investigationId: string }): Promise<Result<InvestigationRecord, "INVESTIGATION_NOT_FOUND">> {
    const inv = await this.investigations.findById(input.investigationId, input.tenantId);
    return inv ? Result.ok(inv) : Result.fail("INVESTIGATION_NOT_FOUND");
  }
}

export class ListEvidenceUseCase {
  constructor(private readonly investigations: IInvestigationRepository) {}

  async execute(input: In & { investigationId: string }): Promise<Result<EvidenceRecord[], "INVESTIGATION_NOT_FOUND">> {
    const inv = await this.investigations.findById(input.investigationId, input.tenantId);
    if (!inv) return Result.fail("INVESTIGATION_NOT_FOUND");
    return Result.ok(await this.investigations.listEvidence(inv.id));
  }
}

export class GetEvidenceUseCase {
  constructor(private readonly investigations: IInvestigationRepository) {}

  async execute(input: In & { evidenceId: string }): Promise<Result<EvidenceDetail, "EVIDENCE_NOT_FOUND">> {
    const ev = await this.investigations.findEvidence(input.evidenceId, input.tenantId);
    return ev ? Result.ok(ev) : Result.fail("EVIDENCE_NOT_FOUND");
  }
}

export class ListIocsByInvestigationUseCase {
  constructor(private readonly investigations: IInvestigationRepository) {}

  async execute(input: In & { investigationId: string }): Promise<Result<IocRecord[], "INVESTIGATION_NOT_FOUND">> {
    const inv = await this.investigations.findById(input.investigationId, input.tenantId);
    if (!inv) return Result.fail("INVESTIGATION_NOT_FOUND");
    return Result.ok(await this.investigations.listIocs(inv.id));
  }
}
