import { PrismaClient } from "@prisma/client";
import { IThreatIntelVerdictReader, ThreatIntelVerdict } from "../../../../application/incident/ports/IThreatIntelVerdictReader";

type Row = { output_contract: unknown };
type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : null);
const str = (v: unknown): string | null => (typeof v === "string" && v ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);

/** Maps one recorded `threatIntel.indicators[]` entry; entries without a type/value are skipped. */
export function toVerdict(raw: unknown, executionId: string | null): ThreatIntelVerdict | null {
  const i = obj(raw);
  const iocType = str(i?.iocType);
  const iocValue = str(i?.ioc);
  if (!i || !iocType || !iocValue) return null;
  const list = (v: unknown) => (Array.isArray(v) ? v.map(obj).filter((x): x is Obj => !!x) : []);
  return {
    iocType,
    iocValue,
    verdict: str(i.verdict),
    confidence: num(i.confidence),
    providers: list(i.providers).map((p) => ({ provider: str(p.provider) ?? "unknown", status: str(p.status) ?? "UNKNOWN", source: str(p.source) })),
    evidence: list(i.evidence).map((e) => ({ provider: str(e.provider) ?? "unknown", summary: str(e.summary), reference: str(e.reference) })),
    queriedAt: str(i.queriedAt),
    executionId: str(i.executionId) ?? executionId,
  };
}

/** Latest completed AI job of the incident that carries a Threat Intel report (read-only). */
export class PrismaThreatIntelVerdictReader implements IThreatIntelVerdictReader {
  constructor(private readonly prisma: PrismaClient) {}

  async latestVerdicts(incidentId: string): Promise<ThreatIntelVerdict[]> {
    const rows = await this.prisma.$queryRaw<Row[]>`
      SELECT output_contract FROM agent_executions
       WHERE incident_id = ${incidentId}
         AND status IN ('SUCCESS', 'PARTIAL_SUCCESS')
         AND output_contract->'threatIntel'->'indicators' IS NOT NULL
       ORDER BY coalesce(completed_at, started_at) DESC
       LIMIT 1`;
    const contract = obj(rows[0]?.output_contract);
    const indicators = obj(contract?.threatIntel)?.indicators;
    const executionId = str(contract?.executionId);
    return (Array.isArray(indicators) ? indicators : []).map((i) => toVerdict(i, executionId)).filter((v): v is ThreatIntelVerdict => !!v);
  }
}
