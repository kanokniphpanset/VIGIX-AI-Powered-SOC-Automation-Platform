import { CreateIocUseCase } from "../src/application/investigation/use-cases/CreateIoc.usecase";
import { createIocSchema } from "../src/application/investigation/dto/InvestigationDtos";
import { ListRelatedAlertEvidenceUseCase, IRelatedAlertEvidenceReader, RelatedAlertQuery } from "../src/application/investigation/use-cases/RelatedAlertEvidence.usecase";
import { CreateIocData } from "../src/domain/investigation/Investigation.types";

/**
 * Related-alert evidence (E2E 2026-09-26, ATK-04): with 1 Alert = 1 Incident, the C2 indicator of the same malware sat
 * in ANOTHER alert/incident, so the re-hunt of the malware incident could not see it and resolved it wrongly.
 * The SOC may now record such an indicator on the incident WITH its provenance (source alert, reason, who, when) —
 * nothing is grouped or moved, and the value must really be in the source alert.
 */

const TENANT = "t1";
const MALWARE_ALERT = { agent: { name: "WKS-FIN-07" }, rule: { id: "87105", level: 12 }, data: { sha256: "61f0f070c5e6e8306a167aaf764b843a6fd337ca49a2f4f04b3e864b7cdb34eb" } };
const C2_ALERT = {
  agent: { name: "WKS-FIN-07" },
  rule: { id: "100321", level: 12, description: "Sysmon: process downloaded a payload from a known C2 host" },
  data: { dstip: "45.155.205.233", url: "http://vigix-mock-c2.net/stage2.bin", dns: { question: { name: "vigix-mock-c2.net" } } },
};

function setup() {
  const created: CreateIocData[] = [];
  const audits: Array<{ action: string; metadata: Record<string, unknown> }> = [];
  const investigations = {
    findById: async (id: string) => (id === "inv-1" ? { id: "inv-1", incidentId: "inc-malware", status: "ACTIVE" } : null),
    createIoc: async (data: CreateIocData) => {
      created.push(data);
      return { id: `ioc-${created.length}`, ...data, reputationScore: null, confidence: null, createdAt: new Date(), evidenceIds: [], sourceAlertId: data.sourceAlertId ?? null, addedReason: data.addedReason ?? null };
    },
  };
  const alerts = {
    findById: async (id: string, tenantId: string) =>
      id === "alert-c2" && tenantId === TENANT ? ({ id: "alert-c2", externalAlertId: "1790.c2", rawPayload: C2_ALERT } as never) : null,
  };
  const useCase = new CreateIocUseCase(investigations as never, { record: async (e: never) => void audits.push(e) } as never, alerts);
  const add = (body: Record<string, unknown>) =>
    useCase.execute({ tenantId: TENANT, investigationId: "inv-1", createdBy: "soc-user-1", body: createIocSchema.parse(body) });
  return { created, audits, add };
}

describe("IOC from a related alert — provenance, SOC-confirmed, grounded in the source alert", () => {
  it("records the indicator with sourceAlertId, reason and who added it; audited as IOC_ADDED_FROM_RELATED_ALERT", async () => {
    const { created, audits, add } = setup();
    const r = await add({ iocType: "IPV4", iocValue: "45.155.205.233", source: "SOC analyst (related Wazuh alert 1790.c2)", sourceAlertId: "alert-c2", reason: "Related C2 activity observed on the same endpoint" });
    expect(r.isSuccess).toBe(true);
    expect(created[0]).toMatchObject({ incidentId: "inc-malware", iocValue: "45.155.205.233", createdBy: "soc-user-1", sourceAlertId: "alert-c2", addedReason: "Related C2 activity observed on the same endpoint" });
    expect(audits[0]).toMatchObject({
      action: "IOC_ADDED_FROM_RELATED_ALERT",
      metadata: expect.objectContaining({ sourceAlertId: "alert-c2", sourceExternalAlertId: "1790.c2", reason: "Related C2 activity observed on the same endpoint", addedBy: "soc-user-1" }),
    });
  });

  it("refuses an indicator that is NOT in the source alert (no attribution without evidence)", async () => {
    const { created, add } = setup();
    const r = await add({ iocType: "IPV4", iocValue: "203.0.113.99", source: "SOC", sourceAlertId: "alert-c2", reason: "claimed related" });
    expect(r.isFailure && r.error.code).toBe("IOC_NOT_IN_SOURCE_ALERT");
    expect(created).toHaveLength(0);
  });

  it("refuses an unknown / other-tenant source alert", async () => {
    const { add } = setup();
    const r = await add({ iocType: "IPV4", iocValue: "45.155.205.233", source: "SOC", sourceAlertId: "alert-other-tenant", reason: "related C2" });
    expect(r.isFailure && r.error.code).toBe("SOURCE_ALERT_NOT_FOUND");
  });

  it("a reason is mandatory with sourceAlertId (request validation)", () => {
    expect(createIocSchema.safeParse({ iocType: "DOMAIN", iocValue: "vigix-mock-c2.net", source: "SOC", sourceAlertId: "alert-c2" }).success).toBe(false);
    expect(createIocSchema.safeParse({ iocType: "DOMAIN", iocValue: "vigix-mock-c2.net", source: "SOC", sourceAlertId: "alert-c2", reason: "same C2 domain" }).success).toBe(true);
  });

  it("an ordinary analyst IOC (no source alert) is unchanged: IOC_CREATED, no provenance fields", async () => {
    const { created, audits, add } = setup();
    const r = await add({ iocType: "IPV4", iocValue: "45.155.205.233", source: "SOC analyst" });
    expect(r.isSuccess).toBe(true);
    expect(created[0]).toMatchObject({ sourceAlertId: null, addedReason: null });
    expect(audits[0].action).toBe("IOC_CREATED");
  });
});

describe("Related-alert evidence list (read only, deterministic)", () => {
  const now = new Date("2026-09-26T08:00:00Z");
  function reader(rows: Array<{ id: string; rawPayload: unknown; receivedAt: Date; incidentId: string | null }>) {
    const queries: RelatedAlertQuery[] = [];
    const r: IRelatedAlertEvidenceReader = {
      incidentFacts: async (incidentId) =>
        incidentId === "inc-malware" ? { alertIds: ["alert-malware"], alerts: [{ rawPayload: MALWARE_ALERT, receivedAt: now }], iocValues: ["61f0f070c5e6e8306a167aaf764b843a6fd337ca49a2f4f04b3e864b7cdb34eb", "root"] } : null,
      candidates: async (q) => (queries.push(q), rows.map((x) => ({ ...x, externalAlertId: `ext-${x.id}`, severity: "high" }))),
    };
    return { r, queries };
  }

  it("queries the same host (±24 h) and the incident's specific indicators (±7 d), never its own alert", async () => {
    const { r, queries } = reader([]);
    await new ListRelatedAlertEvidenceUseCase(r).execute({ tenantId: TENANT, incidentId: "inc-malware" });
    const q = queries[0];
    expect(q.excludeAlertIds).toEqual(["alert-malware"]);
    expect(q.hosts).toEqual(["wks-fin-07"]);
    expect(q.hostTo.getTime() - q.hostFrom.getTime()).toBe(48 * 3600_000);
    expect(q.iocValues).toContain("61f0f070c5e6e8306a167aaf764b843a6fd337ca49a2f4f04b3e864b7cdb34eb");
    expect(q.iocValues).not.toContain("root"); // too generic to hunt by substring
  });

  it("lists the C2 alert with its indicators; the alert keeps its own incident (nothing grouped)", async () => {
    const { r } = reader([{ id: "alert-c2", rawPayload: C2_ALERT, receivedAt: new Date(now.getTime() + 3600_000), incidentId: "inc-c2" }]);
    const out = await new ListRelatedAlertEvidenceUseCase(r).execute({ tenantId: TENANT, incidentId: "inc-malware" });
    expect(out.isSuccess && out.value.items[0]).toMatchObject({
      alertId: "alert-c2",
      incidentId: "inc-c2",
      relation: ["SAME_HOST"],
      host: "WKS-FIN-07",
      iocs: expect.arrayContaining([
        expect.objectContaining({ iocType: "IPV4", value: "45.155.205.233", onIncident: false }),
        expect.objectContaining({ iocType: "DOMAIN", value: "vigix-mock-c2.net", onIncident: false }),
      ]),
    });
  });

  it("unknown incident -> INCIDENT_NOT_FOUND", async () => {
    const { r } = reader([]);
    const out = await new ListRelatedAlertEvidenceUseCase(r).execute({ tenantId: TENANT, incidentId: "nope" });
    expect(out.isFailure && out.error).toBe("INCIDENT_NOT_FOUND");
  });
});
