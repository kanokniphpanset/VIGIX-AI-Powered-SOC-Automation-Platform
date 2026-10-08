import fs from "node:fs";
import path from "node:path";
import { extractWazuhEvidenceV2 } from "../src/domain/investigation/evidenceV2/extractWazuhEvidenceV2";
import { extractAlertIocs } from "../src/domain/investigation/alertIocs";
import { WazuhAdapter } from "../src/infrastructure/external-services/siem/WazuhAdapter";

/** resources/mock-attacks-tc-realshape: the real alerts with only an id and the vigix_custom group changed. */
const MOCK_DIR = path.resolve(__dirname, "../../../resources/mock-attacks-tc-realshape");
const REAL_DIR = path.join(__dirname, "fixtures", "wazuh-real");
const COUNTERPART: Record<string, string> = { "TC-01": "5712", "TC-02": "100301", "TC-03": "100310", "TC-04": "40112", "TC-05": "100300", "TC-06": "31103", "TC-07": "100320", "TC-08": "100330", "TC-09": "100340", "TC-10": "100350" };
const readJson = (p: string) => JSON.parse(fs.readFileSync(p, "utf8"));
const mockFile = (tc: string) => fs.readdirSync(MOCK_DIR).find((f) => f.startsWith(tc + "-"))!;
const realFile = (rule: string) => fs.readdirSync(REAL_DIR).find((f) => f.startsWith(rule + "-") && !f.includes(".v2."))!;
const ctx = { receivedAt: new Date("2026-10-08T00:00:00.000Z") };
const v2 = (p: unknown) => { const r = extractWazuhEvidenceV2(p, ctx); if (r.isFailure) throw new Error(r.error); return r.value; };

describe("real-shaped mock set", () => {
  it.each(Object.keys(COUNTERPART))("%s differs from its real alert only by id and the vigix_custom group", (tc) => {
    const mock = readJson(path.join(MOCK_DIR, mockFile(tc)));
    const real = readJson(path.join(REAL_DIR, realFile(COUNTERPART[tc])));
    const { id: _a, rule: mr, ...mockRest } = mock;
    const { id: _b, rule: rr, ...realRest } = real;
    expect(mockRest).toEqual(realRest);
    expect({ ...mr, groups: undefined }).toEqual({ ...rr, groups: undefined });
    expect(mr.groups).toEqual([...rr.groups, "vigix_custom"]);
    expect(mock.id).toMatch(/^1790000000.9100(0[1-9]|10)$/);
  });

  it.each(Object.keys(COUNTERPART))("%s is a MOCK_FIXTURE whose evidence equals the real alert's", (tc) => {
    const mock = v2(readJson(path.join(MOCK_DIR, mockFile(tc))));
    const real = v2(readJson(path.join(REAL_DIR, realFile(COUNTERPART[tc]))));
    expect(mock.provenance.class).toBe("MOCK_FIXTURE");
    expect(mock.evidence).toEqual(real.evidence);
    expect(mock.iocs).toEqual(real.iocs);
    expect(mock.detection.mitre).toEqual(real.detection.mitre);
    expect(mock.provenance.completeness).toEqual(real.provenance.completeness);
  });

  it("no longer hides the FIM gap: TC-02 yields the same (zero) legacy IOCs as the real alert, and v2 yields the path and hashes", () => {
    const mock = readJson(path.join(MOCK_DIR, mockFile("TC-02")));
    expect(mock.data).toBeUndefined();
    expect(extractAlertIocs(mock)).toEqual([]);
    expect(v2(mock).iocs.map((i) => i.sourcePath)).toEqual(expect.arrayContaining(["syscheck.path", "syscheck.sha256_after"]));
  });

  it("carries no field the real lab alerts lack (no GeoLocation, no Suricata keys)", () => {
    for (const tc of Object.keys(COUNTERPART)) {
      const m = readJson(path.join(MOCK_DIR, mockFile(tc)));
      expect(m.GeoLocation).toBeUndefined();
      expect(m.data?.dest_ip).toBeUndefined();
    }
  });

  it("is accepted by the production Wazuh adapter", () => {
    const adapter = new WazuhAdapter();
    for (const tc of Object.keys(COUNTERPART)) {
      const n = adapter.normalize(readJson(path.join(MOCK_DIR, mockFile(tc))));
      expect(n.siemSource).toBe("wazuh");
      expect(n.externalAlertId).toMatch(/^1790000000\./);
    }
  });
});
