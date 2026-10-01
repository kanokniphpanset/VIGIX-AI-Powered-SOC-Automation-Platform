import { PlaybookSelector } from "../src/application/recommendation/services/PlaybookSelector";
import { Playbook } from "../src/domain/playbook/entities/Playbook.entity";

const pb = (code: string, mitreTechniques: string[]): Playbook =>
  ({ code, name: code, version: "1.0", status: "ACTIVE", steps: [], triggerConditions: { scope: "INCIDENT", incidentType: code, mitreTechniques, allowedActions: [] } }) as unknown as Playbook;

// Mirrors the KB entries involved in the Real-Wazuh finding (TC-09).
const C2 = pb("PB-C2", ["T1071", "T1573", "T1571"]);
const EXFIL = pb("PB-DATA-EXFIL", ["T1041", "T1048", "T1567"]);

describe("PlaybookSelector — SIEM-asserted techniques outrank AI-inferred ones on a tie", () => {
  it("without the SIEM signal the old behaviour stands (tie -> code order -> PB-C2)", () => {
    expect(new PlaybookSelector().select([EXFIL, C2], ["T1048", "T1071.001"])?.code).toBe("PB-C2");
  });
  it("Wazuh asserted T1048, AI inferred T1071.001 on top: the tie goes to the playbook the SIEM's own technique matches", () => {
    expect(new PlaybookSelector().select([C2, EXFIL], ["T1048", "T1071.001"], ["T1048"])?.code).toBe("PB-DATA-EXFIL");
  });
  it("a strictly higher match count still wins regardless of the SIEM signal", () => {
    expect(new PlaybookSelector().select([C2, EXFIL], ["T1048", "T1041", "T1071.001"], ["T1071.001"])?.code).toBe("PB-DATA-EXFIL");
  });
  it("is independent of playbook row order", () => {
    const a = new PlaybookSelector().select([C2, EXFIL], ["T1048", "T1071.001"], ["T1048"])?.code;
    const b = new PlaybookSelector().select([EXFIL, C2], ["T1048", "T1071.001"], ["T1048"])?.code;
    expect(a).toBe(b);
  });
});
