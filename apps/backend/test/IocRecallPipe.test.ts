import { isExpectedIocPresent } from "../src/evaluation/iocRecall";
import { REAL_GROUND_TRUTH, resolveGroundTruth } from "../src/evaluation/groundTruthReal";

const stored = (...values: string[]) => values.map((iocValue) => ({ iocValue }));
const SHA = "c488c4fbeb112223e34b76b84e06e4d6a2dc1209a664ecda48d6feb4c4448d64";

describe("expected-IOC presence (harness B4: literal | inside an IOC value)", () => {
  it("Test 1: a COMMAND_LINE containing | is ONE value and is found when the complete value is stored", () => {
    const cmd = '/bin/sh -c "echo test | grep test"';
    expect(isExpectedIocPresent({ type: "command", value: cmd }, stored(cmd))).toBe(true);
  });
  it("the halves of a piped command are NOT enough (no partial credit)", () => {
    const cmd = '/bin/sh -c "echo test | grep test"';
    expect(isExpectedIocPresent({ type: "command", value: cmd }, stored('/bin/sh -c "echo test ', ' grep test"'))).toBe(false);
    expect(isExpectedIocPresent({ type: "command", value: cmd }, stored())).toBe(false);
  });
  it("Test 2: an ordinary value works as before (case-insensitive, exact)", () => {
    expect(isExpectedIocPresent({ type: "file", value: "/tmp/.cache/kworkerd" }, stored("/TMP/.cache/kworkerd"))).toBe(true);
    expect(isExpectedIocPresent({ type: "file", value: "/tmp/.cache/kworkerd" }, stored("/tmp/.cache/other"))).toBe(false);
  });
  it("Test 3: several expected IOCs are judged separately; the | stays literal in the command", () => {
    const cmd = '/bin/sh -c "echo test | grep test"';
    const expected = [{ type: "file", value: "/tmp/.cache/kworkerd" }, { type: "hash", value: SHA }, { type: "command", value: cmd }];
    const present = (have: string[]) => expected.filter((e) => !isExpectedIocPresent(e, stored(...have))).map((e) => e.type);
    expect(present(["/tmp/.cache/kworkerd", SHA, cmd])).toEqual([]);
    expect(present(["/tmp/.cache/kworkerd", cmd])).toEqual(["hash"]);
    expect(present(["/tmp/.cache/kworkerd", SHA])).toEqual(["command"]);
  });
  it("the one real alternatives list (user, @ATTEMPTED_USER) still means 'any of these users'", () => {
    const expected = { type: "user", value: "admin|oracle|test" };
    expect(isExpectedIocPresent(expected, stored("oracle"))).toBe(true);
    expect(isExpectedIocPresent(expected, stored("root"))).toBe(false);
  });
  it("Test 4: the actual TC-08 expected IOCs are all recognised against the stored set, command included", () => {
    const gt = resolveGroundTruth(REAL_GROUND_TRUTH.find((g) => g.caseId === "TC-08")!, { KWORKERD_SHA256: SHA });
    const command = gt.expectedIocs.find((e) => e.type === "command")!;
    expect(command.value).toContain("|");
    const have = stored(...gt.expectedIocs.map((e) => e.value));
    expect(gt.expectedIocs.filter((e) => !isExpectedIocPresent(e, have))).toEqual([]);
    // and it is the COMPLETE command that is required
    const withoutCommand = stored(...gt.expectedIocs.filter((e) => e.type !== "command").map((e) => e.value));
    expect(gt.expectedIocs.filter((e) => !isExpectedIocPresent(e, withoutCommand)).map((e) => e.type)).toEqual(["command"]);
  });
  it("every | in the real ground truth outside user entries is a literal (only TC-08's command)", () => {
    const piped = REAL_GROUND_TRUTH.flatMap((g) => g.expectedIocs.filter((e) => e.value.includes("|") || e.value === "@ATTEMPTED_USER").map((e) => `${g.caseId}:${e.type}`));
    expect(piped.sort()).toEqual(["TC-01:user", "TC-08:command"]);
  });
});
