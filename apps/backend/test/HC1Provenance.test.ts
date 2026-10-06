import { canonicalRevisionContent, hashRevisionContent, pinRevision, PlaybookProvenanceError } from "../src/domain/playbook/PlaybookRevisionProvenance";

describe("HC1-10 canonical content", () => {
  test("same object with different recursive key order has the same hash", () => {
    expect(hashRevisionContent({ z: [1, { b: false, a: null }], a: "ไทย" })).toBe(hashRevisionContent({ a: "ไทย", z: [1, { a: null, b: false }] }));
    expect(hashRevisionContent({})).toMatch(/^sha256:canonical-json-v1:[0-9a-f]{64}$/);
  });
  test("different value and different array order change the hash", () => {
    expect(hashRevisionContent({ a: 1 })).not.toBe(hashRevisionContent({ a: 2 }));
    expect(hashRevisionContent([1, 2])).not.toBe(hashRevisionContent([2, 1]));
  });
  test.each([undefined, NaN, Infinity, new Date(), () => 1, BigInt(1), { a: undefined }, new Array(2)])("rejects unsupported value %p", value => {
    expect(() => canonicalRevisionContent(value)).toThrow(PlaybookProvenanceError);
  });
  test("rejects cycles, symbols and accessors", () => {
    const cyclic: Record<string, unknown> = {}; cyclic.self = cyclic;
    for (const value of [cyclic, { [Symbol()]: 1 }, { get a() { return 1; } }])
      expect(() => canonicalRevisionContent(value)).toThrow(PlaybookProvenanceError);
  });
  test("pin is an independent deeply frozen copy of the complete raw content", () => {
    const content = { steps: [{ order: 2 }, { order: 1 }], extra: "preserve" };
    const pin = pinRevision({ tenantId: "t", playbookId: "p", revisionId: "r", version: "1", content });
    content.steps[0].order = 9;
    expect(pin.content).toEqual({ steps: [{ order: 2 }, { order: 1 }], extra: "preserve" });
    expect(Object.isFrozen(pin)).toBe(true);
    expect(Object.isFrozen((pin.content as typeof content).steps[0])).toBe(true);
    expect(pin.contentHash).toBe(hashRevisionContent(pin.content));
  });
});
