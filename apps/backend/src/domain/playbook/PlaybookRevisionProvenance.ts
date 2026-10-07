import { createHash } from "node:crypto";

export type PlaybookProvenanceErrorCode =
  | "PLAYBOOK_PROVENANCE_MISMATCH"
  | "PLAYBOOK_PROVENANCE_TENANT_MISMATCH"
  | "PLAYBOOK_PROVENANCE_NOT_FOUND"
  | "PLAYBOOK_PROVENANCE_INVALID"
  | "RECOMMENDATION_INVESTIGATION_REQUIRED";

export class PlaybookProvenanceError extends Error {
  constructor(readonly code: PlaybookProvenanceErrorCode) { super(code); this.name = "PlaybookProvenanceError"; }
}

export interface PlaybookRevisionProvenance {
  readonly tenantId: string;
  readonly playbookId: string;
  readonly revisionId: string;
  readonly version: string;
  readonly content: unknown;
  readonly contentHash: string;
}

/** canonical-json-v1: JSON values only, lexical object keys, significant array order. */
export function canonicalRevisionContent(value: unknown): string {
  const ancestors = new Set<object>();
  const encode = (v: unknown): string => {
    if (v === null || typeof v === "string" || typeof v === "boolean") return JSON.stringify(v);
    if (typeof v === "number" && Number.isFinite(v)) return JSON.stringify(v);
    if (!v || typeof v !== "object" || ancestors.has(v)) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
    ancestors.add(v);
    let result: string;
    if (Array.isArray(v)) {
      if (Object.keys(v).length !== v.length || Object.getOwnPropertySymbols(v).length) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
      result = "[" + v.map(encode).join(",") + "]";
    } else {
      if (Object.getPrototypeOf(v) !== Object.prototype || Reflect.ownKeys(v).length !== Object.keys(v).length)
        throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
      result = "{" + Object.keys(v).sort().map(k => {
        const descriptor = Object.getOwnPropertyDescriptor(v, k)!;
        if (!('value' in descriptor)) throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
        return JSON.stringify(k) + ":" + encode(descriptor.value);
      }).join(",") + "}";
    }
    ancestors.delete(v);
    return result;
  };
  return encode(value);
}

export function hashRevisionContent(value: unknown): string {
  return "sha256:canonical-json-v1:" + createHash("sha256").update(canonicalRevisionContent(value), "utf8").digest("hex");
}

function freeze<T>(value: T): T {
  if (value && typeof value === "object") { Object.values(value).forEach(freeze); Object.freeze(value); }
  return value;
}

export function pinRevision(input: Omit<PlaybookRevisionProvenance, "contentHash">): PlaybookRevisionProvenance {
  if (![input.tenantId, input.playbookId, input.revisionId, input.version].every(v => typeof v === "string" && v.length > 0))
    throw new PlaybookProvenanceError("PLAYBOOK_PROVENANCE_INVALID");
  const content = JSON.parse(canonicalRevisionContent(input.content));
  return freeze({ ...input, content, contentHash: hashRevisionContent(content) });
}
