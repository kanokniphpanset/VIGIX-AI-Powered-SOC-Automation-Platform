import * as fs from "node:fs";
import * as path from "node:path";
import {
  ISiemRehuntPort,
  RehuntError,
  RehuntEvent,
  RehuntHealth,
  RehuntQuery,
  RehuntResult,
} from "../../../application/verification/ports/ISiemRehuntPort";
import { buildRehuntDsl } from "./WazuhIndexerAdapter";

/** FIXTURE = answer from resources/mock-attacks rounds; the others force that failure on every re-hunt. */
export type MockRehuntMode = "FIXTURE" | "ERROR" | "TIMEOUT" | "INDEXER_UNAVAILABLE";
export const MOCK_REHUNT_MODES: readonly MockRehuntMode[] = ["FIXTURE", "ERROR", "TIMEOUT", "INDEXER_UNAVAILABLE"];

/** repo-root/resources/mock-attacks, from src/ (ts-node) or dist/ (node). */
export const DEFAULT_MOCK_ATTACKS_DIR = path.resolve(__dirname, "../../../../../../resources/mock-attacks");

type Doc = Record<string, unknown>;
interface FixtureCase {
  id: string;
  file: string;
  alert: Doc;
  relatedAlerts: Doc[];
  rounds: Array<{ round: number; events: Doc[] }>;
}

function dig(o: unknown, dotted: string): unknown {
  return dotted.split(".").reduce<unknown>((n, k) => (n && typeof n === "object" ? (n as Doc)[k] : undefined), o);
}
const str = (v: unknown): string | null => (v === undefined || v === null ? null : String(v));

/**
 * MockRehuntAdapter — DEV/TEST ONLY implementation of ISiemRehuntPort, selected by REHUNT_PROVIDER=mock.
 * It never touches Wazuh. It answers a re-hunt from the deterministic fixture rounds in resources/mock-attacks
 * (each round's events are, by definition, post-containment — no wall-clock filtering), matching exactly like
 * the real Indexer query (buildRehuntDsl): an event matches when one of the queried IOC values appears as a
 * phrase in the indexer's IOC fields, or its rule.id equals the original detection's rule — on any host.
 * A match on a host outside `query.hosts` is spread.
 *
 * Safety: every failure is a RehuntError (mode ERROR -> QUERY_FAILED, TIMEOUT -> TIMEOUT, INDEXER_UNAVAILABLE ->
 * UNREACHABLE; no fixture / ambiguous fixture / missing round -> QUERY_FAILED). It never returns an empty
 * "clean" result for something it could not answer.
 */
export class MockRehuntAdapter implements ISiemRehuntPort {
  private cases: FixtureCase[] | null = null;
  private readonly iocFields: string[];

  constructor(
    private readonly mode: MockRehuntMode = "FIXTURE",
    private readonly fixtureDir: string = DEFAULT_MOCK_ATTACKS_DIR
  ) {
    const probe = buildRehuntDsl({ incidentId: "", responseId: "", hosts: [], iocs: [{ type: "ip", value: "x" }], timeRange: { start: new Date(0), end: new Date(0) } }) as {
      query: { bool: { should: Array<{ bool: { should: Array<{ multi_match: { fields: string[] } }> } }> } };
    };
    this.iocFields = probe.query.bool.should[0].bool.should[0].multi_match.fields;
  }

  isConfigured(): boolean {
    return true;
  }

  async health(): Promise<RehuntHealth> {
    const reachable = this.mode === "FIXTURE";
    return {
      configured: true,
      reachable,
      clusterStatus: reachable ? "mock" : undefined,
      indexPattern: "mock-attacks/*",
      alertIndices: reachable ? this.load().length : undefined,
      error: reachable ? undefined : `mock re-hunt forced mode ${this.mode}`,
    };
  }

  async rehunt(query: RehuntQuery): Promise<RehuntResult> {
    if (this.mode === "ERROR") throw new RehuntError("QUERY_FAILED", "Mock re-hunt: forced query error.");
    if (this.mode === "TIMEOUT") throw new RehuntError("TIMEOUT", "Mock re-hunt: forced timeout.");
    if (this.mode === "INDEXER_UNAVAILABLE") throw new RehuntError("UNREACHABLE", "Mock re-hunt: forced indexer unavailable.");

    const dsl = buildRehuntDsl(query);
    if (!dsl) throw new RehuntError("INSUFFICIENT_CRITERIA", "Re-hunt needs at least one IOC or the original detection rule.");

    const fixture = this.selectCase(query);
    const roundNumber = query.investigationNumber ?? 1;
    const round = fixture.rounds.find((r) => r.round === roundNumber);
    if (!round) throw new RehuntError("QUERY_FAILED", `Mock re-hunt: ${fixture.id} has no fixture round ${roundNumber}.`);

    const iocValues = query.iocs.map((i) => i.value.trim()).filter(Boolean);
    const known = new Set(query.hosts.map((h) => h.toLowerCase()));
    const ruleId = query.rule?.id ?? null;
    const ruleDescription = query.rule?.description ?? null;

    const matched: RehuntEvent[] = [];
    for (const doc of round.events) {
      const haystacks = this.iocFields.map((f) => dig(doc, f)).filter((v) => v !== undefined && v !== null).map((v) => String(v).toLowerCase());
      const hits = iocValues.filter((v) => haystacks.some((h) => h.includes(v.toLowerCase())));
      const docRule = str(dig(doc, "rule.id"));
      const byRule = ruleId ? docRule === ruleId : !!ruleDescription && String(dig(doc, "rule.description") ?? "").includes(ruleDescription);
      if (hits.length === 0 && !byRule) continue;
      matched.push({
        id: str(doc.id) ?? `${fixture.id}-r${roundNumber}-${matched.length}`,
        timestamp: str(doc["@timestamp"]) ?? str(doc.timestamp) ?? "",
        host: str(dig(doc, "agent.name")),
        agentId: str(dig(doc, "agent.id")),
        ruleId: docRule,
        ruleLevel: typeof dig(doc, "rule.level") === "number" ? (dig(doc, "rule.level") as number) : null,
        ruleDescription: str(dig(doc, "rule.description")),
        matchedIoc: hits.length > 0,
        matchedIocValues: hits,
      });
    }

    const affectedHosts = [...new Set(matched.map((e) => e.host).filter((h): h is string => !!h))];
    return {
      source: "MOCK_REHUNT",
      index: `mock-attacks/${fixture.file}#round-${roundNumber}`,
      query: JSON.stringify({ fixture: fixture.id, round: roundNumber, dsl }),
      timeRange: { start: query.timeRange.start.toISOString(), end: query.timeRange.end.toISOString() },
      matchingEvents: matched.length,
      affectedHosts,
      iocRecurrence: matched.some((e) => e.matchedIoc),
      spreadDetected: affectedHosts.some((h) => !known.has(h.toLowerCase())),
      threatContained: matched.length === 0,
      events: matched,
      truncated: false,
    };
  }

  /** The fixture whose ORIGINAL alert has this rule id on one of these hosts; IOC overlap breaks ties. */
  private selectCase(query: RehuntQuery): FixtureCase {
    const hosts = new Set(query.hosts.map((h) => h.toLowerCase()));
    const candidates = this.load().filter(
      (c) => (!query.rule?.id || str(dig(c.alert, "rule.id")) === query.rule.id) && hosts.has(String(dig(c.alert, "agent.name") ?? "").toLowerCase())
    );
    if (candidates.length === 0) throw new RehuntError("QUERY_FAILED", "Mock re-hunt: no fixture case matches this incident's detection rule and host.");
    const scored = candidates
      .map((c) => {
        const text = JSON.stringify([c.alert, ...c.relatedAlerts]).toLowerCase();
        return { c, score: query.iocs.filter((i) => i.value && text.includes(i.value.toLowerCase())).length };
      })
      .sort((a, b) => b.score - a.score);
    if (scored.length > 1 && scored[0].score === scored[1].score) {
      throw new RehuntError("QUERY_FAILED", `Mock re-hunt: ambiguous fixture (${scored.map((s) => s.c.id).join(", ")}).`);
    }
    return scored[0].c;
  }

  private load(): FixtureCase[] {
    if (this.cases) return this.cases;
    const out: FixtureCase[] = [];
    try {
      for (const dir of fs.readdirSync(this.fixtureDir, { withFileTypes: true }).filter((d) => d.isDirectory())) {
        for (const f of fs.readdirSync(path.join(this.fixtureDir, dir.name)).filter((x) => /^case-.*\.json$/.test(x))) {
          const raw = JSON.parse(fs.readFileSync(path.join(this.fixtureDir, dir.name, f), "utf-8")) as Doc;
          const rounds = (dig(raw, "rehunt.rounds") as Array<{ round: number; events: Doc[] }> | undefined) ?? [];
          out.push({ id: String(raw.id), file: `${dir.name}/${f}`, alert: raw.alert as Doc, relatedAlerts: (raw.relatedAlerts as Doc[]) ?? [], rounds });
        }
      }
    } catch (err) {
      throw new RehuntError("UNREACHABLE", `Mock re-hunt fixtures unavailable at ${this.fixtureDir}: ${err instanceof Error ? err.message : String(err)}`);
    }
    this.cases = out;
    return out;
  }
}
