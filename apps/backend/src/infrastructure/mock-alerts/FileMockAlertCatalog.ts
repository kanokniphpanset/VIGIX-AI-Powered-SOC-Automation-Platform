import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { MockAlertCase, MockAlertSet } from "../../domain/alert/mockAlerts";

export interface MockAlertFixture extends MockAlertCase {
  /** The raw Wazuh alert exactly as written in the file (test data — goes through normal normalization). */
  alert: Record<string, unknown>;
}

export interface IMockAlertCatalog {
  list(): MockAlertFixture[];
  find(key: string): MockAlertFixture | null;
}

/** First existing resources/ folder: MOCK_ALERTS_DIR, the repo root relative to this file, or relative to the cwd. */
function resourcesDir(): string | null {
  const candidates = [
    process.env.MOCK_ALERTS_DIR,
    path.resolve(__dirname, "../../../../../resources"), // apps/backend/src/infrastructure/mock-alerts → repo root
    path.resolve(process.cwd(), "../../resources"), // cwd apps/backend
    path.resolve(process.cwd(), "resources"),
  ].filter((p): p is string => !!p);
  return candidates.find((p) => existsSync(path.join(p, "mock-attacks-tc")) || existsSync(path.join(p, "mock-attacks"))) ?? null;
}

const obj = (v: unknown): Record<string, unknown> | null => (v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : typeof v === "number" ? String(v) : null);
const ACRONYMS: Record<string, string> = { sql: "SQL", ssh: "SSH", powershell: "PowerShell", rdp: "RDP", c2: "C2" };
/** "sql-injection" → "SQL injection", "powershell" → "PowerShell" (file / folder names → display titles). */
const titleCase = (slug: string) =>
  slug.split("-").map((w) => ACRONYMS[w.toLowerCase()] ?? w).join(" ").replace(/^[a-z]/, (c) => c.toUpperCase());

function toCase(key: string, set: MockAlertSet, file: string, alert: Record<string, unknown>, title: string, attackType: string): MockAlertFixture {
  const rule = obj(alert.rule) ?? {};
  const level = Number(rule.level);
  return {
    key, set, file, alert, title, attackType,
    fixtureAlertId: str(alert.id),
    ruleId: str(rule.id),
    ruleLevel: Number.isFinite(level) ? level : null,
    ruleDescription: str(rule.description),
    host: str(obj(alert.agent)?.name),
  };
}

/**
 * Reads the mock fixtures from resources/ once (at construction). A file that cannot be read or parsed is skipped with a
 * warning — one broken fixture must not take the catalog down. Nothing here sends or stores anything.
 */
export class FileMockAlertCatalog implements IMockAlertCatalog {
  private readonly cases: MockAlertFixture[];

  constructor(dir: string | null = resourcesDir()) {
    this.cases = dir ? [...this.loadTc(dir), ...this.loadAtk(dir)] : [];
    if (!dir) console.warn("[mock-alerts] resources/ folder not found — mock alert catalog is empty (set MOCK_ALERTS_DIR)");
  }

  list(): MockAlertFixture[] {
    return this.cases;
  }

  find(key: string): MockAlertFixture | null {
    return this.cases.find((c) => c.key === key.toUpperCase()) ?? null;
  }

  private read(file: string): Record<string, unknown> | null {
    try {
      return obj(JSON.parse(readFileSync(file, "utf8")));
    } catch (e) {
      console.warn(`[mock-alerts] skipped ${file}: ${e instanceof Error ? e.message : e}`);
      return null;
    }
  }

  private loadTc(dir: string): MockAlertFixture[] {
    const folder = path.join(dir, "mock-attacks-tc");
    if (!existsSync(folder)) return [];
    return readdirSync(folder)
      .filter((f) => /^TC-\d{2}-.+\.json$/.test(f))
      .sort()
      .flatMap((f) => {
        const alert = this.read(path.join(folder, f));
        if (!alert) return [];
        const [, num, slug] = /^TC-(\d{2})-(.+)\.json$/.exec(f)!;
        return [toCase(`TC-${num}`, "TC", `mock-attacks-tc/${f}`, alert, titleCase(slug), titleCase(slug))];
      });
  }

  private loadAtk(dir: string): MockAlertFixture[] {
    const folder = path.join(dir, "mock-attacks");
    if (!existsSync(folder)) return [];
    const out: MockAlertFixture[] = [];
    for (const type of readdirSync(folder, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name)) {
      for (const f of readdirSync(path.join(folder, type)).filter((x) => /^case-.+\.json$/.test(x))) {
        const doc = this.read(path.join(folder, type, f));
        const alert = obj(doc?.alert);
        const id = str(doc?.id);
        if (!doc || !alert || !id || !/^ATK-\d{2}$/.test(id)) continue;
        out.push(toCase(`MOCK-${id}`, "MOCK_ATK", `mock-attacks/${type}/${f}`, alert, str(doc.title) ?? titleCase(type), titleCase(type)));
      }
    }
    return out.sort((a, b) => a.key.localeCompare(b.key));
  }
}
