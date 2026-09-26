import * as fs from "node:fs";
import * as path from "node:path";
import { safeLoad } from "js-yaml";
import { AssetCriticality } from "../../domain/policy/entities/PolicyEvaluationTypes";
import { AssetCriticalityResolution, IAssetCriticalityProvider } from "../../application/approval/ports/IAssetCriticalityProvider";

const TIER_TO_CRITICALITY: Record<string, AssetCriticality> = {
  tier1_critical: "CRITICAL",
  tier2_high: "HIGH",
  tier3_medium: "MEDIUM",
  tier4_low: "LOW",
};
const RANK: Record<AssetCriticality, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/** repo-root/resources/assets/asset-criticality-catalog.yaml, from src/ (ts-node) or dist/ (node). */
export const DEFAULT_ASSET_CATALOG_PATH = path.resolve(__dirname, "../../../../../resources/assets/asset-criticality-catalog.yaml");

interface Catalog {
  defaultTier: string;
  byKey: Map<string, string>;
}

/**
 * ResourceAssetCriticalityProvider — the backend's loader for the shared asset criticality catalog
 * (resources/assets/asset-criticality-catalog.yaml; the AI orchestrator reads the same file with its own
 * loader, per resources/README.md). Hosts are matched case-insensitively by hostname or IP.
 *
 * - Several hosts: the MOST critical one wins.
 * - Host not in the catalog: the catalog's own `default_tier` (never guessed lower).
 * - Catalog missing/unreadable: fails CLOSED to CRITICAL, so Policy can only become stricter, never skip an approval.
 */
export class ResourceAssetCriticalityProvider implements IAssetCriticalityProvider {
  private catalog: Catalog | null | undefined;

  constructor(private readonly catalogPath: string = process.env.ASSET_CRITICALITY_CATALOG_PATH ?? DEFAULT_ASSET_CATALOG_PATH) {}

  resolve(hosts: string[]): AssetCriticalityResolution {
    const catalog = this.load();
    const unique = [...new Set(hosts.map((h) => h.trim()).filter(Boolean))];
    if (!catalog) {
      return { criticality: "CRITICAL", assets: unique.map((host) => ({ host, tier: "catalog_unavailable", known: false })) };
    }
    const assets = unique.map((host) => {
      const tier = catalog.byKey.get(host.toLowerCase());
      return { host, tier: tier ?? catalog.defaultTier, known: tier !== undefined };
    });
    const tiers = assets.length ? assets.map((a) => a.tier) : [catalog.defaultTier];
    const criticality = tiers
      .map((t) => TIER_TO_CRITICALITY[t] ?? "CRITICAL")
      .reduce((a, b) => (RANK[b] > RANK[a] ? b : a));
    return { criticality, assets };
  }

  private load(): Catalog | null {
    if (this.catalog !== undefined) return this.catalog;
    try {
      const raw = safeLoad(fs.readFileSync(this.catalogPath, "utf-8")) as { default_tier?: unknown; assets?: unknown };
      const defaultTier = typeof raw?.default_tier === "string" ? raw.default_tier : "tier1_critical";
      const byKey = new Map<string, string>();
      for (const a of Array.isArray(raw?.assets) ? raw.assets : []) {
        const entry = a as { hostname?: unknown; ip?: unknown; tier?: unknown };
        if (typeof entry.tier !== "string") continue;
        if (typeof entry.hostname === "string") byKey.set(entry.hostname.toLowerCase(), entry.tier);
        if (typeof entry.ip === "string") byKey.set(entry.ip.toLowerCase(), entry.tier);
      }
      this.catalog = { defaultTier, byKey };
    } catch (err) {
      console.error("Asset criticality catalog unavailable — Policy input fails closed to CRITICAL", this.catalogPath, err);
      this.catalog = null;
    }
    return this.catalog;
  }
}
