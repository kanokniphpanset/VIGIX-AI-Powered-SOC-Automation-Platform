import { AssetCriticality } from "../../../domain/policy/entities/PolicyEvaluationTypes";

export interface AssetCriticalityResolution {
  criticality: AssetCriticality;
  /** Per host: the catalog tier it resolved to, or "default" when the host is not in the catalog. */
  assets: Array<{ host: string; tier: string; known: boolean }>;
}

/**
 * IAssetCriticalityProvider — resolves the business criticality of the assets an incident affects,
 * as a Policy Engine input (assetCriticality). Deterministic catalog lookup, never AI output.
 */
export interface IAssetCriticalityProvider {
  resolve(hosts: string[]): AssetCriticalityResolution;
}
