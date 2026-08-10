export type Severity = "low" | "medium" | "high" | "critical";

interface SeverityMeta {
  label: string;
  color: string;
  bg: string;
}

const SEVERITY_MAP: Record<Severity, SeverityMeta> = {
  critical: { label: "Critical", color: "var(--severity-critical)", bg: "var(--severity-critical-bg)" },
  high: { label: "High", color: "var(--severity-high)", bg: "var(--severity-high-bg)" },
  medium: { label: "Medium", color: "var(--severity-medium)", bg: "var(--severity-medium-bg)" },
  low: { label: "Low", color: "var(--severity-low)", bg: "var(--severity-low-bg)" },
};

export function severityMeta(severity: string): SeverityMeta {
  return SEVERITY_MAP[severity as Severity] ?? SEVERITY_MAP.low;
}

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function severityRank(severity: string): number {
  return SEVERITY_ORDER[severity as Severity] ?? 99;
}
