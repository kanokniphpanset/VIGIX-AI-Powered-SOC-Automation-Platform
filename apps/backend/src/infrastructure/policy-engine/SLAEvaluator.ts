import { PolicyPriority } from "../../domain/policy/entities/PolicyEvaluationTypes";

export type SlaStatus = "NOT_STARTED" | "ON_TRACK" | "AT_RISK" | "BREACHED" | "MET" | "PAUSED" | "CANCELLED";

/** An SLA target as the Policy states it (e.g. 3 business days), for display. The clock itself runs on `...Minutes`. */
export type SlaUnit = "minute" | "hour" | "business_day";
export interface SlaTarget {
  value: number;
  unit: SlaUnit;
}

export interface SlaBaseline {
  firstResponseMinutes: number;
  resolutionMinutes: number;
  firstResponseTarget: SlaTarget;
  resolutionTarget: SlaTarget;
}

const HOUR = 60;
const DAY = 24 * HOUR;

/**
 * Policy SLA per priority. "Business days" are counted on the calendar, so the deadline shown is the deadline
 * enforced: 1 business day = 1 calendar day, 3 business days = 3 days, 5 business days = 1 week.
 */
const SLA_BASELINE: Record<PolicyPriority, SlaBaseline> = {
  P0: { firstResponseMinutes: 15, resolutionMinutes: 4 * HOUR, firstResponseTarget: { value: 15, unit: "minute" }, resolutionTarget: { value: 4, unit: "hour" } },
  P1: { firstResponseMinutes: 30, resolutionMinutes: 8 * HOUR, firstResponseTarget: { value: 30, unit: "minute" }, resolutionTarget: { value: 8, unit: "hour" } },
  P2: { firstResponseMinutes: 4 * HOUR, resolutionMinutes: 3 * DAY, firstResponseTarget: { value: 4, unit: "hour" }, resolutionTarget: { value: 3, unit: "business_day" } },
  P3: { firstResponseMinutes: 1 * DAY, resolutionMinutes: 7 * DAY, firstResponseTarget: { value: 1, unit: "business_day" }, resolutionTarget: { value: 5, unit: "business_day" } },
};

/**
 * SLAEvaluator — baseline SLA lookup by Priority, plus a stateless status
 * calculator. Kept separate from PolicyEvaluator so SLA rules can change
 * (or read from the database) without touching rule-matching logic at all.
 */
export class SLAEvaluator {
  getBaseline(priority: PolicyPriority): SlaBaseline {
    return SLA_BASELINE[priority];
  }

  /**
   * Pure status calculation — no persistence, no side effects. `now`
   * defaults to the real clock but is injectable for tests.
   */
  getStatus(
    input: {
      dueAt: Date;
      startedAt: Date | null;
      completedAt: Date | null;
      paused?: boolean;
      cancelled?: boolean;
    },
    now: Date = new Date()
  ): SlaStatus {
    if (input.cancelled) return "CANCELLED";
    if (input.paused) return "PAUSED";
    if (input.completedAt) {
      return input.completedAt.getTime() <= input.dueAt.getTime() ? "MET" : "BREACHED";
    }
    if (!input.startedAt) return "NOT_STARTED";
    if (now.getTime() > input.dueAt.getTime()) return "BREACHED";

    const totalWindowMs = input.dueAt.getTime() - input.startedAt.getTime();
    const elapsedMs = now.getTime() - input.startedAt.getTime();
    const AT_RISK_THRESHOLD = 0.8; // 80% of the window elapsed with no resolution yet
    if (totalWindowMs > 0 && elapsedMs / totalWindowMs >= AT_RISK_THRESHOLD) {
      return "AT_RISK";
    }
    return "ON_TRACK";
  }
}
