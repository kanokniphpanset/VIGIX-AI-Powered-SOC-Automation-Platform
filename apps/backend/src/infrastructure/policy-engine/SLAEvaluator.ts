import { PolicyPriority } from "../../domain/policy/entities/PolicyEvaluationTypes";

export type SlaStatus = "NOT_STARTED" | "ON_TRACK" | "AT_RISK" | "BREACHED" | "MET" | "PAUSED" | "CANCELLED";

export interface SlaBaseline {
  firstResponseMinutes: number;
  resolutionMinutes: number;
}

/** One business day = 8 working hours = 480 minutes. The spec gives P2/P3
 * resolution targets in "business days"; this is the conversion used to
 * express them in the same minutes unit as everything else in the DTO.
 * Documented here since the spec doesn't fix the conversion factor itself. */
const MINUTES_PER_BUSINESS_DAY = 480;

const SLA_BASELINE: Record<PolicyPriority, SlaBaseline> = {
  P0: { firstResponseMinutes: 15, resolutionMinutes: 4 * 60 },
  P1: { firstResponseMinutes: 30, resolutionMinutes: 8 * 60 },
  P2: { firstResponseMinutes: 4 * 60, resolutionMinutes: 3 * MINUTES_PER_BUSINESS_DAY },
  // P3 first response is "1 Business Day" (1 * 480min = 8h), not 24 calendar
  // hours — corrected per VIGIX Policy Engine audit; was 1440.
  P3: { firstResponseMinutes: 1 * MINUTES_PER_BUSINESS_DAY, resolutionMinutes: 5 * MINUTES_PER_BUSINESS_DAY },
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
