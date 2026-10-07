/**
 * SOC report time windows — computed on the BACKEND (previously the frontend sent a `since` instant).
 *
 * Each window ends at the moment of the request and starts at:
 *   daily  = local midnight today            (since local 00:00)
 *   weekly = the last 7 x 24 hours           (default)
 *   1m     = one calendar month back, same day-of-month (clamped to month length), same time-of-day
 *   3m     = three calendar months back, same rule
 *
 * "Local" means the report timezone (REPORT_TIMEZONE, default Asia/Bangkok — Thailand, fixed UTC+7, no DST),
 * so `daily`/`1m`/`3m` land on the right calendar boundary regardless of the server's own timezone. This mirrors
 * the frontend `windowStart` in apps/src/utils/socReport.ts exactly, just evaluated server-side and TZ-aware.
 */
export const REPORT_WINDOW_KEYS = ["daily", "weekly", "1m", "3m"] as const;
export type ReportWindow = (typeof REPORT_WINDOW_KEYS)[number];

export const DEFAULT_WINDOW: ReportWindow = "weekly";

export const isReportWindow = (v: unknown): v is ReportWindow =>
  typeof v === "string" && (REPORT_WINDOW_KEYS as readonly string[]).includes(v);

const SPEC: Record<ReportWindow, { days: number; months: number }> = {
  daily: { days: 0, months: 0 },
  weekly: { days: 7, months: 0 },
  "1m": { days: 0, months: 1 },
  "3m": { days: 0, months: 3 },
};

const REPORT_TZ = process.env.REPORT_TIMEZONE || "Asia/Bangkok";

/** Wall-clock components of `at` in the given IANA timezone. */
function partsIn(at: Date, tz: string): { y: number; mo: number; d: number; h: number; mi: number; s: number } {
  const f = new Intl.DateTimeFormat("en-CA", {
    timeZone: tz,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  const p: Record<string, number> = {};
  for (const { type, value } of f.formatToParts(at)) if (type !== "literal") p[type] = Number(value);
  if (p.hour === 24) p.hour = 0; // some engines render midnight as 24
  return { y: p.year, mo: p.month, d: p.day, h: p.hour, mi: p.minute, s: p.second };
}

/** The UTC instant of a wall-clock time (1-based month) in `tz`. Exact for fixed-offset zones like Asia/Bangkok. */
function zonedToUtc(y: number, mo: number, d: number, h: number, mi: number, s: number, tz: string): Date {
  const guess = Date.UTC(y, mo - 1, d, h, mi, s);
  const p = partsIn(new Date(guess), tz);
  const asUtcOfGuess = Date.UTC(p.y, p.mo - 1, p.d, p.h, p.mi, p.s);
  const offset = asUtcOfGuess - guess; // ms the zone is ahead of UTC
  return new Date(guess - offset);
}

/** Start instant of the report window ending at `now`. `tz` defaults to REPORT_TIMEZONE (Asia/Bangkok). */
export function windowStart(period: ReportWindow, now: Date, tz: string = REPORT_TZ): Date {
  const { days, months } = SPEC[period];
  if (months > 0) {
    const p = partsIn(now, tz);
    let y = p.y;
    let m0 = p.mo - 1 - months; // 0-based target month
    while (m0 < 0) {
      m0 += 12;
      y -= 1;
    }
    const lastDay = new Date(Date.UTC(y, m0 + 1, 0)).getUTCDate();
    const day = Math.min(p.d, lastDay);
    return zonedToUtc(y, m0 + 1, day, p.h, p.mi, p.s, tz);
  }
  if (days === 0) {
    const p = partsIn(now, tz);
    return zonedToUtc(p.y, p.mo, p.d, 0, 0, 0, tz);
  }
  return new Date(now.getTime() - days * 86_400_000);
}
