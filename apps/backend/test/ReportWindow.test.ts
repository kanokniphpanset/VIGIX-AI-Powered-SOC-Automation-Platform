import { windowStart, isReportWindow, REPORT_WINDOW_KEYS } from "../src/application/dashboard/reportWindow";

/**
 * The report window is now computed on the backend (previously the frontend sent a `since` instant). These mirror the
 * frontend cases in apps/src/utils/socReport.test.ts, but evaluated in Asia/Bangkok (the report timezone) regardless
 * of the machine's own TZ — so `daily`/`1m`/`3m` land on the right Bangkok calendar boundary.
 */
const BKK = "Asia/Bangkok";
const bkk = (d: Date) =>
  new Intl.DateTimeFormat("sv-SE", {
    timeZone: BKK,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);

// Bangkok wall-clock 2026-09-30 15:30:00 == 08:30:00 UTC (UTC+7, no DST).
const now = new Date("2026-09-30T08:30:00.000Z");

describe("report window (backend, Asia/Bangkok)", () => {
  it("exposes exactly the four window keys", () => {
    expect([...REPORT_WINDOW_KEYS]).toEqual(["daily", "weekly", "1m", "3m"]);
  });

  it("daily = since local midnight today", () => {
    expect(bkk(windowStart("daily", now, BKK))).toBe("2026-09-30 00:00:00");
  });

  it("weekly = exactly the last 7 x 24 hours", () => {
    const start = windowStart("weekly", now, BKK);
    expect(now.getTime() - start.getTime()).toBe(7 * 86_400_000);
    expect(bkk(start)).toBe("2026-09-23 15:30:00");
  });

  it("1m / 3m = same day-of-month and time-of-day, N months back", () => {
    expect(bkk(windowStart("1m", now, BKK))).toBe("2026-08-30 15:30:00");
    expect(bkk(windowStart("3m", now, BKK))).toBe("2026-06-30 15:30:00");
  });

  it("clamps the day when the target month is shorter (May 31 -> Apr 30)", () => {
    const may31 = new Date("2026-05-31T02:00:00.000Z"); // BKK 2026-05-31 09:00
    expect(bkk(windowStart("1m", may31, BKK))).toBe("2026-04-30 09:00:00");
  });

  it("isReportWindow validates the query value", () => {
    expect(isReportWindow("weekly")).toBe(true);
    expect(isReportWindow("7d")).toBe(false);
    expect(isReportWindow(null)).toBe(false);
    expect(isReportWindow(undefined)).toBe(false);
  });
});
