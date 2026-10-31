import { describe, expect, it } from "vitest";
import { relativeDate } from "./relativeDate";

describe("relativeDate", () => {
  const now = new Date(2026, 9, 31, 15, 0);
  it("shows today's time, then Yesterday, a weekday and a date", () => {
    expect(relativeDate(new Date(2026, 9, 31, 9, 5).toISOString(), now)).toBe(new Date(2026, 9, 31, 9, 5).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }));
    expect(relativeDate(new Date(2026, 9, 30, 23, 59).toISOString(), now)).toBe("Yesterday");
    expect(relativeDate(new Date(2026, 9, 27, 8).toISOString(), now)).toBe(new Date(2026, 9, 27).toLocaleDateString([], { weekday: "long" }));
    expect(relativeDate(new Date(2026, 8, 2).toISOString(), now)).toBe(new Date(2026, 8, 2).toLocaleDateString([], { month: "short", day: "numeric" }));
    expect(relativeDate(new Date(2025, 8, 2).toISOString(), now)).toContain("2025");
  });
  it("treats a clock-skewed future save as today and a missing date as none", () => {
    expect(relativeDate(new Date(2026, 9, 31, 16).toISOString(), now)).not.toBe("");
    expect(relativeDate("", now)).toBe("");
    expect(relativeDate("not a date", now)).toBe("");
  });
});
