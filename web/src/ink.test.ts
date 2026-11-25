import { describe, expect, it } from "vitest";
import { samplesOf, strokePath } from "./ink";

type Move = { x: number; getCoalescedEvents?: () => Move[] };

describe("samplesOf", () => {
  it("uses the browser's coalesced samples", () => {
    const samples: Move[] = [{ x: 1 }, { x: 2 }];
    const move: Move = { x: 2, getCoalescedEvents: () => samples };
    expect(samplesOf(move)).toBe(samples);
  });
  it("falls back to the move itself when the list is empty or missing", () => {
    const empty: Move = { x: 3, getCoalescedEvents: () => [] };
    const missing: Move = { x: 4 };
    expect(samplesOf(empty)).toEqual([empty]);
    expect(samplesOf(missing)).toEqual([missing]);
  });
});

describe("strokePath", () => {
  it("renders nothing without points", () => {
    expect(strokePath([], 4, false)).toBe("");
  });
  it("renders a closed outline for a dot and a line", () => {
    expect(strokePath([10, 10, 0.5], 4, false)).toMatch(/^M[\d.]+,[\d.]+(L[\d.]+,[\d.]+)+Z$/);
    expect(strokePath([0, 0, 0.5, 50, 50, 0.9, 100, 0, 0.2], 8, true)).toMatch(/^M.*Z$/);
  });
});
