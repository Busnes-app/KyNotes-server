import { describe, expect, it } from "vitest";
import { strokePath } from "./ink";

describe("strokePath", () => {
  it("renders nothing without points", () => {
    expect(strokePath([], 4, false)).toBe("");
  });
  it("renders a closed outline for a dot and a line", () => {
    expect(strokePath([10, 10, 0.5], 4, false)).toMatch(/^M[\d.]+,[\d.]+(L[\d.]+,[\d.]+)+Z$/);
    expect(strokePath([0, 0, 0.5, 50, 50, 0.9, 100, 0, 0.2], 8, true)).toMatch(/^M.*Z$/);
  });
});
