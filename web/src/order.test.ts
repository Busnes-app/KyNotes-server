import { describe, expect, it } from "vitest";
import { MAX_ORDER_KEY, isOrderKey, keyBetween } from "./order";

describe("order keys", () => {
  it("sorts every random insertion between its neighbours", () => {
    const keys: string[] = [];
    for (let n = 0; n < 5000; n += 1) {
      const i = Math.floor(Math.random() * (keys.length + 1));
      const key = keyBetween(keys[i - 1] ?? null, keys[i] ?? null);
      expect(isOrderKey(key)).toBe(true);
      if (i > 0) expect(keys[i - 1] < key).toBe(true);
      if (i < keys.length) expect(key < keys[i]).toBe(true);
      keys.splice(i, 0, key);
    }
  });

  it("grows slowly for repeated appends and prepends", () => {
    let last: string | null = null;
    for (let n = 0; n < 2000; n += 1) last = keyBetween(last, null);
    expect(last!.length).toBeLessThan(80);
    let first: string | null = null;
    for (let n = 0; n < 2000; n += 1) first = keyBetween(null, first);
    expect(first!.length).toBeLessThan(80);
  });

  it("refuses inverted or equal bounds", () => {
    expect(() => keyBetween("b", "a")).toThrow("order keys out of order");
    expect(() => keyBetween("b", "b")).toThrow("order keys out of order");
  });

  it("stops at the length cap instead of producing an invalid key", () => {
    const low = keyBetween(null, null);
    let high = keyBetween(low, null);
    expect(() => { for (;;) high = keyBetween(low, high); }).toThrow("order key limit reached");
    expect(high.length).toBeLessThanOrEqual(MAX_ORDER_KEY);
  });

  it("rejects keys a client must never produce", () => {
    for (const bad of ["", "a0", "A", "a-b", 7, null, "z".repeat(MAX_ORDER_KEY + 1)]) expect(isOrderKey(bad)).toBe(false);
  });
});
