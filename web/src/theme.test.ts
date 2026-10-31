import { afterEach, describe, expect, it } from "vitest";
import { THEME_PAIRS } from "./ky-ui/themes";
import { THEME_CHOICES, THEME_STORAGE_KEY, storedTheme } from "./theme";

const memory = new Map<string, string>();
Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: (key: string) => memory.get(key) ?? null, setItem: (key: string, value: string) => void memory.set(key, value) } });
const saved = (value: string) => { memory.set(THEME_STORAGE_KEY, value); return storedTheme(); };

describe("theme", () => {
  afterEach(() => memory.clear());

  it("offers Match system, Light and Dark for every pair, with Busnes following the OS as system", () => {
    expect(THEME_CHOICES).toHaveLength(THEME_PAIRS.length);
    expect(THEME_CHOICES[0].choices.map((choice) => choice.value)).toEqual(["system", "busnes-light", "busnes-dark"]);
    expect(THEME_CHOICES[2].choices[0].value).toBe("ocean-pair");
  });

  it("selects the half that a name saved by an earlier version names", () => {
    expect(saved("Busnes Light")).toBe("busnes-light");
    expect(saved("Ocean")).toBe("ocean");
    expect(saved("Polished Ky")).toBe("polished-ky");
  });

  it("keeps pair and half IDs, and falls back to Match system for removed palettes", () => {
    expect(saved("forest-pair")).toBe("forest-pair");
    expect(saved("nord")).toBe("nord");
    expect(saved("Coffee")).toBe("system");
    expect(saved("Sun")).toBe("system");
  });

  it("follows the system without a saved choice", () => {
    expect(storedTheme()).toBe("system");
  });
});
