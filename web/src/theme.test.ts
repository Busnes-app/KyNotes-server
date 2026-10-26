import { describe, expect, it } from "vitest";
import { THEME_CATALOG, findTheme } from "./ky-ui/themes";
import { THEME_OPTIONS, getStoredTheme } from "./theme";

// Every name earlier versions saved under kynotes-theme.
const SAVED = ["Busnes Light", "Busnes Dark", "Dark Matter", "Light Matter", "Tropics", "Tropic Night", "Ocean", "Coffee", "White Cliffs", "Cyber Punk", "Neon Purple", "Space", "Sky", "Forest", "Sun", "Patina Ky", "Polished Ky"];

describe("theme", () => {
  it("offers Match system first, then the suite catalog", () => {
    expect(THEME_OPTIONS).toHaveLength(THEME_CATALOG.length + 1);
    expect(THEME_OPTIONS[0].id).toBe("system");
  });

  it("still recognises every saved name and keeps it as the saved value", () => {
    for (const name of SAVED) expect(findTheme(name)?.name).toBe(name);
  });

  it("follows the system without browser storage", () => {
    expect(getStoredTheme().id).toBe("system");
  });
});
