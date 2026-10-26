import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { SYSTEM_THEME, THEME_CATALOG, applyThemeVariables, findTheme } from './ky-ui/themes';
import type { CatalogTheme, SystemTheme } from './ky-ui/themes';

export const THEME_STORAGE_KEY = "kynotes-theme";
// The suite catalog: Match system, Busnes Light/Dark and every named palette.
export type Theme = CatalogTheme | SystemTheme;
export const THEME_OPTIONS: readonly Theme[] = [SYSTEM_THEME, ...THEME_CATALOG];
const prefersDark = () => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;

/** The saved choice (names saved by earlier versions included), else Match system. */
export function getStoredTheme(): Theme { try { return findTheme(readChoice(THEME_STORAGE_KEY)) ?? SYSTEM_THEME; } catch { return SYSTEM_THEME; } }

export function applyTheme(theme: Theme, persist = true) {
  const root = document.documentElement;
  if (applyThemeVariables(theme.id, root)) delete root.dataset.theme;
  else {
    const busnes = theme.id === "system" ? (prefersDark() ? "busnes-dark" : "busnes-light") : theme.id;
    root.dataset.theme = busnes;
    root.style.colorScheme = busnes === "busnes-dark" ? "dark" : "light";
  }
  // Names are what earlier versions saved; keep writing them.
  if (persist) try { saveChoice(THEME_STORAGE_KEY, theme.id === "system" ? "system" : theme.name); } catch { /* browser storage is optional */ }
}
export function applyStoredTheme() { applyTheme(getStoredTheme(), false); }

if (typeof window !== 'undefined') watchChoice(THEME_STORAGE_KEY, applyStoredTheme, () => getStoredTheme().id !== "system");
