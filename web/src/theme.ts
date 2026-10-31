import { readChoice, saveChoice, watchChoice } from './ky-ui/theme';
import { SYSTEM_THEME, THEME_PAIRS, applyThemeVariables, findPair, findTheme } from './ky-ui/themes';

export const THEME_STORAGE_KEY = "kynotes-theme";
// Busnes.app defaults; explicit choices are local to this browser. The saved value is `system`
// (Busnes following the OS), a pair ID (that pair following the OS) or a half ID (a fixed mode).
// Names and aliases earlier versions saved resolve to their half; removed ones fall back to `system`.
export const THEME_CHOICES = THEME_PAIRS.map((pair) => ({
  pair,
  choices: [
    { mode: "system", label: "Match system", value: pair.id === "busnes-pair" ? SYSTEM_THEME.id : pair.id },
    { mode: "light", label: "Light", value: pair.light },
    { mode: "dark", label: "Dark", value: pair.dark },
  ],
}));
const prefersDark = () => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false;

/** The saved choice as a radio value, else Match system. */
export function storedTheme(): string {
  const saved = readChoice(THEME_STORAGE_KEY);
  return findPair(saved)?.id ?? findTheme(saved)?.id ?? SYSTEM_THEME.id;
}

export function applyTheme(choice: string, persist = false) {
  const theme = findTheme(choice, prefersDark());
  if (!theme) return;
  const root = document.documentElement;
  if (applyThemeVariables(choice, root)) delete root.dataset.theme;
  else {
    const busnes = theme.id === "system" ? (prefersDark() ? "busnes-dark" : "busnes-light") : theme.id;
    root.dataset.theme = busnes;
    root.style.colorScheme = busnes === "busnes-dark" ? "dark" : "light";
  }
  if (persist) saveChoice(THEME_STORAGE_KEY, findPair(choice)?.id ?? theme.id);
}
export function applyStoredTheme() { applyTheme(storedTheme()); }

if (typeof window !== "undefined") watchChoice(THEME_STORAGE_KEY, applyStoredTheme);
