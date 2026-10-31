import { useEffect, useState } from "react";
import { findTheme } from "../ky-ui/themes";
import { NavIcon } from "../NavIcon";
import { THEME_CHOICES, applyTheme, storedTheme } from "../theme";

/** The saved choice, kept in step with another tab's choice (theme.ts applies it). */
function useStoredTheme() {
  const [theme, setTheme] = useState(storedTheme);
  useEffect(() => {
    const sync = () => setTheme(storedTheme());
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, []);
  return [theme, (value: string) => { setTheme(value); applyTheme(value, true); }] as const;
}

// One native radio group across the pairs: arrow keys move through every choice.
export function Appearance() {
  const [theme, choose] = useStoredTheme();
  return (
    // A Settings tab: the tab names it, so its heading is for screen readers.
    <section className="appearance-section" aria-labelledby="appearance-heading">
      <h2 id="appearance-heading" className="visually-hidden">Appearance</h2>
      <p className="config-muted">Pick a palette and how it handles light and dark. Match system switches with your device’s setting; Light or Dark keeps one. Your choice applies straight away and is saved in this browser only.</p>
      <fieldset className="ky-appearance">
        <legend className="ky-appearance-legend">Theme</legend>
        <div className="ky-appearance-grid appearance-pairs">
          {THEME_CHOICES.map(({ pair, choices }) => (
            <div key={pair.id} role="group" aria-labelledby={`${pair.id}-name`} className="appearance-pair">
              <div className="appearance-pair-head">
                <h2 id={`${pair.id}-name`} className="appearance-pair-name">{pair.name}</h2>
                <span className="appearance-pair-halves">{findTheme(pair.light)?.name} · {findTheme(pair.dark)?.name}</span>
              </div>
              <span className="ky-appearance-preview" data-ky-preview={pair.id} aria-hidden="true" />
              <div className="appearance-modes">
                {choices.map(({ mode, label, value }) => (
                  <label key={mode} className="appearance-mode">
                    <input type="radio" name="kynotes-theme" value={value} checked={theme === value} onChange={() => choose(value)} />
                    {theme === value && <NavIcon name="check" />}
                    <span>{label}</span>
                  </label>
                ))}
              </div>
            </div>
          ))}
        </div>
      </fieldset>
    </section>
  );
}

/** The sign-in screen's theme picker, top right. */
export function ThemeSwitcher() {
  const [theme, choose] = useStoredTheme();
  return (
    <select aria-label="Color theme" value={theme} onChange={(event) => choose(event.target.value)}>
      {THEME_CHOICES.map(({ pair, choices }) => (
        <optgroup key={pair.id} label={pair.name}>
          {choices.map(({ mode, label, value }) => <option key={mode} value={value}>{pair.name} · {label}</option>)}
        </optgroup>
      ))}
    </select>
  );
}
