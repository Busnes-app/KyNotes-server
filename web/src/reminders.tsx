// In-tab task reminders: browser notifications while a KyNotes tab is open. Nothing leaves the browser.
import { useEffect, useRef, useState } from "react";
import { readChoice, saveChoice } from "./ky-ui/theme";
import { planReminders } from "./taskDates";

const ENABLED_KEY = "kynotes-reminders";
const TEXT_KEY = "kynotes-reminder-text";
const DAY = 24 * 60 * 60 * 1000;
const OPENED = Date.now();
const CHECK = { display: "flex", alignItems: "center", gap: 10, marginTop: 16 } as const;

export type ReminderPrefs = { enabled: boolean; showText: boolean };
export type ReminderTask = { key: string; text: string; remind?: string };

const granted = () => typeof Notification !== "undefined" && Notification.permission === "granted";

// Per account: another account in this browser starts with everything off.
const choice = (key: string, userID: string) => readChoice(`${key}:${userID}`) === "on";

export function readReminderPrefs(userID: string): ReminderPrefs {
  return { enabled: choice(ENABLED_KEY, userID) && granted(), showText: choice(TEXT_KEY, userID) };
}

export function saveReminderPrefs(userID: string, prefs: ReminderPrefs) {
  saveChoice(`${ENABLED_KEY}:${userID}`, prefs.enabled ? "on" : "off");
  saveChoice(`${TEXT_KEY}:${userID}`, prefs.showText ? "on" : "off");
}

/**
 * Fires each reminder whose time passes while this tab is open, and returns the keys of
 * reminders that passed unfired (missed). ponytail: fired reminders are kept in memory only,
 * so after a reload a reminder that already fired shows as missed; persist the set to fix that.
 */
export function useReminders(tasks: ReminderTask[], prefs: ReminderPrefs): Set<string> {
  const fired = useRef(new Set<string>());
  const [tick, setTick] = useState(0);
  const enabled = prefs.enabled && granted();
  const plan = planReminders(tasks, Date.now(), OPENED, fired.current, enabled);
  useEffect(() => {
    for (const key of plan.fire) {
      if (fired.current.has(key)) continue;
      fired.current.add(key);
      const text = tasks.find((task) => task.key === key)?.text;
      new Notification("KyNotes", { body: prefs.showText && text ? `A task is due: ${text}` : "A task is due", tag: key });
    }
    if (plan.next === undefined) return;
    const timer = window.setTimeout(() => setTick((value) => value + 1), Math.min(Math.max(plan.next - Date.now(), 0), DAY));
    return () => window.clearTimeout(timer);
  }, [tasks, enabled, prefs.showText, tick]);
  return plan.missed;
}

export function ReminderSettings({ userID, prefs, onChange }: { userID: string; prefs: ReminderPrefs; onChange: (prefs: ReminderPrefs) => void }) {
  const [refused, setRefused] = useState(false);
  const save = (next: ReminderPrefs) => {
    saveReminderPrefs(userID, next);
    onChange(next);
  };
  async function toggle(on: boolean) {
    setRefused(false);
    if (!on) return save({ ...prefs, enabled: false });
    const permission = typeof Notification === "undefined" ? "denied" : await Notification.requestPermission();
    if (permission === "granted") save({ ...prefs, enabled: true });
    else setRefused(true);
  }
  return (
    <section id="reminders" className="config-card">
      <h2>Reminders</h2>
      <p className="config-muted">Tasks with <code>remind:2026-11-01T09:00</code> notify you in this browser while a KyNotes tab is open. Reminders that pass with no tab open show as missed in the work queue.</p>
      <label style={CHECK}>
        <input type="checkbox" checked={prefs.enabled} onChange={(event) => void toggle(event.target.checked)} />
        <span>Show reminders while KyNotes is open</span>
      </label>
      <label style={CHECK}>
        <input type="checkbox" checked={prefs.showText} onChange={(event) => save({ ...prefs, showText: event.target.checked })} />
        <span>Show task text in reminders</span>
      </label>
      <p className="config-muted">With task text off, a reminder says only "A task is due", so nothing from your notes shows on a locked screen.</p>
      {refused && <p role="status">This browser blocked notifications for KyNotes. Allow them in the site settings, then try again.</p>}
    </section>
  );
}
