// In-tab task reminders: browser notifications while a KyNotes tab is open. Nothing leaves the browser,
// except with the opt-in push below: then reminder times of push:yes tasks go to the server (reminderPush.ts).
import { useEffect, useRef, useState } from "react";
import { deletePushSubscription, pushKey, putPushSubscription } from "./api";
import { readChoice, saveChoice } from "./ky-ui/theme";
import { planReminders } from "./taskDates";

const ENABLED_KEY = "kynotes-reminders";
const TEXT_KEY = "kynotes-reminder-text";
const PUSH_KEY = "kynotes-reminder-push";
const DAY = 24 * 60 * 60 * 1000;
const OPENED = Date.now();
const CHECK = { display: "flex", alignItems: "center", gap: 10, marginTop: 16 } as const;

export type ReminderPrefs = { enabled: boolean; showText: boolean; push: boolean };
export type ReminderTask = { key: string; text: string; remind?: string };

const granted = () => typeof Notification !== "undefined" && Notification.permission === "granted";
const pushSupported = () => typeof navigator !== "undefined" && "serviceWorker" in navigator && typeof PushManager !== "undefined";

// Per account: another account in this browser starts with everything off.
const choice = (key: string, userID: string) => readChoice(`${key}:${userID}`) === "on";

export function readReminderPrefs(userID: string): ReminderPrefs {
  return { enabled: choice(ENABLED_KEY, userID) && granted(), showText: choice(TEXT_KEY, userID), push: choice(PUSH_KEY, userID) && granted() && pushSupported() };
}

export function saveReminderPrefs(userID: string, prefs: ReminderPrefs) {
  saveChoice(`${ENABLED_KEY}:${userID}`, prefs.enabled ? "on" : "off");
  saveChoice(`${TEXT_KEY}:${userID}`, prefs.showText ? "on" : "off");
  saveChoice(`${PUSH_KEY}:${userID}`, prefs.push ? "on" : "off");
}

const fromBase64URL = (value: string) => Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (char) => char.charCodeAt(0));
const sameBytes = (a: ArrayBuffer | null, b: Uint8Array) => a !== null && a.byteLength === b.length && new Uint8Array(a).every((byte, index) => byte === b[index]);

/**
 * Subscribes this browser for pushes and registers the endpoint (idempotent). A subscription made
 * under another server key (a replaced vapid.key) is replaced, so a restored server keeps working.
 */
export async function ensurePushSubscription(): Promise<void> {
  await navigator.serviceWorker.register("/sw.js", { scope: "/" });
  const registration = await navigator.serviceWorker.ready;
  const key = fromBase64URL((await pushKey()).publicKey);
  let subscription = await registration.pushManager.getSubscription();
  if (subscription && !sameBytes(subscription.options.applicationServerKey, key)) {
    await subscription.unsubscribe();
    subscription = null;
  }
  subscription ??= await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: key });
  await putPushSubscription(subscription.endpoint);
}

/**
 * Removes this browser's endpoint from the server (if this account holds it), then unsubscribes even if
 * that failed: the push service then answers 410 and the server drops it. Run at sign-out, and on open
 * for an account that has push off, so no account's subscription carries over to another.
 */
export async function dropPushSubscription(): Promise<void> {
  if (!pushSupported()) return;
  const subscription = await (await navigator.serviceWorker.getRegistration("/"))?.pushManager.getSubscription();
  if (!subscription) return;
  try {
    await deletePushSubscription(subscription.endpoint);
  } finally {
    await subscription.unsubscribe();
  }
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
  const [pushError, setPushError] = useState("");
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
  async function togglePush(on: boolean) {
    setRefused(false);
    setPushError("");
    try {
      if (!on) {
        save({ ...prefs, push: false });
        return await dropPushSubscription();
      }
      if (!pushSupported()) return setPushError("This browser cannot receive pushes for KyNotes.");
      if ((await Notification.requestPermission()) !== "granted") return setRefused(true);
      await ensurePushSubscription();
      save({ ...prefs, push: true });
    } catch (error) {
      setPushError(error instanceof Error ? `Push reminders failed: ${error.message}` : "Push reminders failed.");
    }
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
      <label style={CHECK}>
        <input type="checkbox" checked={prefs.push} onChange={(event) => void togglePush(event.target.checked)} />
        <span>Also remind me when KyNotes is closed (sends reminder times to the server)</span>
      </label>
      <p className="config-muted">For tasks you mark <code>push:yes</code>, the server learns each reminder's time and how many you have, never which task, and your browser's push service (Google, Mozilla, Apple or Microsoft) sees an empty push arrive; the notification says only "A reminder is due".</p>
      {pushError && <p role="status">{pushError}</p>}
      {refused && <p role="status">This browser blocked notifications for KyNotes. Allow them in the site settings, then try again.</p>}
    </section>
  );
}
