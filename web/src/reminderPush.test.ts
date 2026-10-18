import { describe, expect, it, vi } from "vitest";
import { reminderIDKey } from "./keyring";
import { desiredReminders, MAX_SERVER_REMINDERS, planReconcile, reminderID, reminderUTC } from "./reminderPush";
import { remindAt } from "./taskDates";
import { generateIdentity } from "./teamKeys";

const key = reminderIDKey(generateIdentity());
const note = `obj_${"a".repeat(26)}`;

describe("reminder ids", () => {
  it("are 26 lowercase Crockford symbols, stable for a note and time", () => {
    const id = reminderID(key, note, "2030-11-01T09:00");
    expect(id).toMatch(/^[0-9abcdefghjkmnpqrstvwxyz]{26}$/);
    expect(reminderID(key, note, "2030-11-01T09:00")).toBe(id);
    expect(reminderID(new Uint8Array(key), note, "2030-11-01T09:00")).toBe(id);
  });

  it("differ per note, per time and per identity", () => {
    const id = reminderID(key, note, "2030-11-01T09:00");
    expect(reminderID(key, `obj_${"b".repeat(26)}`, "2030-11-01T09:00")).not.toBe(id);
    expect(reminderID(key, note, "2030-11-01T09:01")).not.toBe(id);
    expect(reminderID(reminderIDKey(generateIdentity()), note, "2030-11-01T09:00")).not.toBe(id);
  });

  it("derive from the identity under their own label, never the waiting key", async () => {
    const identity = generateIdentity();
    expect(reminderIDKey(identity)).toEqual(reminderIDKey({ privateKey: new Uint8Array(identity.privateKey) }));
    const { waitingKey } = await import("./keyring");
    expect(reminderIDKey(identity)).not.toEqual(new Uint8Array(waitingKey(identity)));
  });

  it("send the local time as a UTC minute", () => {
    const at = reminderUTC("2030-11-01T09:00");
    expect(at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00Z$/);
    expect(Date.parse(at)).toBe(remindAt("2030-11-01T09:00"));
  });
});

describe("reconcile planning", () => {
  const now = Date.parse("2030-01-01T00:00:00Z");
  const task = (remind: string, push = true, noteID = note) => ({ noteID, remind, push });

  it("wants only opted-in tasks with a future time, once each", () => {
    const desired = desiredReminders(key, [task("2030-06-01T09:00"), task("2030-06-01T09:00"), task("2029-06-01T09:00"), task("2030-07-01T09:00", false), { noteID: note, push: true }], now);
    expect(desired).toEqual([{ id: reminderID(key, note, "2030-06-01T09:00"), at: reminderUTC("2030-06-01T09:00") }]);
  });

  it("keeps at most the server's cap, earliest first", () => {
    const tasks = Array.from({ length: MAX_SERVER_REMINDERS + 5 }, (_, index) => task("2030-06-01T09:00", true, `obj_${String(index).padStart(26, "0")}`));
    expect(desiredReminders(key, tasks, now)).toHaveLength(MAX_SERVER_REMINDERS);
  });

  it("puts what is missing or moved and deletes what is no longer wanted", () => {
    const desired = [{ id: "a", at: "2030-06-01T09:00:00Z" }, { id: "b", at: "2030-06-02T09:00:00Z" }, { id: "c", at: "2030-06-03T09:00:00Z" }];
    const server = [{ id: "a", at: "2030-06-01T09:00:00Z" }, { id: "b", at: "2030-06-02T08:00:00Z" }, { id: "z", at: "2030-06-09T09:00:00Z" }];
    expect(planReconcile(desired, server, true)).toEqual({ puts: [desired[1], desired[2]], deletes: ["z"] });
    expect(planReconcile(desired, desired, true)).toEqual({ puts: [], deletes: [] });
    expect(planReconcile([], server, true).deletes).toEqual(["a", "b", "z"]);
  });

  it("does nothing on a partial load, so it never deletes what it could not see", () => {
    expect(planReconcile([], [{ id: "z", at: "2030-06-09T09:00:00Z" }], false)).toEqual({ puts: [], deletes: [] });
    expect(planReconcile([{ id: "a", at: "2030-06-01T09:00:00Z" }], [], false)).toEqual({ puts: [], deletes: [] });
  });

  it("request bodies carry only an id and a time", () => {
    const [row] = desiredReminders(key, [{ noteID: note, remind: "2030-06-01T09:00", push: true }], now);
    expect(JSON.stringify({ at: row.at })).not.toMatch(/obj_|2030-06-01T09:00"/);
    expect(row.id).not.toContain(note.slice(4, 10));
  });
});

describe("reminder preferences", () => {
  it("are per account: another account in this browser starts with everything off", async () => {
    const store = new Map<string, string>();
    vi.stubGlobal("localStorage", { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v) });
    vi.stubGlobal("Notification", { permission: "granted" });
    vi.stubGlobal("navigator", { serviceWorker: {} });
    vi.stubGlobal("PushManager", class {});
    try {
      const { readReminderPrefs, saveReminderPrefs } = await import("./reminders");
      saveReminderPrefs("usr_a", { enabled: true, showText: true, push: true });
      expect(readReminderPrefs("usr_a")).toEqual({ enabled: true, showText: true, push: true });
      expect(readReminderPrefs("usr_b")).toEqual({ enabled: false, showText: false, push: false });
      expect([...store.keys()].every((k) => k.endsWith(":usr_a"))).toBe(true);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
