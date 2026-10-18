// Opt-in reminder push: the server stores only {id, at} and sends an empty push at that minute.
// The id is an HMAC the server cannot link to a page; the time is a UTC minute. Pure functions only.
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "./crypto";
import { remindAt } from "./taskDates";

/** The server's cap per account. */
export const MAX_SERVER_REMINDERS = 500;
const CROCKFORD = "0123456789abcdefghjkmnpqrstvwxyz";

/** HMAC-SHA256(key, noteID + "\n" + remind), first 130 bits as 26 lowercase Crockford symbols. */
export function reminderID(key: Uint8Array, noteID: string, remind: string): string {
  const mac = hmac(sha256, key, new TextEncoder().encode(`${noteID}\n${remind}`));
  let bits = 0n;
  for (const byte of mac.subarray(0, 17)) bits = (bits << 8n) | BigInt(byte);
  bits >>= 6n; // 136 → 130 bits
  let out = "";
  for (let index = 0; index < 26; index += 1, bits >>= 5n) out = CROCKFORD[Number(bits & 31n)] + out;
  return out;
}

/** The local remind: time as the server's RFC3339 UTC minute. */
export const reminderUTC = (remind: string) => `${new Date(remindAt(remind)).toISOString().slice(0, 16)}:00Z`;

export type ServerReminder = { id: string; at: string };
export type PushTask = { noteID: string; remind?: string; push?: boolean };

/** Opted-in tasks with a future reminder time, earliest first, at most the server's cap. */
export function desiredReminders(key: Uint8Array, tasks: PushTask[], now: number): ServerReminder[] {
  const byID = new Map<string, ServerReminder>();
  for (const task of tasks) {
    if (!task.push || !task.remind || remindAt(task.remind) <= now) continue;
    const id = reminderID(key, task.noteID, task.remind);
    byID.set(id, { id, at: reminderUTC(task.remind) });
  }
  return [...byID.values()].sort((a, b) => a.at.localeCompare(b.at) || a.id.localeCompare(b.id)).slice(0, MAX_SERVER_REMINDERS);
}

/**
 * What to send so the server holds exactly `desired`. Nothing at all unless every personal notebook
 * loaded (`complete`): a partial load must never delete a reminder it could not see.
 */
export function planReconcile(desired: ServerReminder[], server: ServerReminder[], complete: boolean): { puts: ServerReminder[]; deletes: string[] } {
  if (!complete) return { puts: [], deletes: [] };
  const held = new Map(server.map((row) => [row.id, row.at]));
  const wanted = new Set(desired.map((row) => row.id));
  return {
    puts: desired.filter((row) => held.get(row.id) !== row.at),
    deletes: server.filter((row) => !wanted.has(row.id)).map((row) => row.id),
  };
}
