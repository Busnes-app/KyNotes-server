import { decryptObject, encryptNote, legacyKeyRef } from "./crypto";
import { WAITING_GENERATION } from "./keyring";
import { getNote, pendingSaves, putNote, replaceQueuedSave, type CachedNote } from "./storage";

// ponytail: stopgap until personal notebooks move to shared keys (team-keys P5) and stop
// deriving content keys from the password.
export const PASSWORD_CHANGE_WARNING =
  "Personal notes are encrypted with keys derived from your current password. After a password change they become unreadable, even if you change it back, until personal notebooks move to shared keys in a later release. So do team pages written before their notebook was shared. Team content written after sharing stays readable. Team edits waiting on this browser for a notebook's keys are re-encrypted for the new password here; edits waiting in any other browser are lost.";

/** Why the change form may not be submitted yet, or undefined when it may. */
export function passwordChangeProblem(next: string, confirmation: string, acknowledged: boolean): string | undefined {
  if (!next || next !== confirmation) return "New passwords do not match.";
  if (!acknowledged) return "Confirm that you understand existing notes become unreadable.";
  return undefined;
}

/** Sealed with the login-derived key and never sent: edits waiting for a team key, and pre-P3 queue entries. */
const waiting = (entry: CachedNote) => entry.keyGeneration === undefined || entry.keyGeneration === WAITING_GENERATION;

/**
 * Re-seals this browser's waiting edits (and their cached drafts) from the old login key to the
 * new one after a password change, so they still reach the team once its keys arrive. Returns how
 * many could not be opened with the old key; those stay as they were.
 */
export async function resealWaitingEdits(oldAuthSecret: string, newAuthSecret: string): Promise<number> {
  const from = legacyKeyRef(oldAuthSecret);
  const to = legacyKeyRef(newAuthSecret);
  let unreadable = 0;
  const reseal = async (entry: CachedNote) => {
    const payload = await decryptObject(from, entry.containerID, entry.payload).catch(() => undefined);
    return payload && { ...entry, payload: await encryptNote(to, entry.containerID, payload) };
  };
  for (const item of (await pendingSaves()).filter(waiting)) {
    const next = await reseal(item);
    if (!next) { unreadable += 1; continue; }
    // A save that replaced the entry meanwhile was sealed by a tab that may already hold the new key.
    await replaceQueuedSave(item, next);
    const cached = await getNote(item.id).catch(() => undefined);
    const draft = cached && waiting(cached) ? await reseal(cached) : undefined;
    if (draft) await putNote(draft);
  }
  return unreadable;
}
