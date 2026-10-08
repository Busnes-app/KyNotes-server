import { decryptObject, encryptNote, legacyKeyRef, type KeyRef } from "./crypto";
import { closedOf, WAITING_GENERATION, type KeyedContainer, type KeyFloor } from "./keyring";
import { getNote, pendingSaves, putNote, replaceQueuedSave, type CachedNote } from "./storage";

/**
 * Notebooks whose items may still be sealed with the login key on this browser: never given a key, or
 * shared but not closed here (P4). A password change makes those items unreadable; everything sealed
 * with a container key, and edits waiting under the identity's waiting key, are unaffected.
 */
export const legacyAtRisk = (containers: ReadonlyArray<Pick<KeyedContainer, "id" | "sharedGeneration">>, floorOf: (id: string) => KeyFloor | undefined): number =>
  containers.filter((container) => {
    const floor = floorOf(container.id);
    return Math.max(container.sharedGeneration, floor?.shared ?? 0) === 0 || closedOf(floor) === 0;
  }).length;

export const passwordChangeWarning = (atRisk: number): string | undefined => atRisk === 0 ? undefined
  : `${atRisk} notebook${atRisk === 1 ? "" : "s"} may still hold items sealed with your current password: items written before ${atRisk === 1 ? "it" : "they"} had ${atRisk === 1 ? "its" : "their"} own key that you have not sealed in its review yet. After a password change those items can no longer be opened. Open each notebook and seal its items first, or confirm below to accept losing them.`;

/** Shown on every password change: a closed notebook (P4 Stop) may still hold the user's unsealed items. */
export const PASSWORD_CHANGE_NOTE = "Items you stopped opening without sealing them can no longer be opened after a password change, even if you show them again.";

/** Why the change form may not be submitted yet, or undefined when it may. */
export function passwordChangeProblem(next: string, confirmation: string, acknowledged: boolean, atRisk: number): string | undefined {
  if (!next || next !== confirmation) return "New passwords do not match.";
  if (atRisk > 0 && !acknowledged) return "Confirm that you understand those items become unreadable.";
  return undefined;
}

/** Never sent: edits waiting for a key (identity waiting key, or login key before P5), and pre-P3 queue entries. */
const waiting = (entry: CachedNote) => entry.keyGeneration === undefined || entry.keyGeneration === WAITING_GENERATION;

/**
 * Re-seals this browser's queued edits that are sealed with the login key onto the identity's waiting key
 * (at WAITING_GENERATION), or the new login key when this browser holds no identity. That covers edits
 * waiting before P5 or with no identity held, and edits queued at a container generation before P5 (a
 * personal notebook's save, M1). Entries the waiting key already opens are skipped and never counted.
 * Returns how many waiting entries could not be opened with the old key; those stay as they were. An
 * entry at a container generation that the old key does not open is sealed with a container key: untouched.
 * ponytail: without an identity, these entries move to the new login key rather than be lost. Upgrade:
 * drop that branch once no browser can hold pre-P5 entries.
 */
export async function resealWaitingEdits(oldAuthSecret: string, newAuthSecret: string, waitingSeal?: KeyRef): Promise<number> {
  const from = legacyKeyRef(oldAuthSecret);
  const to = waitingSeal ?? legacyKeyRef(newAuthSecret);
  let unreadable = 0;
  const reseal = async (entry: CachedNote): Promise<CachedNote | "skip" | undefined> => {
    if (waitingSeal && (await decryptObject(waitingSeal, entry.containerID, entry.payload).then(() => true, () => false))) return "skip";
    const payload = await decryptObject(from, entry.containerID, entry.payload).catch(() => undefined);
    if (!payload) return waiting(entry) ? undefined : "skip";
    return { ...entry, payload: await encryptNote(to, entry.containerID, payload), ...(waitingSeal ? { keyGeneration: WAITING_GENERATION } : {}) };
  };
  for (const item of await pendingSaves()) {
    const next = await reseal(item);
    if (next === "skip") continue;
    if (!next) { unreadable += 1; continue; }
    // A save that replaced the entry meanwhile was sealed by a tab that may already hold the new key.
    await replaceQueuedSave(item, next);
    // The draft beside it, under the same owner (or owner-unknown) key.
    const owner = item.owner ?? "";
    const cached = await getNote(owner, item.id).catch(() => undefined);
    const draft = cached ? await reseal(cached) : undefined;
    if (draft && draft !== "skip") await putNote(owner, draft);
  }
  return unreadable;
}
